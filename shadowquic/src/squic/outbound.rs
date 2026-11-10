use bytes::Bytes;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{Receiver, Sender, channel};

use tokio::io::AsyncReadExt;
use tracing::Instrument;
use tracing::{Level, error, info, span, trace};

use crate::config::AuthUser;
use crate::error::SResult;
use crate::msgs::squic::{
    ConnStats, ExtOpcodeConn, ExtOpcodeUser, SQExtError, SQExtOpcode, UserStats,
};
use crate::{
    ProxyRequest,
    error::SError,
    msgs::{SDecode, SEncode, socks5::SocksAddr, squic::SQReq},
    quic::QuicConnection,
    squic::{handle_udp_recv_ctrl, handle_udp_send},
};

use super::{SQConn, SQConnStats, inbound::Unsplit};

/// Upper bound on how long opening a bi-stream for a request may take before the
/// connection is treated as wedged. Wide enough for a legitimate stream-credit
/// wait under healthy load and narrow enough to bound how long the accept loop
/// can be blocked.
///
/// Waiting on the QUIC idle timeout instead does not help: with
/// `keep_alive_interval` set the connection never goes idle, so a peer that
/// stopped granting stream credit keeps the connection alive indefinitely and
/// only this bound can break the stall.
const HANDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// What [`dispatch`] did with the request, and with the connection.
pub enum Dispatch {
    /// The bi-stream is open and the request header is sent. The caller awaits
    /// the relay, which keeps the session's lifetime owned by the task that
    /// accepted the request.
    Sent(Relay),
    /// The bi-stream open timed out and the connection was closed, so the caller
    /// must drop it from its cache.
    Wedged,
    /// The bi-stream open timed out but the connection was left in place, because
    /// it is still moving application data.
    StillActive,
}

/// The relay of one dispatched request, resolved but not yet started.
pub type Relay = Pin<Box<dyn Future<Output = Result<(), SError>> + Send>>;

/// Dispatches `req` under [`HANDLE_TIMEOUT`] and returns its relay.
///
/// [`handle_request`] opens the bi-stream, sends the request header and hands
/// back the relay without running it, so this bound covers only the open. The
/// caller awaits the relay, so a session that is moving data is never cut at
/// this bound. quinn's `open_bi` waits for the peer to
/// raise `MAX_STREAMS` instead of failing, so without the bound a peer that
/// stopped granting credit would park the request forever: with
/// `keep_alive_interval` set such a connection never goes idle, and only this
/// bound can break the stall.
///
/// On timeout the connection is closed only when no application data moved
/// either. [`data_progress`](QuicConnection::data_progress) counts STREAM and
/// DATAGRAM frames, which keep-alive PINGs and pure ACKs do not touch, so a
/// connection still carrying them is under ordinary stream-credit backpressure
/// from live sessions, and closing it would abort all of them. A transport that
/// cannot report the counter at all is never found silent, so its connection is
/// left in place.
pub async fn dispatch<C: QuicConnection>(
    req: ProxyRequest,
    conn: SQConn<C>,
    over_stream: bool,
    half_close_timeout: u64,
) -> Result<Dispatch, SError> {
    let progress_before = conn.data_progress();
    match tokio::time::timeout(
        HANDLE_TIMEOUT,
        handle_request(req, conn.clone(), over_stream, half_close_timeout),
    )
    .await
    {
        Ok(result) => result.map(Dispatch::Sent),
        Err(_) => {
            if progress_before.is_some() && progress_before == conn.data_progress() {
                error!(
                    "bi-stream open timed out after {}s with no application data moving, dropping the connection",
                    HANDLE_TIMEOUT.as_secs()
                );
                QuicConnection::close(&conn.conn, 0, &[]);
                Ok(Dispatch::Wedged)
            } else {
                error!(
                    "bi-stream open timed out after {}s, connection is still carrying application data",
                    HANDLE_TIMEOUT.as_secs()
                );
                Ok(Dispatch::StillActive)
            }
        }
    }
}

/// Opens the bi-stream of a proxy request, sends its header, and returns the
/// relay without running it.
///
/// The open and the header write are the only parts that can park on a peer that
/// stopped granting stream credit, so they stay inline for [`dispatch`] to bound.
/// The relay itself is left to the caller, whose task is the one that owns the
/// session and is aborted with it.
pub async fn handle_request<C: QuicConnection>(
    req: ProxyRequest,
    conn: SQConn<C>,
    over_stream: bool,
    half_close_timeout: u64,
) -> Result<Relay, SError> {
    let (mut send, recv, id) = QuicConnection::open_bi(&conn.conn).await?;
    let _span = span!(Level::INFO, "bistream", id = id);
    let conn_clone = conn.clone();
    tokio::spawn(
        async move {
            let _ = print_stats(&conn_clone).await;
        }
        .in_current_span(),
    );
    match req {
        crate::ProxyRequest::Tcp(mut tcp_session) => {
            info!(event = "squic:bidirectional_stream_opened", dst = %tcp_session.dst, "bistream opened for tcp");
            let req = SQReq::SQConnect(tcp_session.dst.clone());
            req.encode(&mut send).await?;
            trace!(event = "squic:tcp_request_sent", dst = %tcp_session.dst, "tcp connect req header sent");

            Ok(Box::pin(
                async move {
                    let u: (u64, u64) = crate::utils::copy::copy_bidirectional(
                        &mut Unsplit { s: send, r: recv },
                        &mut tcp_session.stream,
                        8 * 1024,
                        8 * 1024,
                        half_close_timeout,
                    )
                    .await?;

                    info!(
                        dst = %tcp_session.dst,
                        upload = %format!("{} bytes", u.1),
                        download = %format!("{} bytes", u.0),
                        event = "squic:tcp_request_completed",
                        "request finished"
                    );
                    Ok(())
                }
                .in_current_span(),
            ) as Relay)
        }

        crate::ProxyRequest::Udp(udp_session) => {
            info!(event = "squic:bidirectional_stream_opened", bind_addr = %udp_session.bind_addr, "bistream opened for udp association");
            let req = if over_stream {
                SQReq::SQAssociatOverStream(udp_session.bind_addr.clone())
            } else {
                SQReq::SQAssociatOverDatagram(udp_session.bind_addr.clone())
            };

            req.encode(&mut send).await?;
            trace!(
                event = "squic:udp_associate_request_sent",
                "udp associate req header sent"
            );

            Ok(Box::pin(
                async move {
                    let fut2 = handle_udp_recv_ctrl(recv, udp_session.send.clone(), conn.clone());
                    let fut1 = handle_udp_send(send, udp_session.recv, conn, over_stream);

                    let fut3 = async {
                        if udp_session.stream.is_none() {
                            return Ok(());
                        }
                        let mut buf = [0u8];
                        udp_session
                            .stream
                            .unwrap()
                            .read_exact(&mut buf)
                            .await
                            .map_err(|x| SError::UDPSessionClosed(x.to_string()))?;
                        error!(
                            event = "squic:unexpected_control_data",
                            "unexpected data received from socks control stream"
                        );
                        Err(SError::UDPSessionClosed(
                            "unexpected data received from socks control stream".into(),
                        )) as Result<(), SError>
                    };

                    tokio::try_join!(fut1, fut2, fut3)?;
                    info!(
                        event = "squic:udp_association_closed",
                        "udp association to {} ended",
                        udp_session.bind_addr.clone()
                    );
                    Ok(())
                }
                .in_current_span(),
            ) as Relay)
        }
    }
}

/// Helper function to create new stream for proxy dstination
#[allow(dead_code)]
pub async fn connect_tcp<C: QuicConnection>(
    sq_conn: &SQConn<C>,
    dst: SocksAddr,
) -> Result<Unsplit<C::SendStream, C::RecvStream>, crate::error::SError> {
    let conn = sq_conn;

    let (mut send, recv, _id) = conn.open_bi().await?;

    info!(event = "squic:bidirectional_stream_opened", dst = %dst, "bistream opened for tcp");
    let req = SQReq::SQConnect(dst.clone());
    req.encode(&mut send).await?;
    trace!(
        event = "proxy:tcp_request_sent",
        "tcp connect req header sent"
    );

    Ok(Unsplit { s: send, r: recv })
}

pub async fn get_peer_conn_stats<C: QuicConnection>(
    sq_conn: &SQConn<C>,
) -> SResult<Result<ConnStats, SQExtError>> {
    let (mut send, mut recv, _id) = sq_conn.open_bi().await?;
    let req = SQReq::SQExtension(SQExtOpcode::Conn(ExtOpcodeConn::GetConnStats));
    req.encode(&mut send).await?;
    let response = Result::<ConnStats, SQExtError>::decode(&mut recv).await?;
    Ok(response)
}

pub async fn add_user<C: QuicConnection>(
    sq_conn: &SQConn<C>,
    username: &str,
    password: &str,
) -> SResult<Result<(), SQExtError>> {
    send_user_extension(
        sq_conn,
        ExtOpcodeUser::AddUser(AuthUser {
            username: username.to_owned(),
            password: password.to_owned(),
        }),
    )
    .await
}

pub async fn remove_user<C: QuicConnection>(
    sq_conn: &SQConn<C>,
    username: &str,
) -> SResult<Result<(), SQExtError>> {
    send_user_extension(sq_conn, ExtOpcodeUser::RemoveUser(username.to_owned())).await
}

pub async fn list_users<C: QuicConnection>(
    sq_conn: &SQConn<C>,
) -> SResult<Result<Vec<String>, SQExtError>> {
    send_user_extension(sq_conn, ExtOpcodeUser::ListUsers).await
}

pub async fn get_user_stats<C: QuicConnection>(
    sq_conn: &SQConn<C>,
    username: &str,
) -> SResult<Result<UserStats, SQExtError>> {
    send_user_extension(sq_conn, ExtOpcodeUser::GetUserStats(username.to_owned())).await
}

pub async fn get_all_stats<C: QuicConnection>(
    sq_conn: &SQConn<C>,
) -> SResult<Result<Vec<UserStats>, SQExtError>> {
    send_user_extension(sq_conn, ExtOpcodeUser::GetAllStats).await
}

pub async fn kill_user_conns<C: QuicConnection>(
    sq_conn: &SQConn<C>,
    username: &str,
) -> SResult<Result<(), SQExtError>> {
    send_user_extension(sq_conn, ExtOpcodeUser::KillUserConn(username.to_owned())).await
}

pub async fn clear_user_stats<C: QuicConnection>(
    sq_conn: &SQConn<C>,
    username: &str,
) -> SResult<Result<(), SQExtError>> {
    send_user_extension(sq_conn, ExtOpcodeUser::ClearUserStats(username.to_owned())).await
}

pub async fn clear_all_stats<C: QuicConnection>(
    sq_conn: &SQConn<C>,
) -> SResult<Result<(), SQExtError>> {
    send_user_extension(sq_conn, ExtOpcodeUser::ClearAllStats).await
}

async fn send_user_extension<C: QuicConnection, R: SDecode>(
    sq_conn: &SQConn<C>,
    opcode: ExtOpcodeUser,
) -> SResult<Result<R, SQExtError>> {
    let (mut send, mut recv, _id) = sq_conn.open_bi().await?;
    let req = SQReq::SQExtension(SQExtOpcode::User(opcode));
    req.encode(&mut send).await?;
    let response = Result::<R, SQExtError>::decode(&mut recv).await?;
    Ok(response)
}

async fn print_stats<C: QuicConnection>(sq_conn: &SQConn<C>) -> SResult<()> {
    let Ok(_refresh) = sq_conn.stats_refresh.try_lock() else {
        return Ok(()); // if we can't get the lock, it means another task is already printing stats, so we skip this one.
    };
    if sq_conn
        .stats
        .lock()
        .await
        .as_ref()
        .is_some_and(|stats| stats.time.elapsed() < Duration::from_secs(10))
    {
        return Ok(());
    }

    let uplink = sq_conn.get_conn_stats().ok_or(SError::ProtocolUnimpl)?;
    log_conn_stats(&uplink, "uplink");

    let downlink =
        match tokio::time::timeout(Duration::from_secs(10), get_peer_conn_stats(sq_conn)).await {
            Ok(Ok(Ok(stats))) => stats,
            _ => {
                trace!(
                    event = "recovery:peer_metrics_unavailable",
                    "failed to get peer conn stats. Api may not be implemented"
                );
                return Err(SError::ProtocolUnimpl);
            }
        };
    log_conn_stats(&downlink, "downlink");

    *sq_conn.stats.lock().await = Some(SQConnStats {
        uplink,
        downlink,
        time: Instant::now(),
        birth_time: sq_conn.birth_time,
    });
    Ok(())
}

fn log_conn_stats(stats: &ConnStats, direction: &'static str) {
    info!(event = "recovery:metrics_updated",
        packet_loss_rate=%format!("{:.2}%", stats.lost_packets as f32 / (stats.sent_packets + 1) as f32 * 100.0),
        rtt = %format!("{:.1}ms", stats.rtt),
        mtu = stats.current_mtu,
        "{} connection stats",
        direction
    );
}

/// associate a udp socket in the remote server
/// return a socket-like send, recv handle.
#[allow(dead_code)]
pub async fn associate_udp<C: QuicConnection>(
    sq_conn: &SQConn<C>,
    dst: SocksAddr,
    over_stream: bool,
) -> Result<(Sender<(Bytes, SocksAddr)>, Receiver<(Bytes, SocksAddr)>), SError> {
    let conn = sq_conn;

    let (mut send, recv, _id) = conn.open_bi().await?;

    info!(event = "squic:bidirectional_stream_opened", bind_addr = %dst, "bistream opened for udp association");

    let req = if over_stream {
        SQReq::SQAssociatOverStream(dst.clone())
    } else {
        SQReq::SQAssociatOverDatagram(dst.clone())
    };
    req.encode(&mut send).await?;
    let (local_send, udp_recv) = channel::<(Bytes, SocksAddr)>(10);
    let (udp_send, local_recv) = channel::<(Bytes, SocksAddr)>(10);
    let local_send = Arc::new(local_send);
    let fut2 = handle_udp_recv_ctrl(recv, local_send, conn.clone());
    let fut1 = handle_udp_send(send, Box::new(local_recv), conn.clone(), over_stream);

    tokio::spawn(
        async {
            match tokio::try_join!(fut1, fut2) {
                Err(e) => error!(
                    event = "squic:udp_association_failed",
                    "udp association ended due to {}", e
                ),
                Ok(_) => trace!(
                    event = "squic:udp_association_closed",
                    "udp association ended"
                ),
            }
        }
        .in_current_span(),
    );

    Ok((udp_send, udp_recv))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TcpSession, UserContext, quic::QuicErrorRepr};
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream},
        sync::{Mutex, SetOnce, mpsc},
    };

    /// Records what the relay writes toward the peer, so a test can observe the
    /// uplink direction without a QUIC connection.
    struct Uplink(mpsc::UnboundedSender<Bytes>);

    impl AsyncWrite for Uplink {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let _ = self.0.send(Bytes::copy_from_slice(buf));
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A connection that hands out one bi-stream backed by a duplex the test
    /// keeps the other end of, so both relay directions can be driven.
    #[derive(Clone)]
    struct RelayConn {
        uplink: mpsc::UnboundedSender<Bytes>,
        /// The peer end of the last bi-stream, written by the test.
        downlink: Arc<Mutex<Option<DuplexStream>>>,
    }

    #[async_trait::async_trait]
    impl QuicConnection for RelayConn {
        type SendStream = Uplink;
        type RecvStream = DuplexStream;

        async fn open_bi(
            &self,
        ) -> Result<(Self::SendStream, Self::RecvStream, u64), QuicErrorRepr> {
            let (peer, relay) = tokio::io::duplex(64 * 1024);
            *self.downlink.lock().await = Some(peer);
            Ok((Uplink(self.uplink.clone()), relay, 0))
        }
        async fn accept_bi(
            &self,
        ) -> Result<(Self::SendStream, Self::RecvStream, u64), QuicErrorRepr> {
            Err(QuicErrorRepr::QuicBaseError("unused".into()))
        }
        async fn open_uni(&self) -> Result<(Self::SendStream, u64), QuicErrorRepr> {
            Err(QuicErrorRepr::QuicBaseError("unused".into()))
        }
        async fn accept_uni(&self) -> Result<(Self::RecvStream, u64), QuicErrorRepr> {
            Err(QuicErrorRepr::QuicBaseError("unused".into()))
        }
        async fn read_datagram(&self) -> Result<Bytes, QuicErrorRepr> {
            std::future::pending().await
        }
        async fn send_datagram(&self, _bytes: Bytes) -> Result<(), QuicErrorRepr> {
            Ok(())
        }
        fn close(&self, _error_code: u64, _reason: &[u8]) {}
        fn close_reason(&self) -> Option<QuicErrorRepr> {
            None
        }
        fn remote_address(&self) -> std::net::SocketAddr {
            "127.0.0.1:1".parse().unwrap()
        }
        fn peer_id(&self) -> u64 {
            0
        }
    }

    /// [`HANDLE_TIMEOUT`] exists to break a peer that stopped granting stream
    /// credit. It must not become a lifetime cap on the session it dispatched:
    /// wrapping the whole relay in it cut every download, ssh session and udp
    /// association at ten seconds while leaving the connection open, so nothing
    /// else reported it.
    #[tokio::test(start_paused = true)]
    async fn a_session_survives_the_bi_stream_open_bound() {
        let (uplink, mut relayed) = mpsc::unbounded_channel();
        let downlink = Arc::new(Mutex::new(None));
        let conn = RelayConn {
            uplink,
            downlink: downlink.clone(),
        };
        let sq_conn = SQConn::new(conn, SetOnce::new_with(Some(Ok("user".to_string()))));

        let (mut local, session_side) = tokio::io::duplex(64 * 1024);
        let req = ProxyRequest::Tcp(TcpSession {
            stream: Box::new(session_side) as crate::AnyTcp,
            dst: std::net::SocketAddr::from(([192, 0, 2, 1], 443)).into(),
            src_addr: None,
            user_context: UserContext::default(),
        });

        let Ok(Dispatch::Sent(relay)) = dispatch(req, sq_conn, false, 0).await else {
            panic!("dispatch waited for the session instead of handing back its relay");
        };
        let relay = tokio::spawn(relay);

        // The request header is written before the relay starts.
        assert!(relayed.recv().await.is_some());

        // Past the bound, the session must still carry data both ways.
        tokio::time::advance(HANDLE_TIMEOUT + Duration::from_secs(1)).await;
        let alive = tokio::time::timeout(HANDLE_TIMEOUT, async {
            local.write_all(b"hello").await.unwrap();
            let mut seen = Vec::new();
            while !seen.ends_with(b"hello") {
                seen.extend_from_slice(&relayed.recv().await.unwrap());
            }

            downlink
                .lock()
                .await
                .as_mut()
                .unwrap()
                .write_all(b"world")
                .await
                .unwrap();
            let mut buf = [0u8; 5];
            local.read_exact(&mut buf).await.unwrap();
            buf
        })
        .await;

        relay.abort();
        assert_eq!(
            alive.expect("the session stopped carrying data after the bound"),
            *b"world"
        );
    }
}
