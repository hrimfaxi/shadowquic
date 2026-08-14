use bytes::Bytes;
use std::os::unix::net::UnixDatagram;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
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
    config::StatsConfig,
    error::SError,
    msgs::{SDecode, SEncode, socks5::SocksAddr, squic::SQReq},
    quic::QuicConnection,
    squic::{handle_udp_recv_ctrl, handle_udp_send},
};

use super::{SQConn, inbound::Unsplit};

/// Handling a proxy request and starting proxy task with given squic connection
pub async fn handle_request<C: QuicConnection>(
    req: ProxyRequest,
    conn: SQConn<C>,
    over_stream: bool,
    stats_log_interval: u64,
) -> Result<(), SError> {
    let (mut send, recv, id) = QuicConnection::open_bi(&conn.conn).await?;
    let _span = span!(Level::INFO, "bistream", id = id);
    // With periodic logging disabled (interval 0), keep the legacy behavior of
    // printing stats once per new request.
    if stats_log_interval == 0 {
        let conn_clone = conn.clone();
        tokio::spawn(
            async move {
                let _ = print_stats_throttled(&conn_clone).await;
            }
            .in_current_span(),
        );
    }
    let fut = async move {
        match req {
            crate::ProxyRequest::Tcp(mut tcp_session) => {
                info!(dst = %tcp_session.dst, "bistream opened for tcp");
                let req = SQReq::SQConnect(tcp_session.dst.clone());
                req.encode(&mut send).await?;
                trace!(dst = %tcp_session.dst, "tcp connect req header sent");

                let u = tokio::io::copy_bidirectional(
                    &mut Unsplit { s: send, r: recv },
                    &mut tcp_session.stream,
                )
                .await?;

                info!(
                    "request:{} finished, upload:{}bytes,download:{}bytes",
                    tcp_session.dst, u.1, u.0
                );
            }

            crate::ProxyRequest::Udp(udp_session) => {
                info!(bind_addr = %udp_session.bind_addr, "bistream opened for udp association");
                let req = if over_stream {
                    SQReq::SQAssociatOverStream(udp_session.bind_addr.clone())
                } else {
                    SQReq::SQAssociatOverDatagram(udp_session.bind_addr.clone())
                };

                req.encode(&mut send).await?;
                trace!("udp associate req header sent");

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
                    error!("unexpected data received from socks control stream");
                    Err(SError::UDPSessionClosed(
                        "unexpected data received from socks control stream".into(),
                    )) as Result<(), SError>
                };

                tokio::try_join!(fut1, fut2, fut3)?;
                info!("udp association to {} ended", udp_session.bind_addr.clone());
            }
        }
        Ok(()) as Result<(), SError>
    };
    tokio::spawn(async {
        let _ = fut.instrument(_span).await.map_err(|x| error!("{}", x));
    });
    Ok(())
}

/// Helper function to create new stream for proxy dstination
#[allow(dead_code)]
pub async fn connect_tcp<C: QuicConnection>(
    sq_conn: &SQConn<C>,
    dst: SocksAddr,
) -> Result<Unsplit<C::SendStream, C::RecvStream>, crate::error::SError> {
    let conn = sq_conn;

    let (mut send, recv, _id) = conn.open_bi().await?;

    info!(dst = %dst, "bistream opened for tcp");
    let req = SQReq::SQConnect(dst.clone());
    req.encode(&mut send).await?;
    trace!("tcp connect req header sent");

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

#[derive(Clone, Copy, Debug)]
pub enum LinkType {
    Uplink,
    Downlink,
}

impl LinkType {
    fn as_str(&self) -> &'static str {
        match self {
            LinkType::Uplink => "uplink",
            LinkType::Downlink => "downlink",
        }
    }
}

pub struct StatsReporter {
    sock: Option<Arc<UnixDatagram>>,
    path: Option<std::path::PathBuf>,
    upstream_id: String,
    peer: String,
}

impl Clone for StatsReporter {
    fn clone(&self) -> Self {
        Self {
            sock: self.sock.clone(),
            path: self.path.clone(),
            upstream_id: self.upstream_id.clone(),
            peer: self.peer.clone(),
        }
    }
}

impl StatsReporter {
    pub fn new(cfg: Option<&StatsConfig>, peer: String) -> Self {
        let (path, upstream_id) = match cfg {
            Some(c) => (c.socket_path.clone(), c.upstream_id.clone()),
            None => (None, None),
        };
        let sock = path
            .as_ref()
            .and_then(|_| UnixDatagram::unbound().ok().map(Arc::new));
        Self {
            sock,
            path,
            upstream_id: upstream_id.unwrap_or_else(|| peer.clone()),
            peer,
        }
    }

    pub fn report(&self, rtt_ms: f64, loss_rate: f64, mtu: u16, link: LinkType) {
        let (Some(sock), Some(path)) = (&self.sock, &self.path) else {
            return;
        };
        let payload = format!(
            r#"{{"upstream_id":"{}","peer":"{}","rtt_ms":{:.3},"loss_rate":{:.4},"mtu":{},"link":"{}"}}
"#,
            self.upstream_id,
            self.peer,
            rtt_ms,
            loss_rate,
            mtu,
            link.as_str()
        );
        let _ = sock.send_to(payload.as_bytes(), path);
    }
}

/// Only one connection may print link quality logs at a time, to avoid spamming
/// the log when multiple connections are alive.
static STATS_LOG_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Shortest interval at which the connection-closed state is polled, so the
/// reporter role is released promptly once the connection closes.
const CLOSE_POLL: Duration = Duration::from_secs(1);

/// RAII guard that clears the global reporter flag on drop, so the role is
/// released even if the reporter task is cancelled or panics.
struct StatsLogActiveGuard;

impl Drop for StatsLogActiveGuard {
    fn drop(&mut self) {
        STATS_LOG_ACTIVE.store(false, Ordering::SeqCst);
    }
}

/// Periodically prints uplink/downlink link quality logs until the connection
/// closes. The first print happens immediately, then once per `interval`.
/// Only one connection prints at a time; connections that fail to claim the
/// role wait for the owner to release it instead of giving up.
pub async fn report_stats_periodically<C: QuicConnection>(
    sq_conn: SQConn<C>,
    interval: Duration,
) {
    if interval.is_zero() {
        return;
    }

    // Compete to become the sole reporter; if not claimed, wait for the owner
    // to release it, or exit if this connection closes.
    loop {
        if STATS_LOG_ACTIVE
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            break;
        }
        if sq_conn.close_reason().is_some() {
            return;
        }
        tokio::time::sleep(CLOSE_POLL).await;
    }
    // From here on the flag is guaranteed to be released when this future ends,
    // whether by normal return, cancellation, or panic.
    let _active_guard = StatsLogActiveGuard;

    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if sq_conn.close_reason().is_some() {
                    break;
                }
                let _ = print_stats(&sq_conn).await;
            }
            _ = tokio::time::sleep(CLOSE_POLL) => {
                if sq_conn.close_reason().is_some() {
                    break;
                }
            }
        }
    }
}

/// Legacy per-request stats logging used when periodic logging is disabled.
/// Prints at most once every 10 seconds across all connections.
async fn print_stats_throttled<C: QuicConnection>(sq_conn: &SQConn<C>) -> SResult<()> {
    static LAST_PRINT: std::sync::LazyLock<tokio::sync::Mutex<Option<std::time::Instant>>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(None));

    {
        let mut last_print = LAST_PRINT.lock().await;
        if let Some(last) = *last_print
            && last.elapsed() < Duration::from_secs(10)
        {
            return Ok(());
        }
        *last_print = Some(std::time::Instant::now());
    }

    print_stats(sq_conn).await
}

async fn print_stats<C: QuicConnection>(sq_conn: &SQConn<C>) -> SResult<()> {
    let stats = sq_conn.get_conn_stats().ok_or(SError::ProtocolUnimpl)?;
    let reporter = sq_conn.conn.reporter();

    let uplink_loss = stats.lost_packets as f64 / (stats.sent_packets + 1) as f64;
    reporter.report(stats.rtt, uplink_loss, stats.current_mtu, LinkType::Uplink);
    info!(
        packet_loss_rate = %format!("{:.2}%", uplink_loss * 100.0),
        rtt = %format!("{:.1}ms", stats.rtt),
        mtu = stats.current_mtu,
        "uplink stats",
    );

    if let Ok(Ok(Ok(peer_stats))) =
        tokio::time::timeout(Duration::from_secs(10), get_peer_conn_stats(sq_conn)).await
    {
        let downlink_loss = peer_stats.lost_packets as f64 / (peer_stats.sent_packets + 1) as f64;
        reporter.report(
            peer_stats.rtt,
            downlink_loss,
            peer_stats.current_mtu,
            LinkType::Downlink,
        );
        info!(
            packet_loss_rate = %format!("{:.2}%", downlink_loss * 100.0),
            rtt = %format!("{:.1}ms", peer_stats.rtt),
            mtu = peer_stats.current_mtu,
            "downlink stats",
        );
    } else {
        trace!("failed to get peer conn stats. Api may not be implemented");
        return Err(SError::ProtocolUnimpl);
    }
    Ok(())
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

    info!(bind_addr = %dst, "bistream opened for udp association");

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

    tokio::spawn(async {
        match tokio::try_join!(fut1, fut2) {
            Err(e) => error!("udp association ended due to {}", e),
            Ok(_) => trace!("udp association ended"),
        }
    });

    Ok((udp_send, udp_recv))
}
