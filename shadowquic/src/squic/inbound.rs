use bytes::Bytes;
use std::{collections::HashMap, pin::Pin, sync::Arc};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    select,
    sync::mpsc::{Sender, channel},
};
use tracing::{Instrument, Level, event, info, trace, trace_span};

use crate::{
    ProxyRequest, TcpSession, TcpTrait, UdpSession,
    error::SError,
    msgs::{
        SDecode,
        socks5::SocksAddr,
        squic::{SQReq, SunnyCredential},
    },
    quic::QuicConnection,
    squic::wait_sunny_auth,
};

use brutal_jls::{CongestionParameter, brutal_set_parameter_by_remote};

use super::{SQConn, handle_udp_packet_recv, handle_udp_recv_ctrl, handle_udp_send};

pub type SunnyQuicUsers = Arc<HashMap<SunnyCredential, String>>;

#[derive(Clone)]
pub struct SQServerConn<C: QuicConnection> {
    pub inner: SQConn<C>,
    pub users: SunnyQuicUsers,
}
impl<C: QuicConnection> SQServerConn<C> {
    pub async fn handle_connection(self, req_send: Sender<ProxyRequest>) -> Result<(), SError> {
        let conn = &self.inner;
        event!(
            Level::INFO,
            "incoming from {} accepted",
            conn.remote_address()
        );
        let conn_clone = self.inner.clone();
        tokio::spawn(async move {
            let _ = handle_udp_packet_recv(conn_clone).in_current_span().await;
        });

        while conn.close_reason().is_none() {
            select! {
                bi = conn.accept_bi() => {
                    let (send, recv, id) = bi?;
                    let span = trace_span!("bistream", id = id);
                    trace!("bistream accepted");
                    tokio::spawn(self.clone().handle_bistream(send, recv, req_send.clone()).instrument(span).in_current_span());
                },
            }
        }
        Ok(())
    }

    fn apply_brutal_params(
        &self,
        remote: std::net::SocketAddr,
        params: &[(CongestionParameter, &'static str)],
    ) -> Result<(), SError> {
        for (param, name) in params {
            brutal_set_parameter_by_remote(remote, param.clone())
                .map_err(|e| SError::SunnyAuthError(format!("set brutal {name} failed: {e}")))?;
        }
        Ok(())
    }

    async fn handle_bistream(
        self,
        send: C::SendStream,
        mut recv: C::RecvStream,
        req_send: Sender<ProxyRequest>,
    ) -> Result<(), SError> {
        let req = SQReq::decode(&mut recv).await?;

        // let rate: f32 = (self.0.conn.stats().path.lost_packets as f32)
        //     / ((self.0.conn.stats().path.sent_packets + 1) as f32);
        // info!(
        //     "packet_loss_rate:{:.2}%, rtt:{:?}, mtu:{}",
        //     rate * 100.0,
        //     self.0.conn.rtt(),
        //     self.0.conn.stats().path.current_mtu,
        // );
        match req {
            SQReq::SQConnect(dst) => {
                wait_sunny_auth(&self.inner).await?;
                info!(
                    "connect request: {}->{} accepted",
                    self.inner.remote_address(),
                    dst.clone()
                );
                let tcp: TcpSession = TcpSession {
                    stream: Box::new(Unsplit { s: send, r: recv }),
                    dst,
                };
                req_send
                    .send(ProxyRequest::Tcp(tcp))
                    .await
                    .map_err(|_| SError::OutboundUnavailable)?;
            }
            ref req @ (SQReq::SQAssociatOverDatagram(ref dst)
            | SQReq::SQAssociatOverStream(ref dst)) => {
                wait_sunny_auth(&self.inner).await?;
                info!("association request to {} accepted", dst.clone());
                let (local_send, udp_recv) = channel::<(Bytes, SocksAddr)>(10);
                let (udp_send, local_recv) = channel::<(Bytes, SocksAddr)>(10);
                let udp: UdpSession = UdpSession {
                    send: Arc::new(udp_send),
                    recv: Box::new(udp_recv),
                    stream: None,
                    bind_addr: dst.clone(),
                };
                let local_send = Arc::new(local_send);
                req_send
                    .send(ProxyRequest::Udp(udp))
                    .await
                    .map_err(|_| SError::OutboundUnavailable)?;
                let fut1 = handle_udp_send(
                    send,
                    Box::new(local_recv),
                    self.inner.clone(),
                    req == &SQReq::SQAssociatOverStream(dst.clone()),
                );
                let fut2 = handle_udp_recv_ctrl(recv, local_send, self.inner);
                tokio::try_join!(fut1, fut2)?;
            }
            SQReq::SQAuthenticate(passwd_hash) => {
                if let Some(name) = self.users.get(passwd_hash.as_ref()) {
                    tracing::info!("user authenticated:{}", name);
                    self.inner
                        .authed
                        .set(true)
                        .expect("repeated authentication!");
                } else {
                    tracing::error!("authentication failed");
                    // 263 is tested result by connecting with sunnyquic client to
                    // cloudflare.com:443
                    self.inner.close(263, &[]);
                    return Err(SError::SunnyAuthError("Wrong password/username".into()));
                }
            }
            SQReq::SQBrutalNegotiation(nego) => {
                if self.inner.authed.get() != Some(&true) {
                    tracing::warn!("brutal negotiation before authentication, closing");
                    self.inner.close(263, &[]);
                    return Err(SError::SunnyAuthError(
                        "Auth required before brutal neg".into(),
                    ));
                }

                let remote = self.inner.remote_address();
                trace!("brutal negotiation: {:?}", nego);

                self.apply_brutal_params(
                    remote,
                    &[
                        (
                            CongestionParameter::PeerBandwidthHint(nego.bandwidth_hint),
                            "bandwidth_hint",
                        ),
                        (CongestionParameter::CwndGain(nego.cwnd_gain), "cwnd_gain"),
                        (
                            CongestionParameter::AckCompensation(nego.ack_compensate),
                            "ack_compensation",
                        ),
                    ],
                )?;
            }
            _ => {
                unimplemented!()
            }
        }
        Ok(())
    }
}
#[derive(Debug)]
pub struct Unsplit<S, R> {
    pub s: S,
    pub r: R,
}
impl<S: AsyncWrite + Unpin + Sync + Send, R: AsyncRead + Unpin + Sync + Send> TcpTrait
    for Unsplit<S, R>
{
}

impl<S: AsyncWrite + Unpin, R: AsyncRead + Unpin> AsyncRead for Unsplit<S, R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.as_mut().r).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin, R: AsyncRead + Unpin> AsyncWrite for Unsplit<S, R> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.as_mut().s).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.as_mut().s).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.as_mut().s).poll_shutdown(cx)
    }
}
