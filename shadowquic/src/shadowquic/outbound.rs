use async_trait::async_trait;
use std::{
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
    sync::Arc,
};
use tokio::sync::{OnceCell, SetOnce};

use super::quinn_wrapper::EndClient;
use tracing::{error, info, warn};

use crate::{
    Outbound,
    config::{ShadowQuicClientCfg, format_duration},
    error::SError,
    quic::QuicClient,
    squic::outbound::handle_request,
};

use crate::squic::{IDStore, SQConn, handle_udp_packet_recv};
use rand::Rng;
use std::time::Duration;
use tokio::time::sleep;

pub type ShadowQuicConn = SQConn<<EndClient as QuicClient>::C>;

pub struct ShadowQuicClient {
    pub quic_conn: Option<ShadowQuicConn>,
    pub config: ShadowQuicClientCfg,
    pub quic_end: OnceCell<(EndClient, Option<tokio::task::JoinHandle<()>>)>,
}
impl ShadowQuicClient {
    pub fn new(cfg: ShadowQuicClientCfg) -> Self {
        Self {
            quic_conn: None,
            quic_end: OnceCell::new(),
            config: cfg,
        }
    }
    pub async fn init_endpoint(&self, ipv6: bool) -> Result<EndClient, SError> {
        EndClient::new(&self.config, ipv6).await
    }
    pub fn new_with_socket(cfg: ShadowQuicClientCfg, socket: UdpSocket) -> Result<Self, SError> {
        Ok(Self {
            quic_conn: None,
            quic_end: OnceCell::from((EndClient::new_with_socket(&cfg, socket)?, None)),
            config: cfg,
        })
    }

    fn resolve_addrs(&self) -> Vec<SocketAddr> {
        let addrs: Vec<SocketAddr> = self
            .config
            .addr
            .to_socket_addrs()
            .unwrap_or_else(|_| panic!("resolve quic addr failed: {}", self.config.addr))
            .collect();
        if addrs.is_empty() {
            panic!("resolve quic addr failed: {}", self.config.addr);
        }
        addrs
    }

    fn rebind_interval_range(&self) -> Option<(u32, u32)> {
        let min = self
            .config
            .min_rebind_interval
            .or(self.config.rebind_interval);
        let max = self
            .config
            .max_rebind_interval
            .or(self.config.rebind_interval);
        match (min, max) {
            (None, None) => None,
            (Some(m), None) => Some((m, m)),
            (None, Some(m)) => Some((m, m)),
            (Some(a), Some(b)) => Some((a, b)),
        }
    }

    fn spawn_rebind_task(
        end: EndClient,
        rebind_interval: Option<(u32, u32)>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let (min_ms, max_ms) = rebind_interval?;
        let (lo, hi) = if min_ms <= max_ms {
            (min_ms, max_ms)
        } else {
            (max_ms, min_ms)
        };

        if hi == 0 {
            warn!("rebind_interval is 0, disabling rebind");
            return None;
        }

        info!(
            "rebind enabled (interval: {} - {})",
            format_duration(lo),
            format_duration(hi)
        );

        let bind_addr = "[::]:0";

        let handle = tokio::spawn(async move {
            loop {
                let interval_ms = {
                    let mut rng = rand::rng();
                    rng.random_range(lo..=hi) as u64
                };
                sleep(Duration::from_millis(interval_ms)).await;

                match tokio::net::UdpSocket::bind(bind_addr).await {
                    Ok(tokio_socket) => match tokio_socket.into_std() {
                        Ok(std_socket) => {
                            if let Err(e) = end.rebind(std_socket) {
                                error!("rebind failed: {}", e);
                            } else {
                                info!("rebound to new local port");
                            }
                        }
                        Err(e) => {
                            error!("into_std failed for rebind socket: {}", e);
                        }
                    },
                    Err(e) => {
                        error!("failed to bind socket for rebind: {}", e);
                    }
                }
            }
        });

        Some(handle)
    }

    async fn connect_addr(&self, addr: SocketAddr) -> Result<ShadowQuicConn, SError> {
        let (end, _handle) = self
            .quic_end
            .get_or_init(|| async {
                let end = match self.init_endpoint(true).await {
                    Ok(end) => end,
                    Err(_) => self
                        .init_endpoint(false)
                        .await
                        .expect("error during initialize quic endpoint"),
                };
                let handle = Self::spawn_rebind_task(end.clone(), self.rebind_interval_range());
                (end, handle)
            })
            .await;

        let conn = QuicClient::connect(end, addr, &self.config.server_name).await?;

        let conn = SQConn {
            conn,
            authed: Arc::new(SetOnce::new_with(Some(true))),
            send_id_store: Default::default(),
            recv_id_store: IDStore {
                id_counter: Default::default(),
                inner: Default::default(),
            },
        };

        let conn_clone = conn.clone();
        tokio::spawn(async move {
            let _ = handle_udp_packet_recv(conn_clone)
                .await
                .map_err(|x| error!("handle udp packet recv error: {}", x));
        });
        Ok(conn)
    }

    pub async fn get_conn(&self) -> Result<ShadowQuicConn, SError> {
        let addrs = self.resolve_addrs();
        let mut last_err = None;

        for addr in addrs {
            match self.connect_addr(addr).await {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    error!("connect to {} failed: {}", addr, e);
                    last_err = Some(e);
                }
            }
        }

        Err(last_err
            .unwrap_or_else(|| panic!("no usable quic target address: {}", self.config.addr)))
    }

    async fn prepare_conn(&mut self) -> Result<(), SError> {
        // delete connection if closed.
        self.quic_conn.take_if(|x| {
            x.close_reason().is_some_and(|x| {
                info!("quic connection closed due to {}", x);
                true
            })
        });
        // Creating new connectin
        if self.quic_conn.is_none() {
            self.quic_conn = Some(self.get_conn().await?);
        }
        Ok(())
    }
}

impl Drop for ShadowQuicClient {
    fn drop(&mut self) {
        if let Some((_, Some(handle))) = self.quic_end.get() {
            handle.abort();
        }
    }
}

#[async_trait]
impl Outbound for ShadowQuicClient {
    async fn handle(&mut self, req: crate::ProxyRequest) -> Result<(), crate::error::SError> {
        self.prepare_conn().await?;

        let conn = self.quic_conn.as_mut().unwrap().clone();

        let over_stream = self.config.over_stream;
        handle_request(req, conn, over_stream).await?;
        Ok(())
    }
}
