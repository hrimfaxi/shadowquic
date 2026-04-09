use async_trait::async_trait;
use rand::Rng;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{OnceCell, SetOnce};

use super::EndClient;
use tracing::{debug, error, info, warn};

use crate::{
    Outbound,
    config::MIN_PORT_HOP_INTERVAL,
    config::SunnyQuicClientCfg,
    error::SError,
    quic::{QuicClient, QuicConnection},
    squic::{auth_sunny, outbound::handle_request},
    sunnyquic::gen_sunny_user_hash,
};

use crate::squic::{IDStore, SQConn, handle_udp_packet_recv};

pub type SunnyQuicConn = SQConn<<EndClient as QuicClient>::C>;

pub struct SunnyQuicClient {
    pub quic_conn: Option<SunnyQuicConn>,
    pub config: SunnyQuicClientCfg,
    pub quic_end: OnceCell<EndClient>,
    /// Flag indicating that a port hop should be performed on the next prepare_conn call
    hop_requested: Arc<AtomicBool>,
    /// graceful shutdown signal sender for hop timer
    hop_shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for SunnyQuicClient {
    fn drop(&mut self) {
        if let Some(tx) = self.hop_shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

static PORT_HOP_WARN: AtomicBool = AtomicBool::new(false);

impl SunnyQuicClient {
    pub fn new(cfg: SunnyQuicClientCfg) -> Self {
        let hop_requested = Arc::new(AtomicBool::new(false));
        let (hop_shutdown_tx, mut hop_shutdown_rx) = tokio::sync::oneshot::channel();

        if let Some(port_hop) = &cfg.port_hop {
            let hop_requested_clone = hop_requested.clone();
            let interval = port_hop.interval.max(MIN_PORT_HOP_INTERVAL);

            if !PORT_HOP_WARN.swap(true, Ordering::Relaxed) {
                warn!(
                    "port hop enabled: interval {}s, range: {}-{}",
                    interval, port_hop.range.start, port_hop.range.end
                );
            }

            tokio::spawn(async move {
                let mark_pending = || {
                    if !hop_requested_clone.swap(true, Ordering::SeqCst) {
                        debug!("marking port hop as pending");
                    }
                };

                mark_pending();

                loop {
                    let wait_time = {
                        let mut rng = rand::rng();
                        rng.random_range(MIN_PORT_HOP_INTERVAL..=interval)
                    };
                    debug!("scheduled port hop request in {} seconds", wait_time);

                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(wait_time)) => {
                            mark_pending();
                        }
                        _ = &mut hop_shutdown_rx => {
                            break;
                        }
                    }
                }
            });
        }

        Self {
            quic_conn: None,
            quic_end: OnceCell::new(),
            config: cfg,
            hop_requested,
            hop_shutdown_tx: Some(hop_shutdown_tx),
        }
    }

    pub async fn init_endpoint(&self, ipv6: bool) -> Result<EndClient, SError> {
        EndClient::new(&self.config, ipv6).await
    }

    pub fn new_with_socket(cfg: SunnyQuicClientCfg, socket: UdpSocket) -> Result<Self, SError> {
        let mut client = Self::new(cfg);

        client.quic_end = OnceCell::from(EndClient::new_with_socket(&client.config, socket)?);
        Ok(client)
    }

    pub async fn get_conn(&self) -> Result<SunnyQuicConn, SError> {
        let addr = self
            .config
            .addr
            .to_socket_addrs()
            .unwrap_or_else(|_| panic!("resolve quic addr faile: {}", self.config.addr))
            .next()
            .unwrap_or_else(|| panic!("resolve quic addr faile: {}", self.config.addr));
        let end = self
            .quic_end
            .get_or_init(|| async {
                match self.init_endpoint(true).await {
                    Ok(ep) => ep,
                    Err(_) => self
                        .init_endpoint(false)
                        .await
                        .expect("error during initialize quic endpoint"),
                }
            })
            .await;
        let conn = QuicClient::connect(end, addr, &self.config.server_name).await?;

        let conn = SQConn {
            conn,
            authed: Arc::new(SetOnce::new()),
            send_id_store: Default::default(),
            recv_id_store: IDStore {
                id_counter: Default::default(),
                inner: Default::default(),
            },
        };

        let username = self.config.username.clone();
        let password = self.config.password.clone();
        let conn_clone = conn.clone();
        tokio::spawn(async move {
            let _ = auth_sunny(&conn_clone, gen_sunny_user_hash(&username, &password))
                .await
                .map_err(|x| error!("authentication failed: {}", x));
            let _ = handle_udp_packet_recv(conn_clone)
                .await
                .map_err(|x| error!("handle udp packet recv error: {}", x));
        });
        Ok(conn)
    }

    async fn hop_port(&mut self) -> Result<(), SError> {
        let base_addr = self
            .config
            .addr
            .to_socket_addrs()
            .unwrap_or_else(|_| panic!("resolve quic addr faile: {}", self.config.addr))
            .next()
            .unwrap_or_else(|| panic!("resolve quic addr faile: {}", self.config.addr));

        let ip = base_addr.ip();
        let base_port = base_addr.port();

        let target_port = match &self.config.port_hop {
            Some(port_hop) => {
                let mut rng = rand::rng();
                let (start, end) = (port_hop.range.start, port_hop.range.end);
                let port = rng.random_range(start..=end);
                debug!("selected random port {} (range: {}-{})", port, start, end);
                port
            }
            None => base_port,
        };

        let addr = SocketAddr::new(ip, target_port);
        info!("starting port hop to server {}", addr);

        if let Some(ref conn) = self.quic_conn {
            conn.conn.close(0u8.into(), b"port hop");
        }

        self.quic_conn = None;
        self.quic_end.take();

        let end = match self.init_endpoint(true).await {
            Ok(ep) => ep,
            Err(_) => self.init_endpoint(false).await?,
        };
        let _ = self.quic_end.set(end);

        let end = self
            .quic_end
            .get()
            .expect("quic endpoint must be initialized after port hop");

        let conn = QuicClient::connect(end, addr, &self.config.server_name).await?;

        let new_conn = SQConn {
            conn,
            authed: Arc::new(SetOnce::new()),
            send_id_store: Default::default(),
            recv_id_store: IDStore {
                id_counter: Default::default(),
                inner: Default::default(),
            },
        };

        let conn_clone = new_conn.clone();
        tokio::spawn(async move {
            let _ = handle_udp_packet_recv(conn_clone)
                .await
                .map_err(|x| error!("handle udp packet recv error: {}", x));
        });

        self.quic_conn = Some(new_conn);

        debug!("port hopped to server port {}", target_port);
        Ok(())
    }

    async fn prepare_conn(&mut self) -> Result<(), SError> {
        if self.hop_requested.swap(false, Ordering::SeqCst) {
            match self.hop_port().await {
                Ok(()) => {}
                Err(e) => error!("hop_port failed: {}", e),
            }
        }

        // delete connection if closed.
        self.quic_conn.take_if(|x| {
            QuicConnection::close_reason(&x.conn).is_some_and(|x| {
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
#[async_trait]
impl Outbound for SunnyQuicClient {
    async fn handle(&mut self, req: crate::ProxyRequest) -> Result<(), crate::error::SError> {
        self.prepare_conn().await?;

        let conn = self.quic_conn.as_mut().unwrap().clone();

        let over_stream = self.config.over_stream;
        handle_request(req, conn, over_stream).await?;
        Ok(())
    }
}
