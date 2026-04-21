use async_trait::async_trait;
use rand::Rng;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::SetOnce;
use tracing::{debug, error, info, warn};

use super::quinn_wrapper::EndClient;

use crate::{
    Outbound, config::MAX_DRAINING_PATHS, config::MIN_PORT_HOP_INTERVAL,
    config::PORT_HOP_DRAIN_TIMEOUT, config::ShadowQuicClientCfg, error::SError, quic::QuicClient,
    squic::outbound::handle_request,
};

use crate::squic::{IDStore, SQConn, handle_udp_packet_recv};

pub type ShadowQuicConn = SQConn<<EndClient as QuicClient>::C>;

struct DrainingPath {
    end: EndClient,
    conn: ShadowQuicConn,
    addr: SocketAddr,
    since: Instant,
}

pub struct ShadowQuicClient {
    /// Current active connection used by new requests.
    pub quic_conn: Option<ShadowQuicConn>,
    pub config: ShadowQuicClientCfg,

    /// Cached endpoints split by address family.
    pub quic_end_v4: Option<EndClient>,
    pub quic_end_v6: Option<EndClient>,

    /// Current active remote address.
    current_addr: Option<SocketAddr>,

    /// Current active target port.
    current_target_port: Option<u16>,

    /// Old paths kept alive temporarily so existing requests can drain.
    draining: Vec<DrainingPath>,

    /// Flag indicating that a port hop should be performed on the next prepare_conn call.
    hop_requested: Arc<AtomicBool>,

    /// Graceful shutdown signal sender for hop timer.
    hop_shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for ShadowQuicClient {
    fn drop(&mut self) {
        if let Some(tx) = self.hop_shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

static PORT_HOP_WARN: AtomicBool = AtomicBool::new(false);

impl ShadowQuicClient {
    pub fn new(cfg: ShadowQuicClientCfg) -> Self {
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
            quic_end_v4: None,
            quic_end_v6: None,
            current_addr: None,
            current_target_port: None,
            draining: Vec::new(),
            config: cfg,
            hop_requested,
            hop_shutdown_tx: Some(hop_shutdown_tx),
        }
    }

    pub async fn init_endpoint(&self, ipv6: bool) -> Result<EndClient, SError> {
        EndClient::new(&self.config, ipv6).await
    }

    pub fn new_with_socket(cfg: ShadowQuicClientCfg, socket: UdpSocket) -> Result<Self, SError> {
        let local = socket.local_addr()?;
        let end = EndClient::new_with_socket(&cfg, socket)?;

        Ok(if local.is_ipv6() {
            let mut client = Self::new(cfg);
            client.quic_end_v6 = Some(end);
            client
        } else {
            let mut client = Self::new(cfg);
            client.quic_end_v4 = Some(end);
            client
        })
    }

    fn resolve_addrs(&self) -> Vec<SocketAddr> {
        let addrs: Vec<_> = self
            .config
            .addr
            .to_socket_addrs()
            .unwrap_or_else(|_| panic!("resolve quic addr faile: {}", self.config.addr))
            .collect();

        if addrs.is_empty() {
            panic!("resolve quic addr faile: {}", self.config.addr);
        }

        addrs
    }

    fn base_port(&self) -> u16 {
        self.resolve_addrs()
            .first()
            .map(SocketAddr::port)
            .unwrap_or_else(|| panic!("resolve quic addr faile: {}", self.config.addr))
    }

    fn select_target_port(&self) -> u16 {
        match (&self.config.port_hop, self.current_target_port) {
            (Some(port_hop), current_port) => {
                let (start, end) = (port_hop.range.start, port_hop.range.end);
                let mut rng = rand::rng();

                let mut selected = current_port.unwrap_or(start);

                for _ in 0..8 {
                    let port = rng.random_range(start..=end);
                    selected = port;
                    if Some(port) != current_port || start == end {
                        break;
                    }
                }

                debug!(
                    "selected target port {} (range: {}-{})",
                    selected, start, end
                );
                selected
            }
            (None, _) => self.base_port(),
        }
    }

    fn candidate_addrs_for_port(&self, port: u16) -> Vec<SocketAddr> {
        self.resolve_addrs()
            .into_iter()
            .map(|mut addr| {
                addr.set_port(port);
                addr
            })
            .collect()
    }

    fn spawn_recv_task(conn: ShadowQuicConn) {
        tokio::spawn(async move {
            let _ = handle_udp_packet_recv(conn)
                .await
                .map_err(|x| error!("handle udp packet recv error: {}", x));
        });
    }

    fn wrap_conn(raw: <EndClient as QuicClient>::C) -> ShadowQuicConn {
        SQConn {
            conn: raw,
            authed: Arc::new(SetOnce::new_with(Some(true))),
            send_id_store: Default::default(),
            recv_id_store: IDStore {
                id_counter: Default::default(),
                inner: Default::default(),
            },
        }
    }

    async fn connect_with_endpoint(
        &self,
        end: &EndClient,
        addr: SocketAddr,
    ) -> Result<ShadowQuicConn, SError> {
        let raw = end.connect(addr, &self.config.server_name).await?;
        let conn = Self::wrap_conn(raw);
        Self::spawn_recv_task(conn.clone());
        Ok(conn)
    }

    async fn build_path_for_addr(
        &mut self,
        addr: SocketAddr,
    ) -> Result<(EndClient, ShadowQuicConn), SError> {
        if addr.is_ipv6() {
            if self.quic_end_v6.is_none() {
                self.quic_end_v6 = Some(self.init_endpoint(true).await?);
            }

            let end = self
                .quic_end_v6
                .take()
                .expect("missing cached ipv6 endpoint after initialization");

            let conn = self.connect_with_endpoint(&end, addr).await?;
            Ok((end, conn))
        } else {
            if self.quic_end_v4.is_none() {
                self.quic_end_v4 = Some(self.init_endpoint(false).await?);
            }

            let end = self
                .quic_end_v4
                .take()
                .expect("missing cached ipv4 endpoint after initialization");

            let conn = self.connect_with_endpoint(&end, addr).await?;
            Ok((end, conn))
        }
    }

    async fn build_path_for_port(
        &mut self,
        port: u16,
    ) -> Result<(EndClient, ShadowQuicConn, SocketAddr), SError> {
        let mut last_err = None;

        for addr in self.candidate_addrs_for_port(port) {
            match self.build_path_for_addr(addr).await {
                Ok((end, conn)) => return Ok((end, conn, addr)),
                Err(e) => {
                    error!("connect to {} failed: {}", addr, e);
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            std::io::Error::other("no usable quic target address for selected port").into()
        }))
    }

    fn restore_active_endpoint(&mut self, addr: SocketAddr, end: EndClient) {
        if addr.is_ipv6() {
            self.quic_end_v6 = Some(end);
        } else {
            self.quic_end_v4 = Some(end);
        }
    }

    fn cleanup_draining(&mut self) {
        self.draining.retain(|path| {
            let _keep_endpoint_alive = &path.end;

            if let Some(reason) = path.conn.close_reason() {
                debug!(
                    "drained quic connection to {} closed due to {}",
                    path.addr, reason
                );
                return false;
            }

            if path.since.elapsed() >= PORT_HOP_DRAIN_TIMEOUT {
                debug!(
                    "closing drained quic connection to {} after {:?}",
                    path.addr, PORT_HOP_DRAIN_TIMEOUT
                );
                path.conn.conn.close(0u8.into(), b"port hop drain timeout");
                return false;
            }

            true
        });

        while self.draining.len() > MAX_DRAINING_PATHS {
            let old = self.draining.remove(0);
            debug!(
                "closing oldest drained quic connection to {} because draining set exceeds {}",
                old.addr, MAX_DRAINING_PATHS
            );
            old.conn
                .conn
                .close(0u8.into(), b"port hop draining overflow");
        }
    }

    pub async fn get_conn(&self) -> Result<ShadowQuicConn, SError> {
        self.quic_conn
            .clone()
            .ok_or_else(|| std::io::Error::other("quic connection not prepared").into())
    }

    async fn hop_port(&mut self) -> Result<(), SError> {
        let new_port = self.select_target_port();
        info!("starting soft port hop to target port {}", new_port);

        // 1. Build new path first. If this fails, the old path remains intact.
        let (new_end, new_conn, new_addr) = self.build_path_for_port(new_port).await?;

        // 2. Move old active path into draining instead of closing it immediately.
        if let Some(old_conn) = self.quic_conn.take() {
            let old_addr = self.current_addr.unwrap_or(new_addr);

            let old_end = if old_addr.is_ipv6() {
                self.quic_end_v6.take()
            } else {
                self.quic_end_v4.take()
            };

            if let Some(old_end) = old_end {
                debug!("moving old quic path {} into draining set", old_addr);
                self.draining.push(DrainingPath {
                    end: old_end,
                    conn: old_conn,
                    addr: old_addr,
                    since: Instant::now(),
                });
            } else {
                warn!(
                    "active quic connection exists without matching endpoint; closing old path during hop"
                );
                old_conn
                    .conn
                    .close(0u8.into(), b"port hop missing endpoint");
            }
        }

        // 3. Switch new path to active.
        self.restore_active_endpoint(new_addr, new_end);
        self.quic_conn = Some(new_conn);
        self.current_addr = Some(new_addr);
        self.current_target_port = Some(new_port);

        // 4. Opportunistic cleanup.
        self.cleanup_draining();

        debug!("soft port hopped to server {}", new_addr);
        Ok(())
    }

    async fn ensure_active_conn(&mut self) -> Result<(), SError> {
        if self.quic_conn.is_some() {
            return Ok(());
        }

        let port = self.current_target_port.unwrap_or_else(|| self.base_port());
        let (end, conn, addr) = self.build_path_for_port(port).await?;

        self.restore_active_endpoint(addr, end);
        self.quic_conn = Some(conn);
        self.current_addr = Some(addr);
        self.current_target_port = Some(port);

        Ok(())
    }

    async fn prepare_conn(&mut self) -> Result<(), SError> {
        // Clean up old drained paths first.
        self.cleanup_draining();

        // If active connection is already closed, drop the active path.
        let active_closed_reason = self.quic_conn.as_ref().and_then(|x| x.close_reason());

        if let Some(reason) = active_closed_reason {
            debug!("active quic connection closed due to {}", reason);
            self.quic_conn = None;

            if let Some(addr) = self.current_addr.take() {
                if addr.is_ipv6() {
                    self.quic_end_v6 = None;
                } else {
                    self.quic_end_v4 = None;
                }
            }
        }

        // Process pending hop request using make-before-break.
        if self.hop_requested.swap(false, Ordering::SeqCst) {
            match self.hop_port().await {
                Ok(()) => {}
                Err(e) => error!("hop_port failed: {}", e),
            }
        }

        // Ensure there is an active connection.
        self.ensure_active_conn().await?;

        Ok(())
    }
}

#[async_trait]
impl Outbound for ShadowQuicClient {
    async fn handle(&mut self, req: crate::ProxyRequest) -> Result<(), crate::error::SError> {
        self.prepare_conn().await?;

        let conn = self.quic_conn.as_ref().unwrap().clone();
        let over_stream = self.config.over_stream;

        handle_request(req, conn, over_stream).await?;
        Ok(())
    }
}
