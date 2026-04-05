use async_trait::async_trait;
use std::{
    net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{OnceCell, SetOnce};
use rand::Rng;
use tracing::{debug, error, info};

use super::quinn_wrapper::EndClient;

use crate::{
    Outbound, config::ShadowQuicClientCfg, error::SError, quic::QuicClient,
    squic::outbound::handle_request,
};

use crate::squic::{IDStore, SQConn, handle_udp_packet_recv};

pub type ShadowQuicConn = SQConn<<EndClient as QuicClient>::C>;

/// Minimum port hop interval in seconds
const MIN_PORT_HOP_INTERVAL: u64 = 5;

/// Parse port range string like "50000-60000" into (start, end)
fn parse_port_range(range_str: &str) -> Option<(u16, u16)> {
    let parts: Vec<&str> = range_str.split('-').collect();
    if parts.len() != 2 {
        return None;
    }
    let start: u16 = parts[0].trim().parse().ok()?;
    let end: u16 = parts[1].trim().parse().ok()?;
    if start <= end {
        Some((start, end))
    } else {
        Some((end, start))
    }
}

pub struct ShadowQuicClient {
    pub quic_conn: Option<ShadowQuicConn>,
    pub config: ShadowQuicClientCfg,
    pub quic_end: OnceCell<EndClient>,
    /// Flag to request immediate hop
    hop_requested: Arc<std::sync::atomic::AtomicBool>,
    /// Flag indicating hop is currently in progress
    hop_in_progress: Arc<std::sync::atomic::AtomicBool>,
    /// Graceful shutdown signal sender for hop timer
    hop_shutdown_tx: tokio::sync::watch::Sender<()>,
}

impl Drop for ShadowQuicClient {
    fn drop(&mut self) {
        let _ = self.hop_shutdown_tx.send(());
    }
}

impl ShadowQuicClient {
    pub fn new(cfg: ShadowQuicClientCfg) -> Self {
        let hop_requested = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hop_in_progress = Arc::new(std::sync::atomic::AtomicBool::new(false));
        
        // Create watch channel for graceful shutdown
        let (hop_shutdown_tx, mut hop_shutdown_rx) = tokio::sync::watch::channel(());
        
        // Start the hop timer if port hopping is enabled
        if cfg.port_hop_interval > 0 && cfg.port_hop_server_ports.is_some() {
            let flag = hop_requested.clone();
            let in_progress = hop_in_progress.clone();
            let interval = cfg.port_hop_interval;
            
            tokio::spawn(async move {
                loop {
                    // Calculate wait time for this cycle
                    let wait_time = if interval < MIN_PORT_HOP_INTERVAL {
                        MIN_PORT_HOP_INTERVAL
                    } else {
                        let random: u64 = rand::random();
                        MIN_PORT_HOP_INTERVAL + (random % (interval - MIN_PORT_HOP_INTERVAL + 1))
                    };
                    
                    debug!("[PortHop] Next hop scheduled in {} seconds", wait_time);
                    
                    // Wait for timeout or shutdown signal
                    match tokio::time::timeout(Duration::from_secs(wait_time), hop_shutdown_rx.changed()).await {
                        Ok(Ok(())) => {
                            info!("[PortHop] Hop timer stopped gracefully");
                            break;
                        }
                        Ok(Err(_)) | Err(_) => {
                            // Check if hop is already in progress, wait for it to complete
                            if flag.load(std::sync::atomic::Ordering::SeqCst) {
                                // Wait for hop to complete
                                loop {
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                    if !flag.load(std::sync::atomic::Ordering::SeqCst) {
                                        break;
                                    }
                                }
                                continue;
                            }
                            
                            // Trigger hop
                            info!("[PortHop] Triggering port hop request");
                            flag.store(true, std::sync::atomic::Ordering::SeqCst);
                            in_progress.store(true, std::sync::atomic::Ordering::SeqCst);
                            
                            // Wait for hop to complete (flags will be cleared by prepare_conn)
                            loop {
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                if !flag.load(std::sync::atomic::Ordering::SeqCst) {
                                    break;
                                }
                            }
                            
                            info!("[PortHop] Hop completed, scheduling next hop");
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
            hop_in_progress,
            hop_shutdown_tx,
        }
    }
    
    pub async fn init_endpoint(&self, ipv6: bool) -> Result<EndClient, SError> {
        EndClient::new(&self.config, ipv6).await
    }
    
    pub fn new_with_socket(cfg: ShadowQuicClientCfg, socket: UdpSocket) -> Result<Self, SError> {
        // Create basic client first (this starts the hop timer if enabled)
        let mut client = Self::new(cfg);
        
        // Override with the provided socket
        client.quic_end = OnceCell::from(EndClient::new_with_socket(&client.config, socket)?);
        
        Ok(client)
    }
    
    /// Get server base address from config (used for initial connection)
    fn get_server_base_addr(&self) -> (IpAddr, u16) {
        let addr = self
            .config
            .addr
            .to_socket_addrs()
            .unwrap_or_else(|_| panic!("resolve quic addr failed: {}", self.config.addr))
            .next()
            .unwrap_or_else(|| panic!("resolve quic addr failed: {}", self.config.addr));
        (addr.ip(), addr.port())
    }

    pub async fn get_conn(&self) -> Result<ShadowQuicConn, SError> {
        let addr = self.get_server_base_addr();
        let addr = SocketAddr::new(addr.0, addr.1);
        
        debug!("[PortHop] Connecting to server at {}", addr);
        
        let conn = self
            .quic_end
            .get_or_init(|| async {
                self.init_endpoint(addr.is_ipv6())
                    .await
                    .expect("error during initialize quic endpoint")
            })
            .await
            .connect(addr, &self.config.server_name)
            .await?;

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
                .map_err(|x| debug!("[PortHop] recv task ended: {}", x));
        });
        Ok(conn)
    }
    
    /// Create a new QUIC endpoint
    async fn create_new_endpoint(&self, ipv6: bool) -> Result<EndClient, SError> {
        EndClient::new(&self.config, ipv6).await
    }
    
    /// Hop to a new server port by creating a new QUIC connection
    async fn hop_port(&mut self) -> Result<(), SError> {
        let (ip, base_port) = self.get_server_base_addr();
        
        // Select random port from range
        let target_port = if let Some(ref range_str) = self.config.port_hop_server_ports {
            if let Some((start, end)) = parse_port_range(range_str) {
                let mut rng = rand::rng();
                let port = rng.random_range(start..=end);
                info!("[PortHop] Selected random port {} (range: {}-{})", port, start, end);
                port
            } else {
                error!("[PortHop] Failed to parse port range");
                base_port
            }
        } else {
            base_port
        };
        
        let addr = SocketAddr::new(ip, target_port);
        info!("[PortHop] Starting port hop to server {}", addr);
        
        // Close existing connection if any
        if let Some(ref conn) = self.quic_conn {
            debug!("[PortHop] Closing existing connection");
            conn.conn.close(0u8.into(), b"port hop");
        }
        
        // Clear the old connection and endpoint
        self.quic_conn = None;
        self.quic_end.take();
        
        // Create new endpoint
        let new_end = self.create_new_endpoint(addr.is_ipv6()).await?;
        
        // Store the new endpoint
        let _ = self.quic_end.set(new_end);
        
        // Establish new connection
        let conn = self.quic_end.get().unwrap().connect(addr, &self.config.server_name).await?;
        
        let new_conn = SQConn {
            conn,
            authed: Arc::new(SetOnce::new_with(Some(true))),
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
                .map_err(|x| debug!("[PortHop] recv task ended: {}", x));
        });
        
        self.quic_conn = Some(new_conn);
        
        info!("[PortHop] Successfully hopped to server port {}", target_port);
        Ok(())
    }

    async fn prepare_conn(&mut self) -> Result<(), SError> {
        // Check if we need to hop
        if self.hop_requested.load(std::sync::atomic::Ordering::SeqCst) {
            info!("[PortHop] prepare_conn: hop requested, calling hop_port()");
            let hop_result = self.hop_port().await;
            
            // Always clear flags after hop attempt
            self.hop_requested.store(false, std::sync::atomic::Ordering::SeqCst);
            self.hop_in_progress.store(false, std::sync::atomic::Ordering::SeqCst);
            
            if let Err(e) = hop_result {
                error!("[PortHop] hop_port failed: {}", e);
            }
        }
        
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
