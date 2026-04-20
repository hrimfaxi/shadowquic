#![allow(clippy::while_let_loop, clippy::collapsible_if)]
use rand::Rng;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::utils::port_union::PortUnion;

pub struct UdpHopAddr {
    pub host: String,
    pub ports: Vec<u16>,
}

impl UdpHopAddr {
    pub fn parse(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.rsplitn(2, ':').collect();
        if parts.len() != 2 {
            return Err("Invalid address format".into());
        }
        let port_str = parts[0];
        let host = parts[1].to_string();
        let port_union: PortUnion = port_str.parse()?;
        let ports = port_union.ports();
        Ok(Self { host, ports })
    }
}

pub struct UdpHopClientProxy;

fn select_hop_interval_ms(min_hop_interval: u32, max_hop_interval: u32) -> u64 {
    let (min_interval, max_interval) = if min_hop_interval <= max_hop_interval {
        (min_hop_interval, max_hop_interval)
    } else {
        warn!(
            "Invalid hop interval range: min_hop_interval ({}) > max_hop_interval ({}), swapping them",
            min_hop_interval, max_hop_interval
        );
        (max_hop_interval, min_hop_interval)
    };

    rand::rng().random_range(min_interval..=max_interval) as u64
}

impl UdpHopClientProxy {
    pub async fn start(
        addr: &UdpHopAddr,
        min_hop_interval: u32,
        max_hop_interval: u32,
    ) -> Result<SocketAddr, std::io::Error> {
        let host_addrs = tokio::net::lookup_host(format!("{}:0", addr.host))
            .await?
            .collect::<Vec<_>>();
        if host_addrs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Host not found",
            ));
        }
        let base_addr = host_addrs[0];
        let is_ipv6 = base_addr.is_ipv6();

        let local_socket =
            Arc::new(UdpSocket::bind(if is_ipv6 { "[::1]:0" } else { "127.0.0.1:0" }).await?);
        let local_port = local_socket.local_addr()?;

        let quinn_addr = Arc::new(RwLock::new(None));

        let current_socket =
            Arc::new(UdpSocket::bind(if is_ipv6 { "[::]:0" } else { "0.0.0.0:0" }).await?);
        let current_target_port = addr.ports[rand::rng().random_range(0..addr.ports.len())];

        info!(
            "UdpHop initialized with {} target ports (from {} to {})",
            addr.ports.len(),
            addr.ports.first().unwrap_or(&0),
            addr.ports.last().unwrap_or(&0)
        );

        let state = Arc::new(RwLock::new(ProxyState {
            current: current_socket.clone(),
            prev: None,
            current_target_port,
        }));

        let ports = addr.ports.clone();

        // Spawn hop loop
        let state_hop = state.clone();
        let local_socket_hop = local_socket.clone();
        let quinn_addr_hop = quinn_addr.clone();

        tokio::spawn(async move {
            loop {
                let interval = select_hop_interval_ms(min_hop_interval, max_hop_interval);
                tokio::time::sleep(Duration::from_millis(interval)).await;

                let new_socket =
                    match UdpSocket::bind(if is_ipv6 { "[::]:0" } else { "0.0.0.0:0" }).await {
                        Ok(s) => Arc::new(s),
                        Err(e) => {
                            error!("Failed to bind new socket for hop: {}", e);
                            continue;
                        }
                    };

                let new_port = ports[rand::rng().random_range(0..ports.len())];

                let mut st = state_hop.write().await;
                let old_current = st.current.clone();
                st.prev = Some(old_current);
                st.current = new_socket.clone();
                st.current_target_port = new_port;
                drop(st);

                debug!("Hopped to new socket, new target port: {}", new_port);

                // Spawn receiver for the new socket
                spawn_internet_receiver(
                    new_socket,
                    local_socket_hop.clone(),
                    quinn_addr_hop.clone(),
                );
            }
        });

        // Spawn initial internet receiver
        spawn_internet_receiver(current_socket, local_socket.clone(), quinn_addr.clone());

        // Spawn local receiver (from Quinn to internet)
        let state_local = state.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                match local_socket.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        let mut qa = quinn_addr.write().await;
                        if qa.is_none() || qa.unwrap() != src {
                            *qa = Some(src);
                        }
                        drop(qa);

                        let st = state_local.read().await;
                        let socket = st.current.clone();
                        let mut target = base_addr;
                        target.set_port(st.current_target_port);
                        drop(st);

                        if len > 1500 {
                            debug!(
                                "Warning: Large UDP packet received from local Quinn: {} bytes",
                                len
                            );
                        }

                        if let Err(e) = socket.send_to(&buf[..len], target).await {
                            error!("Failed to forward packet to internet: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Local proxy socket recv error: {}", e);
                        break;
                    }
                }
            }
        });

        info!("UdpHop proxy started on {}", local_port);
        Ok(local_port)
    }
}

fn spawn_internet_receiver(
    socket: Arc<UdpSocket>,
    local_socket: Arc<UdpSocket>,
    quinn_addr: Arc<RwLock<Option<SocketAddr>>>,
) {
    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, _)) => {
                    let qa = quinn_addr.read().await;
                    if let Some(addr) = *qa {
                        if let Err(e) = local_socket.send_to(&buf[..len], addr).await {
                            error!("Failed to forward packet to local Quinn: {}", e);
                        }
                    }
                }
                Err(_) => {
                    // Socket might be closed or error, just exit the loop
                    break;
                }
            }
        }
    });
}

struct ProxyState {
    current: Arc<UdpSocket>,
    prev: Option<Arc<UdpSocket>>,
    current_target_port: u16,
}
