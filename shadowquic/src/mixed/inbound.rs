use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tracing::{Instrument, error, info_span};

use crate::{
    Inbound, ProxyRequest,
    config::AuthUser,
    config::MixedServerCfg,
    error::{SError, SResult},
    http::inbound::{HttpProxyServer, ProxyBasicAuth},
    socks::inbound::SocksServer,
    utils::dual_socket::to_ipv4_mapped,
    utils::replay_stream::ReplayStream,
};

pub struct MixedServer {
    http: Arc<HttpProxyServer>,
    users: Arc<Vec<AuthUser>>,
    request_sender: Sender<ProxyRequest>,
    request_receiver: Receiver<ProxyRequest>,
    /// Owned here, not by a spawned task. An `accept(2)` failure has to reach
    /// the caller of `accept`, and a listener whose only owner is a detached
    /// task has nobody to report one to: the task ends, the listener is
    /// dropped with it, and the port closes with no error line anywhere.
    listener: TcpListener,
}

impl MixedServer {
    pub async fn new(cfg: MixedServerCfg) -> Result<Self, SError> {
        let listener = Self::bind(cfg.bind_addr)?;
        let http = Arc::new(HttpProxyServer::with_users(
            cfg.users
                .iter()
                .map(|u| ProxyBasicAuth {
                    username: u.username.clone(),
                    password: u.password.clone(),
                })
                .collect(),
        ));
        let users = Arc::new(cfg.users.clone());
        let (s, r) = channel(20);
        Ok(Self {
            http,
            users,
            request_sender: s,
            request_receiver: r,
            listener,
        })
    }

    fn bind(bind_addr: SocketAddr) -> Result<TcpListener, SError> {
        let dual_stack = bind_addr.is_ipv6();
        let socket = Socket::new(
            if dual_stack {
                Domain::IPV6
            } else {
                Domain::IPV4
            },
            Type::STREAM,
            Some(Protocol::TCP),
        )?;
        if dual_stack {
            let _ = socket
                .set_only_v6(false)
                .map_err(|e| tracing::warn!("failed to set dual stack for socket: {}", e));
        }
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&bind_addr.into())?;
        socket.listen(256)?;
        TcpListener::from_std(socket.into())
            .map_err(|e| SError::SocksError(format!("failed to create TcpListener: {e}")))
    }

    /// Runs one accepted connection in a task of its own, so a client that
    /// stalls mid-handshake cannot hold up the next `accept`.
    fn spawn_handshake(&self, stream: TcpStream, addr: SocketAddr) {
        // Same reason as socks/inbound.rs: the handshake replies are written
        // field by field, so Nagle plus the peer's delayed ACK costs about
        // 40ms per connection unless it is off.
        let _ = stream.set_nodelay(true);
        let span = info_span!("mixed", src = %addr);
        let http = self.http.clone();
        let users = self.users.clone();
        let req_send = self.request_sender.clone();
        tokio::spawn(
            async move {
                if let Err(x) = handle_connection(stream, http, users, req_send).await {
                    error!("failed to handle mixed connection: {}", x)
                }
            }
            .instrument(span),
        );
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    http: Arc<HttpProxyServer>,
    users: Arc<Vec<AuthUser>>,
    sender: Sender<ProxyRequest>,
) -> SResult<()> {
    use tokio::io::AsyncReadExt;

    let local_addr = to_ipv4_mapped(stream.local_addr().unwrap());
    let first_byte = stream.read_u8().await?;

    let req = if first_byte == 0x05 {
        let prefix = vec![first_byte];
        SocksServer::accept_stream_with_local_addr(
            ReplayStream::new(prefix, stream),
            local_addr,
            &users,
        )
        .await?
    } else {
        let prefix = vec![first_byte];
        http.accept_stream(ReplayStream::new(prefix, stream))
            .await?
    };

    sender
        .send(req)
        .await
        .map_err(|_| SError::ChannelError("mixed request channel closed".into()))
}

#[async_trait]
impl Inbound for MixedServer {
    async fn accept(&mut self) -> Result<ProxyRequest, SError> {
        loop {
            let accepted = {
                let listener = &self.listener;
                let receiver = &mut self.request_receiver;
                tokio::select! {
                    // An accept(2) failure is returned to the caller, which
                    // logs it and retries with backoff. The listener is a field
                    // of this struct, so the error cannot take the port with
                    // it: the next `accept` keeps serving.
                    accepted = listener.accept() => accepted?,
                    request = receiver.recv() => {
                        return request.ok_or(SError::InboundUnavailable);
                    }
                }
            };
            self.spawn_handshake(accepted.0, accepted.1);
        }
    }
}
