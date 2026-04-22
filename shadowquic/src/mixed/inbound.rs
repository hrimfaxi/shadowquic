use std::net::SocketAddr;

use anyhow::Result;
use async_trait::async_trait;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{io::AsyncReadExt, net::TcpListener};
use tracing::{Instrument, trace_span};

use crate::{
    Inbound, ProxyRequest,
    config::AuthUser,
    config::MixedServerCfg,
    error::SError,
    http::inbound::{HttpProxyServer, ProxyBasicAuth},
    socks::inbound::SocksServer,
    utils::dual_socket::to_ipv4_mapped,
    utils::replay_stream::ReplayStream,
};

pub struct MixedServer {
    bind_addr: SocketAddr,
    listener: TcpListener,
    http: HttpProxyServer,
    users: Vec<AuthUser>,
}

impl MixedServer {
    pub async fn new(cfg: MixedServerCfg) -> Result<Self, SError> {
        let MixedServerCfg { bind_addr, users } = cfg;

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

        let listener = TcpListener::from_std(socket.into())
            .map_err(|e| SError::SocksError(format!("failed to create TcpListener: {e}")))?;

        let http_users = users
            .iter()
            .map(|u| ProxyBasicAuth {
                username: u.username.clone(),
                password: u.password.clone(),
            })
            .collect();

        Ok(Self {
            bind_addr,
            listener,
            http: HttpProxyServer::with_users(http_users),
            users,
        })
    }

    fn looks_like_socks5(buf: &[u8]) -> bool {
        !buf.is_empty() && buf[0] == 0x05
    }

    fn looks_like_http(buf: &[u8]) -> bool {
        const METHODS: &[&[u8]] = &[
            b"CONNECT ",
            b"GET ",
            b"POST ",
            b"PUT ",
            b"DELETE ",
            b"HEAD ",
            b"OPTIONS ",
            b"PATCH ",
            b"TRACE ",
        ];
        METHODS.iter().any(|m| buf.starts_with(m))
    }
}

#[async_trait]
impl Inbound for MixedServer {
    async fn accept(&mut self) -> Result<ProxyRequest, SError> {
        let (mut stream, addr) = self.listener.accept().await?;
        let local_addr = to_ipv4_mapped(stream.local_addr().unwrap());
        let span = trace_span!(
            "mixed",
            src = addr.to_string(),
            server = self.bind_addr.to_string()
        );

        async {
            let mut sniff = vec![0u8; 1024];
            let n = stream.read(&mut sniff).await?;
            if n == 0 {
                return Err(SError::SocksError(
                    "connection closed before protocol sniff".into(),
                ));
            }
            sniff.truncate(n);

            if Self::looks_like_socks5(&sniff) {
                return SocksServer::accept_stream_with_local_addr(
                    ReplayStream::new(sniff, stream),
                    local_addr,
                    &self.users,
                )
                .await;
            }

            if Self::looks_like_http(&sniff) {
                return self
                    .http
                    .accept_stream(ReplayStream::new(sniff, stream))
                    .await;
            }

            Err(SError::ProtocolViolation)
        }
        .instrument(span)
        .await
    }
}
