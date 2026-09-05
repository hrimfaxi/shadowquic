use std::sync::{Arc, Weak};
use std::time::Duration;

use bytes::Bytes;
use error::SError;
use msgs::socks5::SocksAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use async_trait::async_trait;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{Instrument, Span, error, info, info_span};

pub mod config;
pub mod direct;
pub mod error;
#[cfg(feature = "mixed")]
pub mod http;
#[cfg(feature = "mixed")]
pub mod mixed;
pub mod msgs;
mod observe;
pub mod quic;
pub mod shadowquic;
pub mod socks;
pub mod squic;
pub mod sunnyquic;
#[cfg(all(feature = "tproxy", target_os = "linux"))]
pub mod tproxy;
pub mod utils;

pub use msgs::SDecode;
pub use msgs::SEncode;
pub enum ProxyRequest<T = AnyTcp, I = AnyUdpRecv, O = AnyUdpSend> {
    Tcp(TcpSession<T>),
    Udp(UdpSession<I, O>),
}
/// Udp socket only use immutable reference to self
/// So it can be safely wrapped by Arc and cloned to work in duplex way.
#[async_trait]
pub trait UdpSend: Send + Sync + Unpin {
    async fn send_to(&self, buf: Bytes, addr: SocksAddr) -> Result<usize, SError>; // addr is proxy addr
}
#[async_trait]
pub trait UdpRecv: Send + Sync + Unpin {
    async fn recv_from(&mut self) -> Result<(Bytes, SocksAddr), SError>; // socksaddr is proxy addr
}
pub trait Stoppable: Send + Sync {
    fn stop(&self);
}
pub type UserName = String;
pub struct TcpSession<IO = AnyTcp> {
    pub stream: IO,
    pub dst: SocksAddr,
    #[allow(dead_code)]
    user_context: Option<UserContext>,
}

pub struct UdpSession<I = AnyUdpRecv, O = AnyUdpSend> {
    pub recv: I,
    pub send: O,
    /// Control stream, should be kept alive during session.
    stream: Option<AnyTcp>,
    bind_addr: SocksAddr,
    #[allow(dead_code)]
    user_context: Option<UserContext>,
}
#[derive(Clone)]
pub struct UserContext {
    pub username: UserName,
    pub conn_handle: Weak<dyn Stoppable>,
    pub conn_id: u64,
}

pub type AnyTcp = Box<dyn TcpTrait>;
pub type AnyUdpSend = Arc<dyn UdpSend>;
pub type AnyUdpRecv = Box<dyn UdpRecv>;
pub trait TcpTrait: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl TcpTrait for TcpStream {}

#[async_trait]
pub trait Inbound<T = AnyTcp, I = AnyUdpRecv, O = AnyUdpSend>: Send + Sync + Unpin {
    async fn accept(&mut self) -> Result<ProxyRequest<T, I, O>, SError>;
    async fn init(&self) -> Result<(), SError> {
        Ok(())
    }
    /// Called once on graceful shutdown, flush persistent state here.
    async fn shutdown(&self) -> Result<(), SError> {
        Ok(())
    }
}

#[async_trait]
pub trait Outbound<T = AnyTcp, I = AnyUdpRecv, O = AnyUdpSend>: Send + Sync + Unpin {
    /// Handle one accepted proxy request.
    ///
    /// Implementations must not drive the whole session inline: spawn the
    /// per-session work and return promptly, so the caller's accept/shutdown
    /// loop keeps making progress (shutdown observation, panic propagation,
    /// bounded draining). All built-in outbounds follow this contract.
    async fn handle(&mut self, req: ProxyRequest<T, I, O>) -> Result<(), SError>;
}

#[async_trait]
impl UdpSend for Sender<(Bytes, SocksAddr)> {
    async fn send_to(&self, buf: Bytes, addr: SocksAddr) -> Result<usize, SError> {
        let siz = buf.len();
        self.send((buf, addr))
            .await
            .map_err(|_| SError::InboundUnavailable)?;
        Ok(siz)
    }
}
#[async_trait]
impl UdpRecv for Receiver<(Bytes, SocksAddr)> {
    async fn recv_from(&mut self) -> Result<(Bytes, SocksAddr), SError> {
        let r = self.recv().await.ok_or(SError::OutboundUnavailable)?;
        Ok(r)
    }
}
/// One proxy instance: traffic accepted by `inbound` is forwarded to `outbound`.
pub struct Instance {
    pub inbound: Box<dyn Inbound>,
    pub outbound: Box<dyn Outbound>,
}

impl Instance {
    pub fn new(inbound: Box<dyn Inbound>, outbound: Box<dyn Outbound>) -> Self {
        Self { inbound, outbound }
    }
}

pub struct Manager {
    pub instances: Vec<Instance>,
}

/// Resolves when a shutdown signal is received (Ctrl-C, plus SIGTERM on unix).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

impl Manager {
    /// Creates a manager with a single inbound/outbound pair.
    pub fn new(inbound: Box<dyn Inbound>, outbound: Box<dyn Outbound>) -> Self {
        Self {
            instances: vec![Instance::new(inbound, outbound)],
        }
    }

    /// Creates a manager running multiple inbound/outbound pairs concurrently.
    ///
    /// # Panics
    /// Panics in debug builds if `instances` is empty; `run` rejects it in
    /// release builds.
    pub fn with_instances(instances: Vec<Instance>) -> Self {
        debug_assert!(
            !instances.is_empty(),
            "Manager requires at least one instance"
        );
        Self { instances }
    }

    /// Runs all instances until a shutdown signal (Ctrl-C / SIGTERM).
    ///
    /// Instances are **not** fault-isolated: if any instance's task exits
    /// unexpectedly (or panics), the remaining instances are shut down
    /// gracefully (flushing their persistent state) and `Err` is returned
    /// so the caller can exit the process. Run the proxy under a supervisor
    /// (systemd, procd, ...) that restarts it on failure.
    pub async fn run(self) -> Result<(), SError> {
        if self.instances.is_empty() {
            return Err(SError::Instance("no instances to run".into()));
        }
        for (i, inst) in self.instances.iter().enumerate() {
            if let Err(e) = inst.inbound.init().await {
                error!(instance = i, "instance init failed: {}", e);
                // Roll back instances initialized so far (best effort), e.g. to
                // flush their persistent state, and surface the init error.
                // Each shutdown is bounded so one hung inbound cannot stall
                // startup forever.
                for (j, prev) in self.instances[..i].iter().enumerate() {
                    match tokio::time::timeout(DRAIN_TIMEOUT, prev.inbound.shutdown()).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            error!(instance = j, "error during rollback shutdown: {}", e)
                        }
                        Err(_) => {
                            error!(
                                instance = j,
                                "rollback shutdown timed out after {}s",
                                DRAIN_TIMEOUT.as_secs()
                            )
                        }
                    }
                }
                return Err(SError::Instance(format!("instance {i} init failed: {e}")));
            }
        }
        info!("running {} instance(s)", self.instances.len());

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let multi = self.instances.len() > 1;
        let mut tasks = JoinSet::new();
        for (i, mut inst) in self.instances.into_iter().enumerate() {
            let mut shutdown_rx = shutdown_rx.clone();
            // The instance index only serves to tell chains apart; skip the
            // span for the common single-instance case to keep logs terse.
            let span = if multi {
                info_span!("instance", n = i)
            } else {
                Span::none()
            };
            let task = async move {
                loop {
                    // biased: once the shutdown signal is out, it strictly
                    // outranks accepting new requests.
                    tokio::select! {
                        biased;
                        _ = shutdown_rx.changed() => {
                            inst.inbound.shutdown().await?;
                            return Ok(());
                        }
                        req = inst.inbound.accept() => match req {
                            Ok(req) => {
                                if let Err(e) = inst.outbound.handle(req).await {
                                    error!("error during handling request: {}", e)
                                }
                            }
                            Err(e) => {
                                error!("error during accepting request: {}", e)
                            }
                        }
                    }
                }
            };
            tasks.spawn(task.instrument(span));
        }

        let shutdown = shutdown_signal();
        tokio::pin!(shutdown);
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown signal received, persisting users and stats");
                let _ = shutdown_tx.send(true);
                drain_instances(&mut tasks).await
            }
            Some(res) = tasks.join_next(), if !tasks.is_empty() => {
                // An instance task ended before the shutdown signal: it either
                // panicked or stopped unexpectedly. Shut the remaining instances
                // down gracefully (flushing their persistent state) before
                // surfacing the error so the caller can exit.
                let err = match res {
                    Ok(Ok(())) => SError::Instance("an instance stopped unexpectedly".into()),
                    Ok(Err(e)) => e,
                    Err(join_err) => SError::Instance(format!("instance task failed: {join_err}")),
                };
                error!("instance stopped unexpectedly: {}", err);
                let _ = shutdown_tx.send(true);
                let _ = drain_instances(&mut tasks).await;
                Err(err)
            }
        }
    }
}

/// Maximum time instances get to shut down gracefully (flush persistent
/// state) before they are aborted. Bounded so a hung `Inbound::shutdown`
/// or a custom `Outbound::handle` that blocks on a live session cannot
/// stall process exit forever.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Waits for all instance tasks to finish and returns the first error
/// (subsequent errors are logged). The shutdown signal must already be sent.
///
/// Graceful draining is bounded by [`DRAIN_TIMEOUT`]; instances still
/// running when it expires are aborted and reported as an error.
async fn drain_instances(tasks: &mut JoinSet<Result<(), SError>>) -> Result<(), SError> {
    let mut result = Ok(());
    let drain = async {
        while let Some(res) = tasks.join_next().await {
            if let Err(e) = match res {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(join_err) => Err(SError::Instance(format!(
                    "instance task failed: {join_err}"
                ))),
            } {
                error!("error during instance shutdown: {}", e);
                if result.is_ok() {
                    result = Err(e);
                }
            }
        }
    };
    if tokio::time::timeout(DRAIN_TIMEOUT, drain).await.is_err() {
        error!(
            "graceful shutdown timed out after {}s, aborting remaining instances",
            DRAIN_TIMEOUT.as_secs()
        );
        // Surface the forced abort to the caller: instances killed here did
        // not flush their persistent state.
        if result.is_ok() {
            result = Err(SError::Instance(format!(
                "graceful shutdown timed out after {}s, remaining instances aborted",
                DRAIN_TIMEOUT.as_secs()
            )));
        }
        tasks.abort_all();
        while let Some(res) = tasks.join_next().await {
            match res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => error!("error during instance shutdown: {}", e),
                Err(join_err) if join_err.is_cancelled() => {
                    error!("instance aborted after shutdown timeout")
                }
                Err(join_err) => error!("instance task failed: {}", join_err),
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Draining must be bounded: a task that never finishes is aborted after
    /// [`DRAIN_TIMEOUT`] and the forced abort surfaces as an error. The
    /// paused tokio clock keeps the [`DRAIN_TIMEOUT`] wait instant.
    #[tokio::test(start_paused = true)]
    async fn drain_timeout_surfaces_error() {
        let mut tasks: JoinSet<Result<(), SError>> = JoinSet::new();
        tasks.spawn(std::future::pending());
        let result = drain_instances(&mut tasks).await;
        assert!(
            matches!(result, Err(SError::Instance(_))),
            "drain timeout must surface as Err, got {result:?}"
        );
    }
}
