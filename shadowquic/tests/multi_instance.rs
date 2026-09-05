use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use fast_socks5::client::Config as SocksClientConfig;
use fast_socks5::client::Socks5Stream;
use shadowquic::config::{Config, SocksServerCfg};
use shadowquic::direct::outbound::DirectOut;
use shadowquic::error::SError;
use shadowquic::socks::inbound::SocksServer;
use shadowquic::{Inbound, Instance, Manager, Outbound, ProxyRequest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Spawns a TCP echo server on a random port, returns its port.
async fn spawn_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = stream.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

fn socks_client_config() -> SocksClientConfig {
    let mut config = SocksClientConfig::default();
    config.set_skip_auth(false);
    config
}

/// Connects to `echo_port` through the socks5 inbound on `proxy_port` and
/// asserts the payload round-trips.
async fn assert_roundtrip(proxy_port: u16, echo_port: u16, payload: &[u8]) {
    let mut stream = Socks5Stream::connect(
        format!("127.0.0.1:{proxy_port}"),
        "127.0.0.1".into(),
        echo_port,
        socks_client_config(),
    )
    .await
    .unwrap();

    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, payload);
}

#[tokio::test]
async fn test_multi_instance_runtime() {
    let (port_a, port_b) = (21021u16, 21022u16);
    let echo_port = spawn_echo().await;

    let in_a = SocksServer::new(SocksServerCfg {
        bind_addr: format!("127.0.0.1:{port_a}").parse().unwrap(),
        users: vec![],
    })
    .await
    .unwrap();
    let in_b = SocksServer::new(SocksServerCfg {
        bind_addr: format!("127.0.0.1:{port_b}").parse().unwrap(),
        users: vec![],
    })
    .await
    .unwrap();

    let manager = Manager::with_instances(vec![
        Instance::new(Box::new(in_a), Box::new(DirectOut::default())),
        Instance::new(Box::new(in_b), Box::new(DirectOut::default())),
    ]);
    tokio::spawn(manager.run());
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Both inbounds serve concurrently in the same process.
    assert_roundtrip(port_a, echo_port, b"hello from instance a").await;
    assert_roundtrip(port_b, echo_port, b"hello from instance b").await;
    assert_roundtrip(port_a, echo_port, b"still alive a").await;
    assert_roundtrip(port_b, echo_port, b"still alive b").await;
}

#[tokio::test]
async fn test_multi_instance_config() {
    let echo_port = spawn_echo().await;
    let yaml = r###"
instances:
    - inbound:
          type: socks
          bind-addr: "127.0.0.1:21031"
      outbound:
          type: direct
          dns-strategy: prefer-ipv4
    - inbound:
          type: socks
          bind-addr: "127.0.0.1:21032"
      outbound:
          type: direct
log-level: info
"###;
    let cfg: Config = serde_saphyr::from_str(yaml).expect("yaml parsed failed");
    assert_eq!(cfg.instances.len(), 2);
    let manager = cfg.build_manager().await.expect("build manager failed");
    tokio::spawn(manager.run());
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_roundtrip(21031, echo_port, b"cfg instance 1").await;
    assert_roundtrip(21032, echo_port, b"cfg instance 2").await;
}

#[tokio::test]
async fn test_legacy_config_still_works() {
    let echo_port = spawn_echo().await;
    let yaml = r###"
inbound:
    type: socks
    bind-addr: "127.0.0.1:21041"
outbound:
    type: direct
    dns-strategy: prefer-ipv4
log-level: info
"###;
    let cfg: Config = serde_saphyr::from_str(yaml).expect("yaml parsed failed");
    assert_eq!(cfg.instances.len(), 1);
    let manager = cfg.build_manager().await.expect("build manager failed");
    tokio::spawn(manager.run());
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_roundtrip(21041, echo_port, b"legacy config").await;
}

/// Outbound stub for lifecycle tests: accepts requests and does nothing.
struct NopOutbound;

#[async_trait]
impl Outbound for NopOutbound {
    async fn handle(&mut self, _req: ProxyRequest) -> Result<(), SError> {
        Ok(())
    }
}

/// Inbound that panics on the first `accept`, simulating an instance crash.
struct PanicInbound;

#[async_trait]
impl Inbound for PanicInbound {
    async fn accept(&mut self) -> Result<ProxyRequest, SError> {
        panic!("instance crashed");
    }
}

/// Inbound whose `accept` never returns and which records `shutdown` calls.
struct PendingInbound {
    shutdown_called: Arc<AtomicBool>,
}

#[async_trait]
impl Inbound for PendingInbound {
    async fn accept(&mut self) -> Result<ProxyRequest, SError> {
        std::future::pending().await
    }
    async fn shutdown(&self) -> Result<(), SError> {
        self.shutdown_called.store(true, Ordering::SeqCst);
        Ok(())
    }
}

/// Inbound whose `init` always fails.
struct FailInitInbound;

#[async_trait]
impl Inbound for FailInitInbound {
    async fn accept(&mut self) -> Result<ProxyRequest, SError> {
        std::future::pending().await
    }
    async fn init(&self) -> Result<(), SError> {
        Err(SError::InboundUnavailable)
    }
}

#[tokio::test]
async fn test_instance_panic_triggers_graceful_shutdown_of_others() {
    let shutdown_called = Arc::new(AtomicBool::new(false));
    let manager = Manager::with_instances(vec![
        Instance::new(Box::new(PanicInbound), Box::new(NopOutbound)),
        Instance::new(
            Box::new(PendingInbound {
                shutdown_called: shutdown_called.clone(),
            }),
            Box::new(NopOutbound),
        ),
    ]);

    // run() must surface the instance failure ...
    let result = tokio::time::timeout(Duration::from_secs(30), manager.run())
        .await
        .expect("run() must return after an instance crash, not hang");
    assert!(result.is_err());

    // ... and the surviving instance must have been shut down gracefully,
    // not silently aborted with the JoinSet.
    assert!(
        shutdown_called.load(Ordering::SeqCst),
        "surviving instance was not shut down gracefully"
    );
}

#[tokio::test]
async fn test_init_failure_rolls_back_initialized_instances() {
    let shutdown_called = Arc::new(AtomicBool::new(false));
    let manager = Manager::with_instances(vec![
        Instance::new(
            Box::new(PendingInbound {
                shutdown_called: shutdown_called.clone(),
            }),
            Box::new(NopOutbound),
        ),
        Instance::new(Box::new(FailInitInbound), Box::new(NopOutbound)),
    ]);

    let result = tokio::time::timeout(Duration::from_secs(30), manager.run())
        .await
        .expect("run() must return after an init failure, not hang");
    assert!(result.is_err());
    assert!(
        shutdown_called.load(Ordering::SeqCst),
        "already-initialized instance was not rolled back"
    );
}

#[tokio::test]
async fn test_empty_instances_is_rejected() {
    // Field-literal construction bypasses `with_instances`' debug_assert;
    // run() must still reject an empty manager instead of idling forever.
    let manager = Manager { instances: vec![] };
    let result = manager.run().await;
    assert!(
        matches!(result, Err(SError::Instance(_))),
        "empty manager must be rejected with SError::Instance, got {result:?}"
    );
}
