use super::*;
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tokio::sync::{Barrier, mpsc};

struct TestInbound {
    requests: mpsc::Receiver<ProxyRequest>,
    initialized: Arc<AtomicUsize>,
    stopped: Arc<AtomicUsize>,
    fail_init: bool,
    fail_shutdown: bool,
}

#[async_trait]
impl Inbound for TestInbound {
    async fn init(&self) -> Result<(), SError> {
        self.initialized.fetch_add(1, Ordering::SeqCst);
        if self.fail_init {
            return Err(SError::InboundUnavailable);
        }
        Ok(())
    }

    async fn accept(&mut self) -> Result<ProxyRequest, SError> {
        match self.requests.recv().await {
            Some(request) => Ok(request),
            None => std::future::pending().await,
        }
    }

    async fn shutdown(&self) -> Result<(), SError> {
        self.stopped.fetch_add(1, Ordering::SeqCst);
        if self.fail_shutdown {
            return Err(SError::InboundUnavailable);
        }
        Ok(())
    }
}

struct TestOutbound {
    called: Arc<Barrier>,
}

#[async_trait]
impl Outbound for TestOutbound {
    async fn handle(&self, _: ProxyRequest) -> Result<(), SError> {
        self.called.wait().await;
        // Shutdown must interrupt a stalled handler.
        std::future::pending().await
    }
}

fn request() -> ProxyRequest {
    let (send, recv) = mpsc::channel(1);
    ProxyRequest::Udp(UdpSession {
        dst: "127.0.0.1:53"
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into(),
        src_addr: None,
        recv: Box::new(recv),
        send: Arc::new(send),
        stream: None,
        bind_addr: "127.0.0.1:0"
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into(),
        user_context: Default::default(),
    })
}

async fn check_manager(fail_init: bool, fail_shutdown: bool) {
    let initialized = Arc::new(AtomicUsize::new(0));
    let stopped = Arc::new(AtomicUsize::new(0));
    let called = Arc::new(Barrier::new(3));
    let mut inbounds: HashMap<String, Box<dyn Inbound>> = HashMap::new();
    for i in 0..2 {
        let (send, recv) = mpsc::channel(1);
        send.send(request())
            .await
            .unwrap_or_else(|_| panic!("request channel closed"));
        inbounds.insert(
            i.to_string(),
            Box::new(TestInbound {
                requests: recv,
                initialized: initialized.clone(),
                stopped: stopped.clone(),
                fail_init,
                fail_shutdown: fail_shutdown && i == 0,
            }),
        );
    }
    let manager = Manager {
        inbounds,
        outbounds: HashMap::from([
            (
                "selected".into(),
                Arc::new(TestOutbound {
                    called: called.clone(),
                }) as Arc<dyn Outbound>,
            ),
            // Selecting this outbound would deadlock the test.
            (
                "unused".into(),
                Arc::new(TestOutbound {
                    called: Arc::new(Barrier::new(100)),
                }) as Arc<dyn Outbound>,
            ),
        ]),
        default_outbound: "selected".into(),
        #[cfg(feature = "plugin")]
        router: None,
    };
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        manager.run_until(async {
            called.wait().await;
        }),
    )
    .await
    .expect("manager stalled");
    assert_eq!(result.is_err(), fail_init || fail_shutdown);
    assert_eq!(stopped.load(Ordering::SeqCst), 2);
    if !fail_init {
        assert_eq!(initialized.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn concurrent_listeners_share_outbound_and_shutdown() {
    check_manager(false, false).await;
}

#[tokio::test]
async fn shutdown_failure_does_not_skip_other_listeners() {
    check_manager(false, true).await;
}

#[tokio::test]
async fn initialization_failure_cleans_up_listeners() {
    check_manager(true, false).await;
}

/// An inbound whose `accept` fails while `failures_left` is non-zero.
struct FlakyAccept {
    failures_left: Arc<AtomicUsize>,
    /// Every `accept` call, so a test can assert how often the manager retried.
    attempts: Arc<AtomicUsize>,
    requests: mpsc::Receiver<ProxyRequest>,
}

#[async_trait]
impl Inbound for FlakyAccept {
    async fn accept(&mut self) -> Result<ProxyRequest, SError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        if self.failures_left.load(Ordering::SeqCst) > 0 {
            self.failures_left.fetch_sub(1, Ordering::SeqCst);
            // Yield so that a manager which does not back off cannot starve the
            // test task and hang the test instead of failing it.
            tokio::task::yield_now().await;
            return Err(SError::Io(std::io::Error::other("too many open files")));
        }
        match self.requests.recv().await {
            Some(request) => Ok(request),
            None => std::future::pending().await,
        }
    }
}

struct RecordingOutbound {
    handled: mpsc::UnboundedSender<()>,
}

#[async_trait]
impl Outbound for RecordingOutbound {
    async fn handle(&self, _: ProxyRequest) -> Result<(), SError> {
        let _ = self.handled.send(());
        Ok(())
    }
}

fn flaky_manager(
    failures_left: Arc<AtomicUsize>,
    attempts: Arc<AtomicUsize>,
    requests: mpsc::Receiver<ProxyRequest>,
    handled: mpsc::UnboundedSender<()>,
) -> Manager {
    Manager::single(
        Box::new(FlakyAccept {
            failures_left,
            attempts,
            requests,
        }),
        Arc::new(RecordingOutbound { handled }),
    )
}

/// A failed `accept` must not end the instance. Before the listener lived in
/// the inbound, an accept error ended the inbound's own loop and took the port
/// with it; a manager that treats the error as fatal would lose the listener
/// the same way.
#[tokio::test]
async fn accept_errors_do_not_stop_an_instance() {
    let (send, recv) = mpsc::channel(1);
    send.send(request()).await.expect("request channel closed");
    let (handled_tx, mut handled_rx) = mpsc::unbounded_channel();
    let manager = flaky_manager(
        Arc::new(AtomicUsize::new(3)),
        Arc::new(AtomicUsize::new(0)),
        recv,
        handled_tx,
    );

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let run = tokio::spawn(async move {
        manager
            .run_until(async move {
                let _ = stop_rx.await;
            })
            .await
    });

    let handled = tokio::time::timeout(Duration::from_secs(5), handled_rx.recv()).await;
    assert_eq!(
        handled.expect("the instance stopped after a failed accept"),
        Some(())
    );

    let _ = stop_tx.send(());
    run.await
        .expect("manager task failed")
        .expect("shutdown after a served request must be clean");
}

/// A failure that is not about one connection must not be retried as fast as
/// the loop can go: a full process fd table is the case, and it has to be
/// reported once per backoff instead of flooding the log while burning a core.
/// The backoff starts at 10ms and doubles, so 200ms is a handful of attempts;
/// without it the same window holds tens of thousands.
#[tokio::test]
async fn a_persistently_failing_accept_backs_off() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let (_send, recv) = mpsc::channel(1);
    let manager = flaky_manager(
        // Far more failures than the window can reach, so it never serves.
        Arc::new(AtomicUsize::new(1000)),
        attempts.clone(),
        recv,
        mpsc::unbounded_channel().0,
    );

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let run = tokio::spawn(async move {
        manager
            .run_until(async move {
                let _ = stop_rx.await;
            })
            .await
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let n = attempts.load(Ordering::SeqCst);
    assert!(
        n <= 10,
        "expected the manager to wait between failed accepts, but it made {n} in 200ms"
    );

    let _ = stop_tx.send(());
    run.await
        .expect("manager task failed")
        .expect("shutdown after a failed accept must be clean");
}
