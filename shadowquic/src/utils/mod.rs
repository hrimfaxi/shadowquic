pub(crate) mod copy;
pub mod dual_socket;
pub mod platform;
pub mod socket_opt;
pub mod user_store;

#[cfg(any(feature = "router-db", feature = "restful-api"))]
pub(crate) mod http;
#[cfg(any(feature = "router-db", feature = "restful-api", feature = "dns-server"))]
pub(crate) mod proxy;
#[cfg(any(feature = "router-db", feature = "dns-server"))]
pub(crate) mod tls;

#[cfg(target_os = "android")]
pub mod protect_socket;

pub mod replay_stream;

/// Report how a spawned session ended. Losing a UDP association is ordinary
/// teardown once the exchange it served has finished, so only log it at debug:
/// a peer that answers one DNS query and closes must not look like a failure.
pub(crate) fn log_session_result(result: std::result::Result<(), crate::error::SError>) {
    match result {
        Ok(()) => {}
        Err(error) if error.is_session_end() => tracing::debug!("{}", error),
        Err(error) => tracing::error!("{}", error),
    }
}

#[cfg(test)]
mod tests {
    use crate::error::SError;

    #[test]
    fn only_udp_teardown_counts_as_a_session_end() {
        assert!(SError::UDPSessionClosed("sender dropped".into()).is_session_end());
        assert!(!SError::OutboundUnavailable.is_session_end());
        assert!(!SError::InboundUnavailable.is_session_end());
    }
}
