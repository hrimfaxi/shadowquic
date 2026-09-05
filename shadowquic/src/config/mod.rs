use crate::{Instance, SDecode, SEncode};
use serde::de::Error as _;
use serde::{Deserialize, Serialize};
use shadowquic_macros::{SDecode, SEncode};
use std::net::{IpAddr, SocketAddr};
use tracing::{Level, warn};

#[cfg(feature = "mixed")]
use crate::mixed::inbound::MixedServer;
use crate::{
    Inbound, Manager, Outbound,
    direct::outbound::DirectOut,
    error::SError,
    shadowquic::{inbound::ShadowQuicServer, outbound::ShadowQuicClient},
    socks::{inbound::SocksServer, outbound::SocksClient},
    sunnyquic::{inbound::SunnyQuicServer, outbound::SunnyQuicClient},
};

mod serde_utils;
#[cfg(all(feature = "tproxy", target_os = "linux"))]
use crate::tproxy::inbound::TproxyServer;

mod shadowquic;
mod sunnyquic;
pub use crate::config::serde_utils::*;
pub use crate::config::shadowquic::*;
pub use crate::config::sunnyquic::*;

/// Overall configuration of shadowquic.
///
/// Two formats are supported.
///
/// Single instance (legacy):
/// ```yaml
/// inbound:
///   type: xxx
///   xxx: xxx
/// outbound:
///   type: xxx
///   xxx: xxx
/// log-level: trace # or debug, info, warn, error
/// ```
///
/// Multiple instances running concurrently in one process:
/// ```yaml
/// instances:
///   - inbound:
///       type: mixed
///       bind-addr: "0.0.0.0:20808"
///     outbound:
///       type: shadowquic
///       addr: "server1.example.com:1443"
///       username: "my_name"
///       password: "my_password"
///       server-name: "cloudflare.com"
///   - inbound:
///       type: mixed
///       bind-addr: "0.0.0.0:20809"
///     outbound:
///       type: shadowquic
///       addr: "server2.example.com:1444"
///       username: "my_name"
///       password: "my_password"
///       server-name: "cloudflare.com"
/// log-level: info
/// ```
/// The two formats cannot be mixed: a config must use either `instances` or
/// the legacy top-level `inbound`/`outbound` pair.
///
/// Supported inbound types are listed in [`InboundCfg`]
///
/// Supported outbound types are listed in [`OutboundCfg`]
#[derive(Clone, Debug)]
pub struct Config {
    pub instances: Vec<InstanceCfg>,
    pub log_level: LogLevel,
}

/// Internal raw config shape accepting both formats.
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawConfig {
    inbound: Option<InboundCfg>,
    outbound: Option<OutboundCfg>,
    instances: Option<Vec<InstanceCfg>>,
    #[serde(default)]
    log_level: LogLevel,
}

impl<'de> Deserialize<'de> for Config {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawConfig::deserialize(deserializer)?;
        Config::from_raw(raw).map_err(D::Error::custom)
    }
}

impl Config {
    fn from_raw(raw: RawConfig) -> Result<Self, String> {
        let RawConfig {
            inbound,
            outbound,
            instances,
            log_level,
        } = raw;
        match (inbound, outbound, instances) {
            (Some(inbound), Some(outbound), None) => Ok(Config {
                instances: vec![InstanceCfg { inbound, outbound }],
                log_level,
            }),
            (None, None, Some(instances)) if !instances.is_empty() => Ok(Config {
                instances,
                log_level,
            }),
            (None, None, Some(_)) => Err("`instances` must not be empty".into()),
            (Some(_), Some(_), Some(_)) | (Some(_), None, Some(_)) | (None, Some(_), Some(_)) => {
                Err("cannot mix `instances` with legacy `inbound`/`outbound` in one config".into())
            }
            (Some(_), None, None) => Err(
                "`outbound` is missing: legacy config requires both `inbound` and `outbound`"
                    .into(),
            ),
            (None, Some(_), None) => Err(
                "`inbound` is missing: legacy config requires both `inbound` and `outbound`".into(),
            ),
            (None, None, None) => {
                Err("config must define either `instances` or both `inbound` and `outbound`".into())
            }
        }
    }

    pub async fn build_manager(self) -> Result<Manager, SError> {
        let mut instances = Vec::with_capacity(self.instances.len());
        for cfg in self.instances {
            instances.push(Instance::new(
                cfg.inbound.build_inbound().await?,
                cfg.outbound.build_outbound().await?,
            ));
        }
        Ok(Manager::with_instances(instances))
    }
}

/// Configuration of a single proxy instance: an [`InboundCfg`] paired with an [`OutboundCfg`].
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct InstanceCfg {
    pub inbound: InboundCfg,
    pub outbound: OutboundCfg,
}

/// Inbound configuration
/// example:
/// ```yaml
/// type: socks # or shadowquic
/// bind-addr: "0.0.0.0:443" # "[::]:443"
/// xxx: xxx # other field depending on type
/// ```
/// See [`SocksServerCfg`] and [`ShadowQuicServerCfg`] for configuration field of corresponding type
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
#[serde(tag = "type")]
pub enum InboundCfg {
    Socks(SocksServerCfg),
    #[cfg(feature = "mixed")]
    Mixed(MixedServerCfg),
    #[serde(rename = "shadowquic")]
    ShadowQuic(ShadowQuicServerCfg),
    #[serde(rename = "sunnyquic")]
    SunnyQuic(SunnyQuicServerCfg),
    #[cfg(all(feature = "tproxy", target_os = "linux"))]
    #[serde(rename = "tproxy")]
    Tproxy(TproxyServerCfg),
}
impl InboundCfg {
    /// Name of the inbound type, e.g. `"mixed"`, `"shadowquic"`
    pub fn type_name(&self) -> &'static str {
        match self {
            InboundCfg::Socks(_) => "socks",
            #[cfg(feature = "mixed")]
            InboundCfg::Mixed(_) => "mixed",
            InboundCfg::ShadowQuic(_) => "shadowquic",
            InboundCfg::SunnyQuic(_) => "sunnyquic",
            #[cfg(all(feature = "tproxy", target_os = "linux"))]
            InboundCfg::Tproxy(_) => "tproxy",
        }
    }

    async fn build_inbound(self) -> Result<Box<dyn Inbound>, SError> {
        let r: Box<dyn Inbound> = match self {
            InboundCfg::Socks(cfg) => Box::new(SocksServer::new(cfg).await?),
            #[cfg(feature = "mixed")]
            InboundCfg::Mixed(cfg) => Box::new(MixedServer::new(cfg).await?),
            InboundCfg::ShadowQuic(cfg) => Box::new(ShadowQuicServer::new(cfg).await?),
            InboundCfg::SunnyQuic(cfg) => Box::new(SunnyQuicServer::new(cfg).await?),
            #[cfg(all(feature = "tproxy", target_os = "linux"))]
            InboundCfg::Tproxy(cfg) => Box::new(TproxyServer::new(cfg).await?),
        };
        Ok(r)
    }
}

/// Outbound configuration
/// example:
/// ```yaml
/// type: socks # or shadowquic or direct
/// addr: "127.0.0.1:443" # "[::1]:443"
/// xxx: xxx # other field depending on type
/// ```
/// See [`SocksClientCfg`] and [`ShadowQuicClientCfg`] for configuration field of corresponding type
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
#[serde(tag = "type")]
pub enum OutboundCfg {
    Socks(SocksClientCfg),
    #[serde(rename = "shadowquic")]
    ShadowQuic(ShadowQuicClientCfg),
    #[serde(rename = "sunnyquic")]
    SunnyQuic(SunnyQuicClientCfg),
    Direct(DirectOutCfg),
}

impl OutboundCfg {
    /// Name of the outbound type, e.g. `"direct"`, `"shadowquic"`
    pub fn type_name(&self) -> &'static str {
        match self {
            OutboundCfg::Socks(_) => "socks",
            OutboundCfg::ShadowQuic(_) => "shadowquic",
            OutboundCfg::SunnyQuic(_) => "sunnyquic",
            OutboundCfg::Direct(_) => "direct",
        }
    }

    async fn build_outbound(self) -> Result<Box<dyn Outbound>, SError> {
        let r: Box<dyn Outbound> = match self {
            OutboundCfg::Socks(cfg) => Box::new(SocksClient::new(cfg)),
            OutboundCfg::ShadowQuic(cfg) => Box::new(ShadowQuicClient::new(cfg)),
            OutboundCfg::SunnyQuic(cfg) => Box::new(SunnyQuicClient::new(cfg)),
            OutboundCfg::Direct(cfg) => Box::new(DirectOut::new(cfg)),
        };
        Ok(r)
    }
}

/// Socks inbound configuration
///
/// Example:
/// ```yaml
/// bind-addr: "0.0.0.0:1089" # or "[::]:1089" for dualstack
/// users:
///  - username: "username"
///    password: "password"
/// ```
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct SocksServerCfg {
    /// Server binding address. e.g. `0.0.0.0:1089`, `[::1]:1089`
    pub bind_addr: SocketAddr,
    /// Socks5 username, optional
    /// Left empty to disable authentication
    #[serde(default = "Vec::new")]
    pub users: Vec<AuthUser>,
}

/// Mixed inbound configuration
///
/// Supports SOCKS5 and HTTP proxy (CONNECT + plain HTTP forwarding) on the same port.
///
/// Example:
/// ```yaml
/// type: mixed
/// bind-addr: "0.0.0.0:1080"
/// ```
#[cfg(feature = "mixed")]
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct MixedServerCfg {
    /// Server binding address. e.g. `0.0.0.0:1080`, `[::]:1080`
    pub bind_addr: SocketAddr,
    /// Socks5 username, optional
    /// Left empty to disable authentication
    #[serde(default = "Vec::new")]
    pub users: Vec<AuthUser>,
}

/// Tproxy inbound configuration
///
/// Example:
/// ```yaml
/// bind-addr: "0.0.0.0:1089" # or "[::]:1089" for dualstack
/// ```
#[cfg(all(feature = "tproxy", target_os = "linux"))]
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct TproxyServerCfg {
    /// Server binding address. e.g. `0.0.0.0:1089`, `[::1]:1089`
    pub bind_addr: SocketAddr,
}

/// user authentication
#[derive(Deserialize, Clone, Debug, PartialEq, Eq, SEncode, SDecode)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AuthUser {
    pub username: String,
    pub password: String,
}

/// Socks outbound configuration
/// Example:
/// ```yaml
/// addr: "12.34.56.7:1089" # or "[12:ff::ff]:1089" for dualstack
/// ```
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct SocksClientCfg {
    pub addr: String,
    /// SOCKS5 username, optional
    pub username: Option<String>,
    /// SOCKS5 password, optional
    pub password: Option<String>,
    /// Socket options like bind interface and fwmark
    #[serde(flatten)]
    pub socket_opt: SocketOpt,
}

/// Socket options
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct SocketOpt {
    /// fw_mark on linux
    pub fw_mark: Option<u32>,
    /// binding interface of this outgoing packet.
    ///
    /// If `bind_interface` is set, the outgoing packet will be sent from the
    /// specified interface. Recommend to use to cooporate with other tun based proxy like sing-box/mihomo
    ///
    /// Example:
    /// ```yaml
    /// # by ip address
    /// bind-interface: "127.0.0.1"
    /// # by interface name
    /// bind-interface: "eth0"
    /// ```
    pub bind_interface: Option<Interface>,
}

/// binding interface of this outgoing packet.
///
/// If `bind_interface` is set, the outgoing packet will be sent from the
/// specified interface. Recommend to use to cooporate with other tun based proxy like sing-box/mihomo
///
/// Example:
/// ```yaml
/// # by ip address
/// bind-interface: "127.0.0.1"
/// # by interface name
/// bind-interface: "eth0"
/// ```
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum Interface {
    Address(IpAddr),
    Device(String),
}

pub fn default_initial_mtu() -> u16 {
    1300
}
pub fn default_min_mtu() -> u16 {
    1290
}
pub fn default_zero_rtt() -> bool {
    true
}
pub fn default_congestion_control() -> CongestionControl {
    CongestionControl::Bbr
}
pub fn default_over_stream() -> bool {
    false
}
pub fn default_alpn() -> Vec<String> {
    vec!["h3".into()]
}
pub fn default_keep_alive_interval() -> u32 {
    0
}

/// Default user-store flush interval in seconds
pub fn default_store_flush_interval() -> u64 {
    60
}

pub fn default_gso() -> bool {
    true
}

pub fn default_mtu_discovery() -> bool {
    true
}

pub fn default_blackhole_detection() -> bool {
    false
}

pub fn default_brutal_bandwidth() -> u64 {
    10_000_000
}

pub fn default_brutal_cwnd_gain() -> f64 {
    1.10
}

pub fn default_brutal_min_window() -> u64 {
    16 * 1024
}

pub fn default_brutal_min_ack_rate() -> f64 {
    0.8
}

pub fn default_brutal_min_sample_count() -> u64 {
    50
}

pub fn default_brutal_ack_compensate() -> bool {
    false
}

/// Congestion control algorithm
/// Example:
/// ```yaml
/// congestion-control: bbr # or cubic, new-reno, brutal
/// ```
/// If `brutal` is used, the configuration is like:
/// ```yaml
/// congestion-control:
///   brutal:
///     bandwidth: 10000000 # default 10000000 bps
/// ```
/// For Brutal, the bandwidth is the uploading bandwidth.
/// If you want to
/// set the downloading bandwidth,  set the bandwidth of the peer(e.g. it's the server for the client)
#[derive(Serialize, Deserialize, Default, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub enum CongestionControl {
    #[default]
    Bbr,
    Cubic,
    NewReno,
    Brutal(BrutalParams),
    Bbr3,
}

impl PartialEq for CongestionControl {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (CongestionControl::Bbr, CongestionControl::Bbr)
                | (CongestionControl::Cubic, CongestionControl::Cubic)
                | (CongestionControl::NewReno, CongestionControl::NewReno)
                | (CongestionControl::Brutal(_), CongestionControl::Brutal(_))
        )
    }
}

/// Configuration of direct outbound
/// Example:
/// ```yaml
/// dns-strategy: prefer-ipv4 # or prefer-ipv6, ipv4-only, ipv6-only
/// ```
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DirectOutCfg {
    #[serde(default)]
    pub dns_strategy: DnsStrategy,
}
/// DNS resolution strategy
/// Default is `prefer-ipv4`
///
/// - `prefer-ipv4`: try to use ipv4 first, if no ipv4 address, use ipv6
/// - `prefer-ipv6`: try to use ipv6 first, if no ipv6 address, use ipv4
/// - `ipv4-only`: only use ipv4 address
/// - `ipv6-only`: only use ipv6 address
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub enum DnsStrategy {
    /// try to use ipv4 first, if no ipv4 address, use ipv6
    #[default]
    PreferIpv4,
    /// try to use ipv6 first, if no ipv6 address, use ipv4
    PreferIpv6,
    /// only use ipv4 address
    Ipv4Only,
    /// only use ipv6 address  
    Ipv6Only,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CipherSuitePreference {
    Aes128Gcm,
    Chacha20Poly1305,
    Aes256Gcm,
}

pub trait HasCipherSuitePreference {
    fn has_cipher_suite_preference(&self) -> bool;
}

pub fn maybe_warn_cipher_suite_on_weak_arch<T: HasCipherSuitePreference>(_cfg: &T) {
    #[cfg(any(target_arch = "mips", target_arch = "mips64"))]
    {
        if !_cfg.has_cipher_suite_preference() {
            warn!(
                "No `cipher-suite-preference` configured on MIPS target. \
                 AES-128-GCM may be significantly slower than ChaCha20-Poly1305 on weak MIPS devices. \
                 Consider setting `cipher-suite-preference: [\"chacha20-poly1305\", \"aes128-gcm\", \"aes256-gcm\"]`."
            );
        }
    }
}

pub fn normalize_cipher_suite_preference(
    cipher_suite_preference: &[CipherSuitePreference],
) -> Vec<CipherSuitePreference> {
    let mut out = Vec::new();

    for suite in cipher_suite_preference {
        if !out.contains(suite) {
            out.push(suite.clone());
        }
    }

    if !out.contains(&CipherSuitePreference::Aes128Gcm) {
        warn!(
            "`cipher-suite-preference` does not include `aes128-gcm`; appending it automatically"
        );
        out.push(CipherSuitePreference::Aes128Gcm);
    }

    out
}

/// Log level of shadowquic
/// Default level is info.
#[derive(Deserialize, Clone, Default, Debug)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}
impl LogLevel {
    pub fn as_tracing_level(&self) -> Level {
        match self {
            LogLevel::Trace => Level::TRACE,
            LogLevel::Debug => Level::DEBUG,
            LogLevel::Info => Level::INFO,
            LogLevel::Warn => Level::WARN,
            LogLevel::Error => Level::ERROR,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::config::{CongestionControl, Interface, ShadowQuicClientCfg};

    use super::Config;
    use super::{CipherSuitePreference, normalize_cipher_suite_preference};
    #[test]
    fn test() {
        let cfgstr = r###"
inbound:
    type: socks
    bind-addr: 127.0.0.1:1089
outbound:
    type: direct
    dns-strategy: prefer-ipv4
"###;
        let _cfg: Config = serde_saphyr::from_str(cfgstr).expect("yaml parsed failed");
    }
    #[test]
    fn test_fail() {
        let cfgstr = r###"
inbound:
    type: socks
    bind-addr: 127.0.0.1:1089
    dhjsj: jkj
outbound:
    type: direct
    dns-strategy: prefer-ipv4
"###;
        let cfg: Result<Config, _> = serde_saphyr::from_str(cfgstr);
        assert!(cfg.is_err());
    }
    #[test]
    fn test_legacy_single_instance() {
        let cfgstr = r###"
inbound:
    type: mixed
    bind-addr: "0.0.0.0:20808"
outbound:
    type: shadowquic
    addr: "server.example.com:1443"
    username: "test"
    password: "test"
    server-name: "cloudflare.com"
log-level: info
"###;
        let cfg: Config = serde_saphyr::from_str(cfgstr).expect("yaml parsed failed");
        assert_eq!(cfg.instances.len(), 1);
        assert_eq!(cfg.instances[0].inbound.type_name(), "mixed");
    }
    #[test]
    fn test_multi_instances() {
        let cfgstr = r###"
instances:
    - inbound:
          type: mixed
          bind-addr: "0.0.0.0:20808"
      outbound:
          type: shadowquic
          addr: "server.example.com:1443"
          username: "test"
          password: "test"
          server-name: "cloudflare.com"
    - inbound:
          type: mixed
          bind-addr: "0.0.0.0:20809"
      outbound:
          type: shadowquic
          addr: "server.example.com:1444"
          username: "test"
          password: "test"
          server-name: "cloudflare.com"
          congestion-control:
              brutal:
                  bandwidth: 10000000
log-level: info
"###;
        let cfg: Config = serde_saphyr::from_str(cfgstr).expect("yaml parsed failed");
        assert_eq!(cfg.instances.len(), 2);
        assert_eq!(cfg.instances[1].inbound.type_name(), "mixed");
        assert_eq!(cfg.instances[1].outbound.type_name(), "shadowquic");
    }
    #[test]
    fn test_reject_mixed_formats() {
        let cfgstr = r###"
instances:
    - inbound:
          type: socks
          bind-addr: 127.0.0.1:1089
      outbound:
          type: direct
inbound:
    type: socks
    bind-addr: 127.0.0.1:1089
outbound:
    type: direct
"###;
        let cfg: Result<Config, _> = serde_saphyr::from_str(cfgstr);
        assert!(cfg.is_err());
    }
    #[test]
    fn test_reject_empty_instances() {
        let cfgstr = r###"
instances: []
"###;
        let cfg: Result<Config, _> = serde_saphyr::from_str(cfgstr);
        assert!(cfg.is_err());
    }
    #[test]
    fn test_reject_legacy_missing_outbound() {
        let cfgstr = r###"
inbound:
    type: socks
    bind-addr: 127.0.0.1:1089
"###;
        let cfg: Result<Config, _> = serde_saphyr::from_str(cfgstr);
        assert!(cfg.is_err());
    }
    #[test]
    fn test_cc() {
        let cfgstr = r###"
        username: "test"
        password: "test"
        addr: "127.0.0.1:1080"
        server-name: "localhost"
        congestion-control: 
            brutal:
                bandwidth: 1000

"###;
        let cfg: Result<ShadowQuicClientCfg, _> = serde_saphyr::from_str(cfgstr);
        match cfg.unwrap().congestion_control {
            CongestionControl::Brutal(params) => {
                assert_eq!(params.bandwidth, 1000);
            }
            _ => panic!("expected brutal congestion control"),
        }
    }

    #[test]
    fn test_socketopt() {
        let cfgstr = r###"
        username: "test"
        password: "test"
        addr: "127.0.0.1:1080"
        server-name: "localhost"
        bind-interface: "eth0"

"###;
        let cfg: Result<ShadowQuicClientCfg, _> = serde_saphyr::from_str(cfgstr);

        assert_eq!(
            cfg.unwrap().socket_opt.bind_interface.unwrap(),
            Interface::Device("eth0".to_string())
        );
    }
    #[test]
    fn normalize_cipher_suite_preference_preserves_first_seen_order_and_removes_duplicates() {
        let input = vec![
            CipherSuitePreference::Chacha20Poly1305,
            CipherSuitePreference::Aes256Gcm,
            CipherSuitePreference::Chacha20Poly1305,
            CipherSuitePreference::Aes128Gcm,
            CipherSuitePreference::Aes256Gcm,
        ];
        let normalized = normalize_cipher_suite_preference(&input);
        assert_eq!(
            normalized,
            vec![
                CipherSuitePreference::Chacha20Poly1305,
                CipherSuitePreference::Aes256Gcm,
                CipherSuitePreference::Aes128Gcm,
            ]
        );
    }
    #[test]
    fn normalize_cipher_suite_preference_appends_aes128_gcm_when_absent() {
        let input = vec![
            CipherSuitePreference::Aes256Gcm,
            CipherSuitePreference::Chacha20Poly1305,
            CipherSuitePreference::Aes256Gcm,
        ];
        let normalized = normalize_cipher_suite_preference(&input);
        assert_eq!(
            normalized,
            vec![
                CipherSuitePreference::Aes256Gcm,
                CipherSuitePreference::Chacha20Poly1305,
                CipherSuitePreference::Aes128Gcm,
            ]
        );
    }
}
