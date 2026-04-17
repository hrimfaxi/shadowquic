use serde::{Deserialize, Serialize};

use std::time::Duration;

/// Minimum port hop interval in seconds
pub const MIN_PORT_HOP_INTERVAL: u64 = 5;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PortHopCfg {
    /// port hopping interval in seconds (maximum)
    /// actual interval is random between 5 seconds and this value
    pub interval: u64,

    /// server port range for port hopping
    /// example: "50000-60000"
    pub range: PortRange,
}

#[derive(Debug, Clone)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

/// Parse port range string like "50000-60000" into (start, end)
pub fn parse_port_range(range_str: &str) -> Option<(u16, u16)> {
    let parts: Vec<&str> = range_str.split('-').collect();
    if parts.len() != 2 {
        return None;
    }
    let start: u16 = parts[0].trim().parse().ok()?;
    let end: u16 = parts[1].trim().parse().ok()?;

    if start == 0 || end == 0 {
        return None;
    }

    Some(if start <= end {
        (start, end)
    } else {
        (end, start)
    })
}

impl<'de> Deserialize<'de> for PortRange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let (start, end) = parse_port_range(&s)
            .ok_or_else(|| serde::de::Error::custom("invalid port-hop range"))?;
        Ok(Self { start, end })
    }
}

impl Serialize for PortRange {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{}-{}", self.start, self.end))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::{
        IntoDeserializer,
        value::{Error as DeError, StrDeserializer},
    };

    #[test]
    fn test_parse_port_range_valid_and_normalized() {
        assert_eq!(parse_port_range("50000-60000"), Some((50000, 60000)));
        assert_eq!(parse_port_range("60000-50000"), Some((50000, 60000)));
        assert_eq!(parse_port_range(" 50000 - 60000 "), Some((50000, 60000)));
    }

    #[test]
    fn test_parse_port_range_reject_zero() {
        assert_eq!(parse_port_range("0-60000"), None);
        assert_eq!(parse_port_range("50000-0"), None);
    }

    #[test]
    fn test_port_range_deserialize_and_normalize() {
        let de: StrDeserializer<'_, DeError> = "60000-50000".into_deserializer();
        let range = PortRange::deserialize(de).unwrap();
        assert_eq!(range.start, 50000);
        assert_eq!(range.end, 60000);
    }

    #[test]
    fn test_port_range_deserialize_invalid_string() {
        let de: StrDeserializer<'_, DeError> = "invalid".into_deserializer();
        assert!(PortRange::deserialize(de).is_err());

        let de: StrDeserializer<'_, DeError> = "0-60000".into_deserializer();
        assert!(PortRange::deserialize(de).is_err());
    }
}

/// How long an old path is kept alive after a hop.
pub const PORT_HOP_DRAIN_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum number of old paths kept in draining state.
pub const MAX_DRAINING_PATHS: usize = 16;
