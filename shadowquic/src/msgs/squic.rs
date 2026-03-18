use std::sync::Arc;

use crate::config::{default_brutal_ack_compensate, default_brutal_cwnd_gain, default_brutal_up};
use crate::error::SError;

use super::socks5::SocksAddr;
use super::{SDecode, SEncode};
use shadowquic_macros::{SDecode, SEncode};

pub static SUNNY_QUIC_AUTH_LEN: usize = 64;
pub(crate) type SunnyCredential = Arc<[u8; SUNNY_QUIC_AUTH_LEN]>;

#[derive(SEncode, SDecode, Clone, Debug, PartialEq)]
pub struct BrutalNegotiation {
    pub bandwidth_hint: u64,
    pub cwnd_gain: f64,
    pub ack_compensate: bool,
}

impl BrutalNegotiation {
    pub fn new(bandwidth_hint: u64, cwnd_gain: f64, ack_compensate: bool) -> Self {
        Self {
            bandwidth_hint,
            cwnd_gain,
            ack_compensate,
        }
    }
}

impl Default for BrutalNegotiation {
    fn default() -> Self {
        Self::new(
            default_brutal_up(),
            default_brutal_cwnd_gain(),
            default_brutal_ack_compensate(),
        )
    }
}

#[derive(PartialEq)]
#[repr(u8)]
#[derive(SEncode, SDecode)]
pub enum SQReq {
    SQConnect(SocksAddr) = 0x1,
    SQBind(SocksAddr) = 0x2,
    SQAssociatOverDatagram(SocksAddr) = 0x3,
    SQAssociatOverStream(SocksAddr) = 0x4,
    SQAuthenticate(SunnyCredential) = 0x5,
    SQBrutalNegotiation(BrutalNegotiation) = 0x6,
}

#[derive(SEncode, SDecode)]
pub struct SQUdpControlHeader {
    pub dst: SocksAddr,
    pub id: u16, // id is one to one coresponance a udpsocket and proxy dst
}

#[derive(SEncode, SDecode)]
pub struct SQPacketStreamHeader {
    pub id: u16, // id is one to one coresponance a udpsocket and proxy dst
    pub len: u16,
}

#[derive(SEncode, SDecode, Clone)]
pub struct SQPacketDatagramHeader {
    pub id: u16, // id is one to one coresponance a udpsocket and proxy dst
}

#[tokio::test]
async fn test_encode_req() {
    let req = SQReq::SQAuthenticate(Arc::new([1u8; SUNNY_QUIC_AUTH_LEN]));
    let buf = vec![0u8; 1 + SUNNY_QUIC_AUTH_LEN];
    let mut cursor = std::io::Cursor::new(buf);
    req.encode(&mut cursor).await.unwrap();
    assert_eq!(cursor.into_inner()[0], 0x5);
}

#[tokio::test]
async fn test_macro_expand_req() {
    const TEST_CONST: u8 = 89;
    #[repr(u8)]
    #[derive(SDecode, SEncode, PartialEq)]
    #[allow(dead_code)]
    pub enum Cmd {
        Connect,
        Bind = 0x8,
        AssociatOverDatagram,
        AssociatOverStream = TEST_CONST,
        Authenticate,
    }
}
