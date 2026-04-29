use std::fmt::{Display, Error as FmtError, Formatter};

use bytes::Buf;
use prost::Message;
use serde_derive::{Deserialize, Serialize};

use ibc_proto::google::protobuf::Any;
use ibc_proto::Protobuf;

use crate::clients::ics08_bankd::error::Error;
use crate::core::ics02_client::client_type::ClientType;
use crate::core::ics02_client::error::Error as Ics02Error;
use crate::timestamp::Timestamp;
use crate::Height;

pub const BANKD_HEADER_TYPE_URL: &str = "/ibc.lightclients.bankd.v1.Header";

/// Prost-generated raw protobuf type for bankd Header wire format.
#[derive(Clone, PartialEq, Message)]
pub struct RawBankdHeader {
    #[prost(message, optional, tag = "1")]
    pub height: Option<ibc_proto::ibc::core::client::v1::Height>,
    #[prost(message, optional, tag = "2")]
    pub timestamp: Option<ibc_proto::google::protobuf::Timestamp>,
    #[prost(bytes = "vec", tag = "3")]
    pub new_root: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub ibc_root: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub block_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub threshold_signature: Vec<u8>,
}

/// Bankd consensus header
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Header {
    pub height: Height,
    pub timestamp: Timestamp,
    pub new_root: Vec<u8>,
    pub ibc_root: Vec<u8>,
    pub block_id: Vec<u8>,
    pub threshold_signature: Vec<u8>,
}

impl core::fmt::Debug for Header {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        write!(f, "BankdHeader {{ height: {} }}", self.height)
    }
}

impl Display for Header {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        write!(
            f,
            "Header {{ height: {}, timestamp: {} }}",
            self.height, self.timestamp
        )
    }
}

impl crate::core::ics02_client::header::Header for Header {
    fn client_type(&self) -> ClientType {
        ClientType::Bankd
    }

    fn height(&self) -> Height {
        self.height
    }

    fn timestamp(&self) -> Timestamp {
        self.timestamp
    }
}

impl Protobuf<RawBankdHeader> for Header {}

impl TryFrom<RawBankdHeader> for Header {
    type Error = Error;

    fn try_from(raw: RawBankdHeader) -> Result<Self, Self::Error> {
        let height: Height = raw
            .height
            .ok_or_else(|| Error::invalid_raw_header("missing height".into()))?
            .try_into()
            .map_err(|_| Error::invalid_raw_header("invalid height".into()))?;

        let proto_timestamp = raw
            .timestamp
            .ok_or_else(|| Error::invalid_raw_header("missing timestamp".into()))?;

        let timestamp = Timestamp::from_nanoseconds(
            (proto_timestamp.seconds as u64) * 1_000_000_000
                + (proto_timestamp.nanos as u64),
        )
        .map_err(|_| Error::invalid_raw_header("invalid timestamp".into()))?;

        Ok(Self {
            height,
            timestamp,
            new_root: raw.new_root,
            ibc_root: raw.ibc_root,
            block_id: raw.block_id,
            threshold_signature: raw.threshold_signature,
        })
    }
}

impl From<Header> for RawBankdHeader {
    fn from(value: Header) -> Self {
        let nanos = value.timestamp.nanoseconds();
        let seconds = (nanos / 1_000_000_000) as i64;
        let nanos = (nanos % 1_000_000_000) as i32;

        Self {
            height: Some(value.height.into()),
            timestamp: Some(ibc_proto::google::protobuf::Timestamp { seconds, nanos }),
            new_root: value.new_root,
            ibc_root: value.ibc_root,
            block_id: value.block_id,
            threshold_signature: value.threshold_signature,
        }
    }
}

impl Protobuf<Any> for Header {}

impl TryFrom<Any> for Header {
    type Error = Ics02Error;

    fn try_from(raw: Any) -> Result<Self, Ics02Error> {
        use core::ops::Deref;

        match raw.type_url.as_str() {
            BANKD_HEADER_TYPE_URL => decode_header(raw.value.deref()).map_err(Into::into),
            _ => Err(Ics02Error::unknown_header_type(raw.type_url)),
        }
    }
}

impl From<Header> for Any {
    fn from(header: Header) -> Self {
        Any {
            type_url: BANKD_HEADER_TYPE_URL.to_string(),
            value: Protobuf::<RawBankdHeader>::encode_vec(header),
        }
    }
}

pub fn decode_header<B: Buf>(buf: B) -> Result<Header, Error> {
    RawBankdHeader::decode(buf)
        .map_err(Error::decode)?
        .try_into()
}
