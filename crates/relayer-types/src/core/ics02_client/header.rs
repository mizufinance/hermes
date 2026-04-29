use core::fmt::Debug;

use serde::{Deserialize, Serialize};

use ibc_proto::google::protobuf::Any;
use ibc_proto::Protobuf;

use crate::clients::ics07_tendermint::header::{
    decode_header as tm_decode_header, Header as TendermintHeader, TENDERMINT_HEADER_TYPE_URL,
};
use crate::clients::ics08_bankd::header::{
    decode_header as bankd_decode_header, Header as BankdHeader, RawBankdHeader,
    BANKD_HEADER_TYPE_URL,
};
use crate::core::ics02_client::client_type::ClientType;
use crate::core::ics02_client::error::Error;
use crate::timestamp::Timestamp;
use crate::Height;

/// Abstract of consensus state update information
pub trait Header: Debug + Send + Sync // Any: From<Self>,
{
    /// The type of client (eg. Tendermint)
    fn client_type(&self) -> ClientType;

    /// The height of the consensus state
    fn height(&self) -> Height;

    /// The timestamp of the consensus state
    fn timestamp(&self) -> Timestamp;
}

/// Decodes an encoded header into a known `Header` type.
pub fn decode_header(header_bytes: &[u8]) -> Result<AnyHeader, Error> {
    // Try decoding into all known types, return an error only if none work.
    if let Ok(header) =
        Protobuf::<Any>::decode(header_bytes).map(|h: TendermintHeader| AnyHeader::Tendermint(h))
    {
        return Ok(header);
    }

    if let Ok(header) =
        Protobuf::<Any>::decode(header_bytes).map(|h: BankdHeader| AnyHeader::Bankd(h))
    {
        return Ok(header);
    }

    let header: TendermintHeader =
        Protobuf::<Any>::decode(header_bytes).map_err(Error::invalid_raw_header)?;

    Ok(AnyHeader::Tendermint(header))
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum AnyHeader {
    Tendermint(TendermintHeader),
    Bankd(BankdHeader),
}

impl Header for AnyHeader {
    fn client_type(&self) -> ClientType {
        match self {
            Self::Tendermint(header) => header.client_type(),
            Self::Bankd(header) => header.client_type(),
        }
    }

    fn height(&self) -> Height {
        match self {
            Self::Tendermint(header) => header.height(),
            Self::Bankd(header) => header.height(),
        }
    }

    fn timestamp(&self) -> Timestamp {
        match self {
            Self::Tendermint(header) => header.timestamp(),
            Self::Bankd(header) => header.timestamp(),
        }
    }
}

impl Protobuf<Any> for AnyHeader {}

impl TryFrom<Any> for AnyHeader {
    type Error = Error;

    fn try_from(raw: Any) -> Result<Self, Error> {
        match raw.type_url.as_str() {
            TENDERMINT_HEADER_TYPE_URL => {
                let val = tm_decode_header(raw.value.as_slice())?;
                Ok(AnyHeader::Tendermint(val))
            }

            BANKD_HEADER_TYPE_URL => {
                let val = bankd_decode_header(raw.value.as_slice())?;
                Ok(AnyHeader::Bankd(val))
            }

            _ => Err(Error::unknown_header_type(raw.type_url)),
        }
    }
}

impl From<AnyHeader> for Any {
    fn from(value: AnyHeader) -> Self {
        use ibc_proto::ibc::lightclients::tendermint::v1::Header as RawHeader;

        match value {
            AnyHeader::Tendermint(header) => Any {
                type_url: TENDERMINT_HEADER_TYPE_URL.to_string(),
                value: Protobuf::<RawHeader>::encode_vec(header),
            },
            AnyHeader::Bankd(header) => Any {
                type_url: BANKD_HEADER_TYPE_URL.to_string(),
                value: Protobuf::<RawBankdHeader>::encode_vec(header),
            },
        }
    }
}

impl From<TendermintHeader> for AnyHeader {
    fn from(header: TendermintHeader) -> Self {
        Self::Tendermint(header)
    }
}

impl From<BankdHeader> for AnyHeader {
    fn from(header: BankdHeader) -> Self {
        Self::Bankd(header)
    }
}
