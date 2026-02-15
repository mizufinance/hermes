use std::time::Duration;

use prost::Message;
use serde::{Deserialize, Serialize};

use ibc_proto::google::protobuf::Any;
use ibc_proto::Protobuf;

use crate::clients::ics08_bankd::error::Error;
use crate::core::ics02_client::client_state::ClientState as Ics2ClientState;
use crate::core::ics02_client::client_type::ClientType;
use crate::core::ics02_client::error::Error as Ics02Error;
use crate::core::ics24_host::identifier::ChainId;
use crate::Height;

pub const BANKD_CLIENT_STATE_TYPE_URL: &str = "/ibc.lightclients.bankd.v1.ClientState";

/// Raw protobuf type matching bankd.proto ClientState.
#[derive(Clone, PartialEq, Message)]
pub struct RawBankdClientState {
    #[prost(string, tag = "1")]
    pub chain_id: String,
    #[prost(message, optional, tag = "2")]
    pub latest_height: Option<ibc_proto::ibc::core::client::v1::Height>,
    #[prost(message, optional, tag = "3")]
    pub frozen_height: Option<ibc_proto::ibc::core::client::v1::Height>,
    // tag 4 = repeated ProofSpec proof_specs (omitted — unused by relayer)
    #[prost(bytes = "vec", tag = "5")]
    pub group_public_key: Vec<u8>,
    #[prost(uint64, tag = "6")]
    pub trusting_period_secs: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClientState {
    pub chain_id: ChainId,
    pub latest_height: Height,
    pub frozen_height: Option<Height>,
    pub group_public_key: Vec<u8>,
    pub trusting_period: Duration,
}

impl ClientState {
    pub fn new(
        chain_id: ChainId,
        latest_height: Height,
        group_public_key: Vec<u8>,
        trusting_period: Duration,
    ) -> Self {
        Self {
            chain_id,
            latest_height,
            frozen_height: None,
            group_public_key,
            trusting_period,
        }
    }

    pub fn latest_height(&self) -> Height {
        self.latest_height
    }

    pub fn with_frozen_height(self, h: Height) -> Self {
        Self {
            frozen_height: Some(h),
            ..self
        }
    }

    pub fn verify_height(&self, height: Height) -> Result<(), Error> {
        if self.latest_height < height {
            return Err(Error::insufficient_height(self.latest_height, height));
        }

        match self.frozen_height {
            Some(frozen_height) if frozen_height <= height => {
                Err(Error::client_frozen(frozen_height, height))
            }
            _ => Ok(()),
        }
    }
}

impl Ics2ClientState for ClientState {
    fn chain_id(&self) -> ChainId {
        self.chain_id.clone()
    }

    fn client_type(&self) -> ClientType {
        ClientType::Bankd
    }

    fn latest_height(&self) -> Height {
        self.latest_height
    }

    fn frozen_height(&self) -> Option<Height> {
        self.frozen_height
    }

    fn expired(&self, elapsed: Duration) -> bool {
        elapsed > self.trusting_period
    }
}

impl Protobuf<RawBankdClientState> for ClientState {}

impl TryFrom<RawBankdClientState> for ClientState {
    type Error = Error;

    fn try_from(raw: RawBankdClientState) -> Result<Self, Self::Error> {
        let frozen_height = raw
            .frozen_height
            .and_then(|raw_height| raw_height.try_into().ok());

        #[allow(deprecated)]
        Ok(Self {
            chain_id: ChainId::from_string(&raw.chain_id),
            latest_height: raw
                .latest_height
                .ok_or_else(Error::missing_latest_height)?
                .try_into()
                .map_err(|_| Error::missing_latest_height())?,
            frozen_height,
            group_public_key: raw.group_public_key,
            trusting_period: Duration::from_secs(raw.trusting_period_secs),
        })
    }
}

impl From<ClientState> for RawBankdClientState {
    fn from(value: ClientState) -> Self {
        Self {
            chain_id: value.chain_id.to_string(),
            latest_height: Some(value.latest_height.into()),
            frozen_height: value
                .frozen_height
                .map(|h| h.into())
                .or(Some(ibc_proto::ibc::core::client::v1::Height {
                    revision_number: 0,
                    revision_height: 0,
                })),
            group_public_key: value.group_public_key,
            trusting_period_secs: value.trusting_period.as_secs(),
        }
    }
}

impl Protobuf<Any> for ClientState {}

impl TryFrom<Any> for ClientState {
    type Error = Ics02Error;

    fn try_from(raw: Any) -> Result<Self, Self::Error> {
        use bytes::Buf;
        use core::ops::Deref;

        fn decode_client_state<B: Buf>(buf: B) -> Result<ClientState, Error> {
            RawBankdClientState::decode(buf)
                .map_err(Error::decode)?
                .try_into()
        }

        match raw.type_url.as_str() {
            BANKD_CLIENT_STATE_TYPE_URL => {
                decode_client_state(raw.value.deref()).map_err(Into::into)
            }
            _ => Err(Ics02Error::unexpected_client_state_type(
                BANKD_CLIENT_STATE_TYPE_URL.to_string(),
                raw.type_url,
            )),
        }
    }
}

impl From<ClientState> for Any {
    fn from(client_state: ClientState) -> Self {
        Any {
            type_url: BANKD_CLIENT_STATE_TYPE_URL.to_string(),
            value: Protobuf::<RawBankdClientState>::encode_vec(client_state),
        }
    }
}
