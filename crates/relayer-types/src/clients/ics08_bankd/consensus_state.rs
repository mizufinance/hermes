use prost::Message;
use serde::{Deserialize, Serialize};

use ibc_proto::google::protobuf::Any;
use ibc_proto::Protobuf;

use crate::clients::ics08_bankd::error::Error;
use crate::core::ics02_client::client_type::ClientType;
use crate::core::ics02_client::error::Error as Ics02Error;
use crate::core::ics23_commitment::commitment::CommitmentRoot;
use crate::timestamp::Timestamp;

pub const BANKD_CONSENSUS_STATE_TYPE_URL: &str = "/ibc.lightclients.bankd.v1.ConsensusState";

/// Raw protobuf type matching bankd.proto ConsensusState.
#[derive(Clone, PartialEq, Message)]
pub struct RawBankdConsensusState {
    #[prost(bytes = "vec", tag = "1")]
    pub root: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub timestamp: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub group_public_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusState {
    pub timestamp: Timestamp,
    pub root: CommitmentRoot,
    pub group_public_key: Vec<u8>,
}

impl ConsensusState {
    pub fn new(root: CommitmentRoot, timestamp: Timestamp, group_public_key: Vec<u8>) -> Self {
        Self { timestamp, root, group_public_key }
    }
}

impl crate::core::ics02_client::consensus_state::ConsensusState for ConsensusState {
    fn client_type(&self) -> ClientType {
        ClientType::Bankd
    }

    fn root(&self) -> &CommitmentRoot {
        &self.root
    }

    fn timestamp(&self) -> Timestamp {
        self.timestamp
    }
}

impl Protobuf<RawBankdConsensusState> for ConsensusState {}

impl TryFrom<RawBankdConsensusState> for ConsensusState {
    type Error = Error;

    fn try_from(raw: RawBankdConsensusState) -> Result<Self, Self::Error> {
        let timestamp = Timestamp::from_nanoseconds(raw.timestamp * 1_000_000_000)
            .map_err(|_| Error::invalid_raw_consensus_state("invalid timestamp".into()))?;

        Ok(Self {
            root: raw.root.into(),
            timestamp,
            group_public_key: raw.group_public_key,
        })
    }
}

impl From<ConsensusState> for RawBankdConsensusState {
    fn from(value: ConsensusState) -> Self {
        let timestamp_secs = value.timestamp.nanoseconds() / 1_000_000_000;

        Self {
            root: value.root.into_vec(),
            timestamp: timestamp_secs,
            group_public_key: value.group_public_key,
        }
    }
}

impl Protobuf<Any> for ConsensusState {}

impl TryFrom<Any> for ConsensusState {
    type Error = Ics02Error;

    fn try_from(raw: Any) -> Result<Self, Self::Error> {
        use bytes::Buf;
        use core::ops::Deref;

        fn decode_consensus_state<B: Buf>(buf: B) -> Result<ConsensusState, Error> {
            RawBankdConsensusState::decode(buf)
                .map_err(Error::decode)?
                .try_into()
        }

        match raw.type_url.as_str() {
            BANKD_CONSENSUS_STATE_TYPE_URL => {
                decode_consensus_state(raw.value.deref()).map_err(Into::into)
            }
            _ => Err(Ics02Error::unknown_consensus_state_type(raw.type_url)),
        }
    }
}

impl From<ConsensusState> for Any {
    fn from(consensus_state: ConsensusState) -> Self {
        Any {
            type_url: BANKD_CONSENSUS_STATE_TYPE_URL.to_string(),
            value: Protobuf::<RawBankdConsensusState>::encode_vec(consensus_state),
        }
    }
}
