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

/// Prost-generated raw protobuf type for bankd ConsensusState wire format.
#[derive(Clone, PartialEq, Message)]
pub struct RawBankdConsensusState {
    #[prost(message, optional, tag = "1")]
    pub timestamp: Option<ibc_proto::google::protobuf::Timestamp>,
    #[prost(bytes = "vec", tag = "2")]
    pub root: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusState {
    pub timestamp: Timestamp,
    pub root: CommitmentRoot,
}

impl ConsensusState {
    pub fn new(root: CommitmentRoot, timestamp: Timestamp) -> Self {
        Self { timestamp, root }
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
        let proto_timestamp = raw
            .timestamp
            .ok_or_else(Error::missing_timestamp)?;

        let timestamp = Timestamp::from_nanoseconds(
            (proto_timestamp.seconds as u64) * 1_000_000_000
                + (proto_timestamp.nanos as u64),
        )
        .map_err(|_| Error::invalid_raw_consensus_state("invalid timestamp".into()))?;

        Ok(Self {
            root: raw.root.into(),
            timestamp,
        })
    }
}

impl From<ConsensusState> for RawBankdConsensusState {
    fn from(value: ConsensusState) -> Self {
        let nanos = value.timestamp.nanoseconds();
        let seconds = (nanos / 1_000_000_000) as i64;
        let nanos = (nanos % 1_000_000_000) as i32;

        Self {
            timestamp: Some(ibc_proto::google::protobuf::Timestamp { seconds, nanos }),
            root: value.root.into_vec(),
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
