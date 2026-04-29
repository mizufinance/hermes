use core::time::Duration;

use ibc_relayer_types::core::ics24_host::identifier::ChainId;
use serde_derive::{Deserialize, Serialize};
use tendermint_rpc::Url;

use crate::config::{default, types::TrustThreshold, PacketFilter};

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BankdConfig {
    pub id: ChainId,

    #[serde(default)]
    pub key_name: String,

    /// Hex-encoded secp256k1 private key for signing EVM transactions.
    /// Required for submitting IBC messages to the bankd precompile.
    #[serde(default)]
    pub signing_key: Option<String>,

    /// HTTP JSON-RPC endpoint (eth_*)
    pub rpc_addr: Url,

    /// WebSocket endpoint (eth_subscribe)
    pub ws_addr: Url,

    /// Numeric EVM chain ID
    pub evm_chain_id: u64,

    #[serde(with = "humantime_serde")]
    pub trusting_period: Duration,

    #[serde(default = "default::max_block_time", with = "humantime_serde")]
    pub max_block_time: Duration,

    #[serde(default)]
    pub trust_threshold: TrustThreshold,

    #[serde(default)]
    pub packet_filter: PacketFilter,

    pub clear_interval: Option<u64>,

    #[serde(default = "default::query_packets_chunk_size")]
    pub query_packets_chunk_size: usize,

    #[serde(default = "default::clock_drift", with = "humantime_serde")]
    pub clock_drift: Duration,
}
