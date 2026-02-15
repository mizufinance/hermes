pub mod config;
pub mod rpc;
pub mod version;

use alloc::sync::Arc;
use std::thread;
use std::time::Duration;

use ibc_proto::ibc::core::channel::v1::{QueryUpgradeErrorRequest, QueryUpgradeRequest};
use ibc_proto::ibc::core::commitment::v1::MerkleProof as RawMerkleProof;
use ibc_relayer_types::applications::ics28_ccv::msgs::{ConsumerChain, ConsumerId};
use ibc_relayer_types::applications::ics31_icq::response::CrossChainQueryResponse;
use ibc_relayer_types::clients::ics08_bankd::client_state::ClientState as BankdClientState;
use ibc_relayer_types::clients::ics08_bankd::consensus_state::ConsensusState as BankdConsensusState;
use ibc_relayer_types::clients::ics08_bankd::header::Header as BankdHeader;
use ibc_relayer_types::core::ics02_client::events::UpdateClient;
use ibc_relayer_types::core::ics02_client::height::Height;
use ibc_relayer_types::core::ics03_connection::connection::{
    ConnectionEnd, IdentifiedConnectionEnd,
};
use ibc_relayer_types::core::ics04_channel::channel::{ChannelEnd, IdentifiedChannelEnd};
use ibc_relayer_types::core::ics04_channel::packet::Sequence;
use ibc_relayer_types::core::ics04_channel::upgrade::{ErrorReceipt, Upgrade};
use ibc_relayer_types::core::ics23_commitment::commitment::CommitmentRoot;
use ibc_relayer_types::core::ics23_commitment::merkle::MerkleProof;
use ibc_relayer_types::core::ics24_host::identifier::{ChainId, ChannelId, ClientId, ConnectionId, PortId};
use ibc_relayer_types::signer::Signer;
use ibc_relayer_types::timestamp::Timestamp;
use ibc_relayer_types::Height as ICSHeight;
use prost::Message;
use serde_json::Value;
use tendermint_rpc::endpoint::broadcast::tx_sync::Response as TxResponse;
use tokio::runtime::Runtime as TokioRuntime;
use tracing::{debug, info, warn};

use crate::account::Balance;
use crate::chain::bankd::config::BankdConfig;
use crate::chain::client::ClientSettings;
use crate::chain::endpoint::{ChainEndpoint, ChainStatus, HealthCheck};
use crate::chain::handle::Subscription;
use crate::chain::requests::*;
use crate::chain::tracking::TrackedMsgs;
use crate::client_state::{AnyClientState, IdentifiedAnyClientState};
use crate::config::{ChainConfig, Error as ConfigError};
use crate::consensus_state::AnyConsensusState;
use crate::denom::DenomTrace;
use crate::error::Error;
use crate::event::source::{EventSource, TxEventSourceCmd};
use crate::event::IbcEventWithHeight;
use crate::keyring::{KeyRing, Secp256k1KeyPair};
use crate::misbehaviour::MisbehaviourEvidence;

/// A bankd light block wrapping a header.
/// Used as the `LightBlock` associated type for `ChainEndpoint`.
#[derive(Clone, Debug)]
pub struct BankdLightBlock {
    pub header: BankdHeader,
}

pub struct BankdChain {
    config: BankdConfig,
    rt: Arc<TokioRuntime>,
    rpc_client: reqwest::Client,
    tx_monitor_cmd: Option<TxEventSourceCmd>,
}

impl BankdChain {
    fn init_event_source(&mut self) -> Result<TxEventSourceCmd, Error> {
        crate::time!(
            "init_event_source",
            {
                "src_chain": self.config.id.to_string(),
            }
        );

        let ws_url = self.config.ws_addr.clone().try_into().map_err(|e| {
            Error::other(format!("invalid WebSocket URL {}: {}", self.config.ws_addr, e))
        })?;

        let batch_delay = Duration::from_millis(500);
        // bankd uses CometBFT-compatible WebSocket events via eth_subscribe,
        // mapped through the existing Hermes WebSocket event source.
        let compat_mode = tendermint_rpc::client::CompatMode::V0_37;

        let (event_source, monitor_tx) = EventSource::websocket(
            self.config.id.clone(),
            ws_url,
            compat_mode,
            batch_delay,
            self.rt.clone(),
        )
        .map_err(Error::event_source)?;

        thread::spawn(move || event_source.run());

        Ok(monitor_tx)
    }

    /// Parse a hex string (e.g. "0x1a") into u64.
    fn parse_hex_u64(s: &str) -> Result<u64, Error> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        u64::from_str_radix(s, 16)
            .map_err(|e| Error::other(format!("failed to parse hex u64 '{}': {}", s, e)))
    }

    /// Build a MerkleProof from raw proof bytes returned by bankd_ibcProof.
    fn decode_proof(raw_bytes: &[u8]) -> Result<MerkleProof, Error> {
        if raw_bytes.is_empty() {
            return Err(Error::empty_response_proof());
        }
        let raw_proof = RawMerkleProof::decode(raw_bytes)
            .map_err(|e| Error::other(format!("failed to decode MerkleProof: {}", e)))?;
        Ok(raw_proof.into())
    }

    /// Query a proof from bankd and decode it.
    fn query_proof_at(
        &self,
        path: &str,
        height: &QueryHeight,
    ) -> Result<Option<MerkleProof>, Error> {
        let h = match height {
            QueryHeight::Latest => 0u64,
            QueryHeight::Specific(h) => h.revision_height(),
        };

        let proof_val: Value = self
            .rt
            .block_on(rpc::query_proof(
                &self.rpc_client,
                &self.config.rpc_addr,
                path,
                h,
            ))?;

        // The RPC returns hex-encoded proof bytes
        let proof_hex = proof_val
            .as_str()
            .ok_or_else(|| Error::other("proof response is not a string".to_string()))?;

        let proof_bytes = hex::decode(proof_hex.strip_prefix("0x").unwrap_or(proof_hex))
            .map_err(|e| Error::other(format!("failed to decode proof hex: {}", e)))?;

        if proof_bytes.is_empty() {
            return Err(Error::other(format!(
                "bankd returned empty proof for path '{}' at height {}",
                path, h
            )));
        }

        Ok(Some(Self::decode_proof(&proof_bytes)?))
    }
}

impl ChainEndpoint for BankdChain {
    type LightBlock = BankdLightBlock;
    type Header = BankdHeader;
    type ConsensusState = BankdConsensusState;
    type ClientState = BankdClientState;
    type Time = Timestamp;
    // Placeholder: bankd doesn't use the Hermes keyring, same pattern as Penumbra.
    type SigningKeyPair = Secp256k1KeyPair;

    fn id(&self) -> &ChainId {
        &self.config.id
    }

    fn config(&self) -> ChainConfig {
        ChainConfig::Bankd(self.config.clone())
    }

    fn bootstrap(config: ChainConfig, rt: Arc<TokioRuntime>) -> Result<Self, Error> {
        let ChainConfig::Bankd(config) = config else {
            return Err(Error::config(ConfigError::wrong_type()));
        };

        let rpc_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(Error::http_request)?;

        info!(
            chain_id = %config.id,
            rpc_addr = %config.rpc_addr,
            "bootstrapping bankd chain"
        );

        // Verify connectivity by querying node status
        let status = rt
            .block_on(rpc::query_node_status(&rpc_client, &config.rpc_addr))?;

        info!(
            chain_id = %config.id,
            finalized = status.finalized_count,
            peers = status.peer_count,
            "bankd node status OK"
        );

        Ok(Self {
            config,
            rt,
            rpc_client,
            tx_monitor_cmd: None,
        })
    }

    fn shutdown(self) -> Result<(), Error> {
        if let Some(monitor_tx) = self.tx_monitor_cmd {
            monitor_tx.shutdown().map_err(Error::event_source)?;
        }
        Ok(())
    }

    fn health_check(&mut self) -> Result<HealthCheck, Error> {
        match self
            .rt
            .block_on(rpc::query_node_status(&self.rpc_client, &self.config.rpc_addr))
        {
            Ok(_status) => Ok(HealthCheck::Healthy),
            Err(e) => Ok(HealthCheck::Unhealthy(Box::new(e))),
        }
    }

    fn subscribe(&mut self) -> Result<Subscription, Error> {
        let tx_monitor_cmd = match &self.tx_monitor_cmd {
            Some(cmd) => cmd,
            None => {
                let cmd = self.init_event_source()?;
                self.tx_monitor_cmd = Some(cmd);
                self.tx_monitor_cmd.as_ref().unwrap()
            }
        };

        let subscription = tx_monitor_cmd.subscribe().map_err(Error::event_source)?;
        Ok(subscription)
    }

    fn keybase(&self) -> &KeyRing<Self::SigningKeyPair> {
        unimplemented!("no key storage support for bankd")
    }

    fn keybase_mut(&mut self) -> &mut KeyRing<Self::SigningKeyPair> {
        unimplemented!("no key storage support for bankd")
    }

    fn get_signer(&self) -> Result<Signer, Error> {
        // bankd uses EVM-style signing; return a dummy signer for now.
        // The actual EVM address will be derived when building transactions.
        Ok(Signer::dummy())
    }

    fn get_key(&self) -> Result<Self::SigningKeyPair, Error> {
        Err(Error::other(
            "bankd does not use the Hermes keyring".to_string(),
        ))
    }

    fn version_specs(&self) -> Result<crate::chain::version::Specs, Error> {
        Ok(crate::chain::version::Specs::Bankd(version::Specs {
            bankd: None,
        }))
    }

    fn send_messages_and_wait_commit(
        &mut self,
        tracked_msgs: TrackedMsgs,
    ) -> Result<Vec<IbcEventWithHeight>, Error> {
        // bankd receives IBC messages as EVM transactions to precompile 0x0800.
        // The calldata is: selector 0xc0509df1 (ibcDispatch) + ABI-encoded protobuf Any.
        //
        // For now, encode each message and submit via eth_sendRawTransaction,
        // then poll for receipt. Full EVM signing is deferred until wallet
        // integration is complete.

        let runtime = self.rt.clone();
        let all_events = Vec::new();

        for msg in &tracked_msgs.msgs {
            debug!(
                type_url = %msg.type_url,
                "submitting IBC message to bankd precompile 0x0800"
            );

            // Build ABI calldata: selector + abi.encode(bytes)
            // selector = 0xc0509df1 for ibcDispatch(bytes)
            let mut calldata = vec![0xc0, 0x50, 0x9d, 0xf1];
            // ABI encoding: offset (32 bytes) + length (32 bytes) + data (padded)
            let proto_bytes = msg.value.clone();
            let offset = 32u64;
            let length = proto_bytes.len() as u64;
            calldata.extend_from_slice(&[0u8; 24]);
            calldata.extend_from_slice(&offset.to_be_bytes());
            calldata.extend_from_slice(&[0u8; 24]);
            calldata.extend_from_slice(&length.to_be_bytes());
            calldata.extend_from_slice(&proto_bytes);
            // Pad to 32-byte boundary
            let padding = (32 - (proto_bytes.len() % 32)) % 32;
            calldata.extend_from_slice(&vec![0u8; padding]);

            let raw_tx_hex = format!("0x{}", hex::encode(&calldata));

            let tx_hash: String = runtime
                .block_on(rpc::send_raw_transaction(
                    &self.rpc_client,
                    &self.config.rpc_addr,
                    &raw_tx_hex,
                ))?;

            info!(tx_hash = %tx_hash, "bankd transaction submitted, polling for receipt");

            // Poll for receipt
            let receipt = runtime.block_on(async {
                for _ in 0..60 {
                    match rpc::get_transaction_receipt(
                        &self.rpc_client,
                        &self.config.rpc_addr,
                        &tx_hash,
                    )
                    .await
                    {
                        Ok(Some(receipt)) => return Ok(receipt),
                        Ok(None) => {
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                        Err(e) => {
                            warn!(error = %e, "error polling receipt, retrying");
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
                Err(Error::other(format!(
                    "timeout waiting for receipt of tx {}",
                    tx_hash
                )))
            })?;

            let block_num = Self::parse_hex_u64(&receipt.block_number)?;
            let height =
                ICSHeight::new(self.config.id.version(), block_num).map_err(|_| {
                    Error::invalid_height_no_source()
                })?;

            if receipt.status != "0x1" {
                return Err(Error::other(format!(
                    "bankd tx {} reverted (status={})",
                    tx_hash, receipt.status
                )));
            }

            // TODO: Parse IBC events from receipt logs when bankd emits them.
            // For now, return an empty event list for successful transactions.
            debug!(
                height = %height,
                tx_hash = %tx_hash,
                "bankd transaction confirmed"
            );
            let _ = all_events; // suppress unused warning in future
        }

        Ok(all_events)
    }

    fn send_messages_and_wait_check_tx(
        &mut self,
        _tracked_msgs: TrackedMsgs,
    ) -> Result<Vec<TxResponse>, Error> {
        // bankd doesn't have a check_tx / mempool concept like Cosmos.
        Err(Error::other(
            "bankd does not support check_tx; use send_messages_and_wait_commit".to_string(),
        ))
    }

    fn verify_header(
        &mut self,
        _trusted: ICSHeight,
        target: ICSHeight,
        _client_state: &AnyClientState,
    ) -> Result<Self::LightBlock, Error> {
        // Fetch the block at the target height and construct a BankdLightBlock.
        let block_num = format!("0x{:x}", target.revision_height());
        let block = self
            .rt
            .block_on(rpc::get_block_by_number(
                &self.rpc_client,
                &self.config.rpc_addr,
                &block_num,
            ))?
            .ok_or_else(|| {
                Error::other(format!("block not found at height {}", target))
            })?;

        let timestamp_secs = Self::parse_hex_u64(&block.timestamp)?;
        let timestamp = Timestamp::from_nanoseconds(timestamp_secs * 1_000_000_000)
            .map_err(|e| Error::other(format!("invalid timestamp: {}", e)))?;

        let state_root_bytes =
            hex::decode(block.state_root.strip_prefix("0x").unwrap_or(&block.state_root))
                .unwrap_or_default();

        let block_hash_bytes =
            hex::decode(block.hash.strip_prefix("0x").unwrap_or(&block.hash))
                .unwrap_or_default();

        let header = BankdHeader {
            height: target,
            timestamp,
            new_root: state_root_bytes.clone(),
            ibc_root: state_root_bytes,
            block_id: block_hash_bytes,
            // TODO: fetch BLS threshold signature from bankd when available
            threshold_signature: vec![],
        };

        Ok(BankdLightBlock { header })
    }

    fn check_misbehaviour(
        &mut self,
        _update: &UpdateClient,
        _client_state: &AnyClientState,
    ) -> Result<Option<MisbehaviourEvidence>, Error> {
        // bankd uses BLS threshold signatures; misbehaviour detection
        // requires comparing two conflicting signed headers.
        // Stub: return None (no misbehaviour detected).
        Ok(None)
    }

    fn query_balance(
        &self,
        _key_name: Option<&str>,
        _denom: Option<&str>,
    ) -> Result<Balance, Error> {
        // bankd doesn't have native denom balances in the Cosmos sense.
        // Could be wired to eth_getBalance in the future.
        Ok(Balance {
            amount: "0".to_string(),
            denom: "wei".to_string(),
        })
    }

    fn query_all_balances(&self, _key_name: Option<&str>) -> Result<Vec<Balance>, Error> {
        Ok(vec![])
    }

    fn query_denom_trace(&self, _hash: String) -> Result<DenomTrace, Error> {
        Err(Error::other(
            "bankd does not support denom trace queries".to_string(),
        ))
    }

    fn query_commitment_prefix(&self) -> Result<ibc_relayer_types::core::ics23_commitment::commitment::CommitmentPrefix, Error> {
        // bankd stores IBC state under the "ibc" prefix.
        Ok(b"ibc".to_vec().try_into().unwrap())
    }

    fn query_application_status(&self) -> Result<ChainStatus, Error> {
        crate::time!(
            "query_application_status",
            {
                "src_chain": self.config.id.to_string(),
            }
        );
        crate::telemetry!(query, self.id(), "query_application_status");

        let status = self
            .rt
            .block_on(rpc::query_node_status(&self.rpc_client, &self.config.rpc_addr))?;

        // Use the finalized block count as the chain height.
        let height = ICSHeight::new(self.config.id.version(), status.finalized_count)
            .map_err(|_| Error::invalid_height_no_source())?;

        // Fetch the latest block to get a timestamp.
        let block = self
            .rt
            .block_on(rpc::get_block_by_number(
                &self.rpc_client,
                &self.config.rpc_addr,
                "latest",
            ))?
            .ok_or_else(|| Error::other("no latest block from bankd".to_string()))?;

        let timestamp_secs = Self::parse_hex_u64(&block.timestamp)?;
        let timestamp = Timestamp::from_nanoseconds(timestamp_secs * 1_000_000_000)
            .map_err(|e| Error::other(format!("invalid block timestamp: {}", e)))?;

        Ok(ChainStatus { height, timestamp })
    }

    fn query_clients(
        &self,
        _request: QueryClientStatesRequest,
    ) -> Result<Vec<IdentifiedAnyClientState>, Error> {
        // bankd doesn't expose a list-all-clients endpoint yet.
        // Return empty list; specific client queries work via bankd_ibcClientState.
        Ok(vec![])
    }

    fn query_client_state(
        &self,
        request: QueryClientStateRequest,
        include_proof: IncludeProof,
    ) -> Result<(AnyClientState, Option<MerkleProof>), Error> {
        crate::telemetry!(query, self.id(), "query_client_state");

        let client_id_str = request.client_id.to_string();
        let response: Value = self.rt.block_on(rpc::query_client_state(
            &self.rpc_client,
            &self.config.rpc_addr,
            &client_id_str,
        ))?;

        // Parse the client state from the JSON-RPC response.
        // bankd returns the protobuf-JSON representation of the client state.
        let client_state_any: ibc_proto::google::protobuf::Any =
            serde_json::from_value(response)
                .map_err(|e| Error::other(format!("failed to parse client state: {}", e)))?;

        let client_state: AnyClientState = client_state_any
            .try_into()
            .map_err(|e: ibc_relayer_types::core::ics02_client::error::Error| {
                Error::other(format!("failed to decode client state: {}", e))
            })?;

        match include_proof {
            IncludeProof::No => Ok((client_state, None)),
            IncludeProof::Yes => {
                let path = format!("clients/{}/clientState", client_id_str);
                let proof = self.query_proof_at(&path, &request.height)?;
                Ok((client_state, proof))
            }
        }
    }

    fn query_consensus_state(
        &self,
        request: QueryConsensusStateRequest,
        include_proof: IncludeProof,
    ) -> Result<(AnyConsensusState, Option<MerkleProof>), Error> {
        crate::telemetry!(query, self.id(), "query_consensus_state");

        let client_id_str = request.client_id.to_string();
        let consensus_height = request.consensus_height;

        let response: Value = self.rt.block_on(rpc::query_consensus_state(
            &self.rpc_client,
            &self.config.rpc_addr,
            &client_id_str,
            consensus_height.revision_height(),
        ))?;

        let consensus_state_any: ibc_proto::google::protobuf::Any =
            serde_json::from_value(response).map_err(|e| {
                Error::other(format!("failed to parse consensus state: {}", e))
            })?;

        let consensus_state: AnyConsensusState = consensus_state_any
            .try_into()
            .map_err(|e: ibc_relayer_types::core::ics02_client::error::Error| {
                Error::other(format!("failed to decode consensus state: {}", e))
            })?;

        match include_proof {
            IncludeProof::No => Ok((consensus_state, None)),
            IncludeProof::Yes => {
                let path = format!(
                    "clients/{}/consensusStates/{}-{}",
                    client_id_str,
                    consensus_height.revision_number(),
                    consensus_height.revision_height(),
                );
                let proof = self.query_proof_at(&path, &request.query_height)?;
                Ok((consensus_state, proof))
            }
        }
    }

    fn query_consensus_state_heights(
        &self,
        request: QueryConsensusStateHeightsRequest,
    ) -> Result<Vec<ICSHeight>, Error> {
        let client_id_str = request.client_id.to_string();

        let response: Value = self.rt.block_on(rpc::query_client_consensus_states(
            &self.rpc_client,
            &self.config.rpc_addr,
            &client_id_str,
        ))?;

        // bankd returns an array of height objects
        let heights_arr = response.as_array().ok_or_else(|| {
            Error::other("consensus state heights response is not an array".to_string())
        })?;

        let mut heights = Vec::new();
        for h in heights_arr {
            if let (Some(rev_num), Some(rev_height)) = (
                h.get("revision_number").and_then(|v| v.as_u64()),
                h.get("revision_height").and_then(|v| v.as_u64()),
            ) {
                if let Ok(height) = ICSHeight::new(rev_num, rev_height) {
                    heights.push(height);
                }
            }
        }

        Ok(heights)
    }

    fn query_upgraded_client_state(
        &self,
        _request: QueryUpgradedClientStateRequest,
    ) -> Result<(AnyClientState, MerkleProof), Error> {
        Err(Error::other(
            "bankd does not support upgraded client state queries".to_string(),
        ))
    }

    fn query_upgraded_consensus_state(
        &self,
        _request: QueryUpgradedConsensusStateRequest,
    ) -> Result<(AnyConsensusState, MerkleProof), Error> {
        Err(Error::other(
            "bankd does not support upgraded consensus state queries".to_string(),
        ))
    }

    fn query_connections(
        &self,
        _request: QueryConnectionsRequest,
    ) -> Result<Vec<IdentifiedConnectionEnd>, Error> {
        // bankd doesn't expose a list-all-connections endpoint yet.
        Ok(vec![])
    }

    fn query_client_connections(
        &self,
        _request: QueryClientConnectionsRequest,
    ) -> Result<Vec<ConnectionId>, Error> {
        // bankd doesn't expose a client-connections endpoint yet.
        Ok(vec![])
    }

    fn query_connection(
        &self,
        request: QueryConnectionRequest,
        include_proof: IncludeProof,
    ) -> Result<(ConnectionEnd, Option<MerkleProof>), Error> {
        crate::telemetry!(query, self.id(), "query_connection");

        let conn_id_str = request.connection_id.to_string();
        let response: Value = self.rt.block_on(rpc::query_connection(
            &self.rpc_client,
            &self.config.rpc_addr,
            &conn_id_str,
        ))?;

        // Parse the raw connection end from the JSON-RPC response.
        let raw_conn: ibc_proto::ibc::core::connection::v1::ConnectionEnd =
            serde_json::from_value(response).map_err(|e| {
                Error::other(format!("failed to parse connection: {}", e))
            })?;

        let connection_end: ConnectionEnd = raw_conn
            .try_into()
            .map_err(|e: ibc_relayer_types::core::ics03_connection::error::Error| {
                Error::other(format!("failed to decode connection: {}", e))
            })?;

        match include_proof {
            IncludeProof::No => Ok((connection_end, None)),
            IncludeProof::Yes => {
                let path = format!("connections/{}", conn_id_str);
                let proof = self.query_proof_at(&path, &request.height)?;
                Ok((connection_end, proof))
            }
        }
    }

    fn query_connection_channels(
        &self,
        _request: QueryConnectionChannelsRequest,
    ) -> Result<Vec<IdentifiedChannelEnd>, Error> {
        // bankd doesn't expose a connection-channels endpoint yet.
        Ok(vec![])
    }

    fn query_channels(
        &self,
        _request: QueryChannelsRequest,
    ) -> Result<Vec<IdentifiedChannelEnd>, Error> {
        // bankd doesn't expose a list-all-channels endpoint yet.
        Ok(vec![])
    }

    fn query_channel(
        &self,
        request: QueryChannelRequest,
        include_proof: IncludeProof,
    ) -> Result<(ChannelEnd, Option<MerkleProof>), Error> {
        crate::telemetry!(query, self.id(), "query_channel");

        let port_id_str = request.port_id.to_string();
        let channel_id_str = request.channel_id.to_string();

        let response: Value = self.rt.block_on(rpc::query_channel(
            &self.rpc_client,
            &self.config.rpc_addr,
            &port_id_str,
            &channel_id_str,
        ))?;

        let raw_channel: ibc_proto::ibc::core::channel::v1::Channel =
            serde_json::from_value(response)
                .map_err(|e| Error::other(format!("failed to parse channel: {}", e)))?;

        let channel_end: ChannelEnd = raw_channel
            .try_into()
            .map_err(|e: ibc_relayer_types::core::ics04_channel::error::Error| {
                Error::other(format!("failed to decode channel: {}", e))
            })?;

        match include_proof {
            IncludeProof::No => Ok((channel_end, None)),
            IncludeProof::Yes => {
                let path = format!("channelEnds/ports/{}/channels/{}", port_id_str, channel_id_str);
                let proof = self.query_proof_at(&path, &request.height)?;
                Ok((channel_end, proof))
            }
        }
    }

    fn query_channel_client_state(
        &self,
        _request: QueryChannelClientStateRequest,
    ) -> Result<Option<IdentifiedAnyClientState>, Error> {
        // bankd doesn't expose a channel-client-state endpoint yet.
        Ok(None)
    }

    fn query_packet_commitment(
        &self,
        request: QueryPacketCommitmentRequest,
        include_proof: IncludeProof,
    ) -> Result<(Vec<u8>, Option<MerkleProof>), Error> {
        crate::telemetry!(query, self.id(), "query_packet_commitment");

        let port_id_str = request.port_id.to_string();
        let channel_id_str = request.channel_id.to_string();
        let sequence: u64 = request.sequence.into();

        let response: Value = self.rt.block_on(rpc::query_packet_commitment(
            &self.rpc_client,
            &self.config.rpc_addr,
            &port_id_str,
            &channel_id_str,
            sequence,
        ))?;

        // bankd returns the commitment as a hex string
        let commitment_hex = response.as_str().unwrap_or("");
        let commitment =
            hex::decode(commitment_hex.strip_prefix("0x").unwrap_or(commitment_hex))
                .unwrap_or_default();

        match include_proof {
            IncludeProof::No => Ok((commitment, None)),
            IncludeProof::Yes => {
                let path = format!(
                    "commitments/ports/{}/channels/{}/sequences/{}",
                    port_id_str, channel_id_str, sequence
                );
                let proof = self.query_proof_at(&path, &request.height)?;
                Ok((commitment, proof))
            }
        }
    }

    fn query_packet_commitments(
        &self,
        _request: QueryPacketCommitmentsRequest,
    ) -> Result<(Vec<Sequence>, ICSHeight), Error> {
        // bankd doesn't expose a bulk packet-commitments endpoint yet.
        let status = self.query_application_status()?;
        Ok((vec![], status.height))
    }

    fn query_packet_receipt(
        &self,
        request: QueryPacketReceiptRequest,
        include_proof: IncludeProof,
    ) -> Result<(Vec<u8>, Option<MerkleProof>), Error> {
        crate::telemetry!(query, self.id(), "query_packet_receipt");

        let port_id_str = request.port_id.to_string();
        let channel_id_str = request.channel_id.to_string();
        let sequence: u64 = request.sequence.into();

        let response: Value = self.rt.block_on(rpc::query_packet_receipt(
            &self.rpc_client,
            &self.config.rpc_addr,
            &port_id_str,
            &channel_id_str,
            sequence,
        ))?;

        // bankd returns a boolean for receipt existence
        let received = response.as_bool().unwrap_or(false);

        match include_proof {
            IncludeProof::No => Ok((vec![received.into()], None)),
            IncludeProof::Yes => {
                let path = format!(
                    "receipts/ports/{}/channels/{}/sequences/{}",
                    port_id_str, channel_id_str, sequence
                );
                let proof = self.query_proof_at(&path, &request.height)?;
                Ok((vec![received.into()], proof))
            }
        }
    }

    fn query_unreceived_packets(
        &self,
        request: QueryUnreceivedPacketsRequest,
    ) -> Result<Vec<Sequence>, Error> {
        // Check each sequence against bankd_ibcPacketReceipt to find unreceived ones.
        let mut unreceived = Vec::new();

        for seq in &request.packet_commitment_sequences {
            let seq_num: u64 = (*seq).into();
            let response: Value = self.rt.block_on(rpc::query_packet_receipt(
                &self.rpc_client,
                &self.config.rpc_addr,
                &request.port_id.to_string(),
                &request.channel_id.to_string(),
                seq_num,
            ))?;

            let received = response.as_bool().unwrap_or(false);
            if !received {
                unreceived.push(*seq);
            }
        }

        Ok(unreceived)
    }

    fn query_packet_acknowledgement(
        &self,
        request: QueryPacketAcknowledgementRequest,
        include_proof: IncludeProof,
    ) -> Result<(Vec<u8>, Option<MerkleProof>), Error> {
        crate::telemetry!(query, self.id(), "query_packet_acknowledgement");

        let port_id_str = request.port_id.to_string();
        let channel_id_str = request.channel_id.to_string();
        let sequence: u64 = request.sequence.into();

        let response: Value = self.rt.block_on(rpc::query_packet_acknowledgement(
            &self.rpc_client,
            &self.config.rpc_addr,
            &port_id_str,
            &channel_id_str,
            sequence,
        ))?;

        let ack_hex = response.as_str().unwrap_or("");
        let ack = hex::decode(ack_hex.strip_prefix("0x").unwrap_or(ack_hex))
            .unwrap_or_default();

        match include_proof {
            IncludeProof::No => Ok((ack, None)),
            IncludeProof::Yes => {
                let path = format!(
                    "acks/ports/{}/channels/{}/sequences/{}",
                    port_id_str, channel_id_str, sequence
                );
                let proof = self.query_proof_at(&path, &request.height)?;
                Ok((ack, proof))
            }
        }
    }

    fn query_packet_acknowledgements(
        &self,
        _request: QueryPacketAcknowledgementsRequest,
    ) -> Result<(Vec<Sequence>, ICSHeight), Error> {
        // bankd doesn't expose a bulk packet-acknowledgements endpoint yet.
        let status = self.query_application_status()?;
        Ok((vec![], status.height))
    }

    fn query_unreceived_acknowledgements(
        &self,
        _request: QueryUnreceivedAcksRequest,
    ) -> Result<Vec<Sequence>, Error> {
        // TODO: implement when bankd exposes unreceived acks endpoint.
        Ok(vec![])
    }

    fn query_next_sequence_receive(
        &self,
        request: QueryNextSequenceReceiveRequest,
        include_proof: IncludeProof,
    ) -> Result<(Sequence, Option<MerkleProof>), Error> {
        crate::telemetry!(query, self.id(), "query_next_sequence_receive");

        let port_id_str = request.port_id.to_string();
        let channel_id_str = request.channel_id.to_string();

        let response: Value = self.rt.block_on(rpc::query_next_sequence_recv(
            &self.rpc_client,
            &self.config.rpc_addr,
            &port_id_str,
            &channel_id_str,
        ))?;

        let next_seq: u64 = response
            .as_u64()
            .ok_or_else(|| Error::other("next_sequence_recv is not a u64".to_string()))?;

        match include_proof {
            IncludeProof::No => Ok((next_seq.into(), None)),
            IncludeProof::Yes => {
                let path = format!(
                    "nextSequenceRecv/ports/{}/channels/{}",
                    port_id_str, channel_id_str
                );
                let proof = self.query_proof_at(&path, &request.height)?;
                Ok((next_seq.into(), proof))
            }
        }
    }

    fn query_txs(&self, _request: QueryTxRequest) -> Result<Vec<IbcEventWithHeight>, Error> {
        // bankd doesn't support Tendermint-style tx search.
        // TODO: implement via bankd event indexer when available.
        Ok(vec![])
    }

    fn query_packet_events(
        &self,
        _request: QueryPacketEventDataRequest,
    ) -> Result<Vec<IbcEventWithHeight>, Error> {
        // bankd doesn't support Tendermint-style block/tx event queries.
        // TODO: implement via bankd event indexer when available.
        Ok(vec![])
    }

    fn query_host_consensus_state(
        &self,
        request: QueryHostConsensusStateRequest,
    ) -> Result<Self::ConsensusState, Error> {
        let height = match request.height {
            QueryHeight::Latest => {
                let status = self.query_application_status()?;
                status.height
            }
            QueryHeight::Specific(h) => h,
        };

        let block_num = format!("0x{:x}", height.revision_height());
        let block = self
            .rt
            .block_on(rpc::get_block_by_number(
                &self.rpc_client,
                &self.config.rpc_addr,
                &block_num,
            ))?
            .ok_or_else(|| {
                Error::other(format!("block not found at height {}", height))
            })?;

        let timestamp_secs = Self::parse_hex_u64(&block.timestamp)?;
        let timestamp = Timestamp::from_nanoseconds(timestamp_secs * 1_000_000_000)
            .map_err(|e| Error::other(format!("invalid timestamp: {}", e)))?;

        let root_bytes =
            hex::decode(block.state_root.strip_prefix("0x").unwrap_or(&block.state_root))
                .unwrap_or_default();

        Ok(BankdConsensusState::new(
            CommitmentRoot::from_bytes(&root_bytes),
            timestamp,
        ))
    }

    fn build_client_state(
        &self,
        height: ICSHeight,
        _settings: ClientSettings,
    ) -> Result<Self::ClientState, Error> {
        Ok(BankdClientState::new(
            self.config.id.clone(),
            height,
            // group_public_key: populated at genesis, empty placeholder for now
            vec![],
            self.config.trusting_period,
        ))
    }

    fn build_consensus_state(
        &self,
        light_block: Self::LightBlock,
    ) -> Result<Self::ConsensusState, Error> {
        let header = light_block.header;
        Ok(BankdConsensusState::new(
            CommitmentRoot::from_bytes(&header.ibc_root),
            header.timestamp,
        ))
    }

    fn build_header(
        &mut self,
        trusted_height: ICSHeight,
        target_height: ICSHeight,
        client_state: &AnyClientState,
    ) -> Result<(Self::Header, Vec<Self::Header>), Error> {
        // Verify the target header and return it.
        // bankd headers are self-contained (BLS threshold signature),
        // so no supporting headers are needed.
        let light_block = self.verify_header(trusted_height, target_height, client_state)?;
        Ok((light_block.header, vec![]))
    }

    fn maybe_register_counterparty_payee(
        &mut self,
        _channel_id: &ChannelId,
        _port_id: &PortId,
        _counterparty_payee: &Signer,
    ) -> Result<(), Error> {
        Err(Error::other(
            "bankd does not support ICS-29 fee middleware".to_string(),
        ))
    }

    fn cross_chain_query(
        &self,
        _requests: Vec<CrossChainQueryRequest>,
    ) -> Result<Vec<CrossChainQueryResponse>, Error> {
        Err(Error::other(
            "bankd does not support ICS-31 cross-chain queries".to_string(),
        ))
    }

    fn query_incentivized_packet(
        &self,
        _request: ibc_proto::ibc::apps::fee::v1::QueryIncentivizedPacketRequest,
    ) -> Result<ibc_proto::ibc::apps::fee::v1::QueryIncentivizedPacketResponse, Error> {
        Err(Error::other(
            "bankd does not support incentivized packets".to_string(),
        ))
    }

    fn query_consumer_chains(&self) -> Result<Vec<ConsumerChain>, Error> {
        Err(Error::other(
            "bankd does not support consumer chains".to_string(),
        ))
    }

    fn query_upgrade(
        &self,
        _request: QueryUpgradeRequest,
        _height: Height,
        _include_proof: IncludeProof,
    ) -> Result<(Upgrade, Option<MerkleProof>), Error> {
        Err(Error::other(
            "bankd does not support channel upgrades".to_string(),
        ))
    }

    fn query_upgrade_error(
        &self,
        _request: QueryUpgradeErrorRequest,
        _height: Height,
        _include_proof: IncludeProof,
    ) -> Result<(ErrorReceipt, Option<MerkleProof>), Error> {
        Err(Error::other(
            "bankd does not support channel upgrade errors".to_string(),
        ))
    }

    fn query_ccv_consumer_id(&self, _client_id: ClientId) -> Result<ConsumerId, Error> {
        Err(Error::other(
            "bankd does not support CCV consumer IDs".to_string(),
        ))
    }
}
