use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use tendermint_rpc::Url;

use crate::error::Error;

static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

fn next_id() -> u64 {
    REQUEST_ID.fetch_add(1, Ordering::Relaxed)
}

#[derive(Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'static str,
    method: &'a str,
    params: Value,
    id: u64,
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Deserialize, Debug)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

impl std::fmt::Display for JsonRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JSON-RPC error {}: {}", self.code, self.message)
    }
}

/// Perform a raw JSON-RPC call to the bankd node.
pub async fn json_rpc_call<T: DeserializeOwned>(
    client: &reqwest::Client,
    rpc_url: &Url,
    method: &str,
    params: Value,
) -> Result<T, Error> {
    let req = JsonRpcRequest {
        jsonrpc: "2.0",
        method,
        params,
        id: next_id(),
    };

    let response = client
        .post(rpc_url.to_string())
        .json(&req)
        .send()
        .await
        .map_err(Error::http_request)?;

    let status = response.status();
    if !status.is_success() {
        return Err(Error::http_response(status));
    }

    let rpc_response: JsonRpcResponse<T> =
        response.json().await.map_err(Error::http_response_body)?;

    if let Some(err) = rpc_response.error {
        return Err(Error::other(err.to_string()));
    }

    rpc_response
        .result
        .ok_or_else(|| Error::other("JSON-RPC response missing 'result' field".to_string()))
}

// ---------------------------------------------------------------------------
// kora_nodeStatus
// ---------------------------------------------------------------------------

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct NodeStatus {
    pub current_view: u64,
    pub finalized_count: u64,
    pub proposed_count: u64,
    pub nullified_count: u64,
    pub peer_count: u64,
    pub is_leader: bool,
}

pub async fn query_node_status(
    client: &reqwest::Client,
    rpc_url: &Url,
) -> Result<NodeStatus, Error> {
    json_rpc_call(client, rpc_url, "kora_nodeStatus", json!([])).await
}

// ---------------------------------------------------------------------------
// bankd_ibcClientState
// ---------------------------------------------------------------------------

#[derive(Deserialize, Debug, Clone)]
pub struct RpcClientStateResponse {
    pub client_state: Value,
}

pub async fn query_client_state(
    client: &reqwest::Client,
    rpc_url: &Url,
    client_id: &str,
) -> Result<Value, Error> {
    json_rpc_call(client, rpc_url, "bankd_ibcClientState", json!([client_id])).await
}

// ---------------------------------------------------------------------------
// bankd_ibcConsensusState
// ---------------------------------------------------------------------------

pub async fn query_consensus_state(
    client: &reqwest::Client,
    rpc_url: &Url,
    client_id: &str,
    height: u64,
) -> Result<Value, Error> {
    json_rpc_call(
        client,
        rpc_url,
        "bankd_ibcConsensusState",
        json!([client_id, height]),
    )
    .await
}

// ---------------------------------------------------------------------------
// bankd_ibcClientConsensusStates
// ---------------------------------------------------------------------------

pub async fn query_client_consensus_states(
    client: &reqwest::Client,
    rpc_url: &Url,
    client_id: &str,
) -> Result<Value, Error> {
    json_rpc_call(
        client,
        rpc_url,
        "bankd_ibcClientConsensusStates",
        json!([client_id]),
    )
    .await
}

// ---------------------------------------------------------------------------
// bankd_ibcConnection
// ---------------------------------------------------------------------------

pub async fn query_connection(
    client: &reqwest::Client,
    rpc_url: &Url,
    connection_id: &str,
) -> Result<Value, Error> {
    json_rpc_call(
        client,
        rpc_url,
        "bankd_ibcConnection",
        json!([connection_id]),
    )
    .await
}

// ---------------------------------------------------------------------------
// bankd_ibcChannel
// ---------------------------------------------------------------------------

pub async fn query_channel(
    client: &reqwest::Client,
    rpc_url: &Url,
    port_id: &str,
    channel_id: &str,
) -> Result<Value, Error> {
    json_rpc_call(
        client,
        rpc_url,
        "bankd_ibcChannel",
        json!([port_id, channel_id]),
    )
    .await
}

// ---------------------------------------------------------------------------
// bankd_ibcProof
// ---------------------------------------------------------------------------

pub async fn query_proof(
    client: &reqwest::Client,
    rpc_url: &Url,
    path: &str,
    height: u64,
) -> Result<Value, Error> {
    json_rpc_call(client, rpc_url, "bankd_ibcProof", json!([path, height])).await
}

// ---------------------------------------------------------------------------
// bankd_ibcPacketCommitment
// ---------------------------------------------------------------------------

pub async fn query_packet_commitment(
    client: &reqwest::Client,
    rpc_url: &Url,
    port_id: &str,
    channel_id: &str,
    sequence: u64,
) -> Result<Value, Error> {
    json_rpc_call(
        client,
        rpc_url,
        "bankd_ibcPacketCommitment",
        json!([port_id, channel_id, sequence]),
    )
    .await
}

// ---------------------------------------------------------------------------
// bankd_ibcPacketReceipt
// ---------------------------------------------------------------------------

pub async fn query_packet_receipt(
    client: &reqwest::Client,
    rpc_url: &Url,
    port_id: &str,
    channel_id: &str,
    sequence: u64,
) -> Result<Value, Error> {
    json_rpc_call(
        client,
        rpc_url,
        "bankd_ibcPacketReceipt",
        json!([port_id, channel_id, sequence]),
    )
    .await
}

// ---------------------------------------------------------------------------
// bankd_ibcPacketAcknowledgement
// ---------------------------------------------------------------------------

pub async fn query_packet_acknowledgement(
    client: &reqwest::Client,
    rpc_url: &Url,
    port_id: &str,
    channel_id: &str,
    sequence: u64,
) -> Result<Value, Error> {
    json_rpc_call(
        client,
        rpc_url,
        "bankd_ibcPacketAcknowledgement",
        json!([port_id, channel_id, sequence]),
    )
    .await
}

// ---------------------------------------------------------------------------
// bankd_ibcNextSequenceRecv
// ---------------------------------------------------------------------------

pub async fn query_next_sequence_recv(
    client: &reqwest::Client,
    rpc_url: &Url,
    port_id: &str,
    channel_id: &str,
) -> Result<Value, Error> {
    json_rpc_call(
        client,
        rpc_url,
        "bankd_ibcNextSequenceRecv",
        json!([port_id, channel_id]),
    )
    .await
}

// ---------------------------------------------------------------------------
// eth_getBlockByNumber
// ---------------------------------------------------------------------------

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EthBlock {
    pub number: String,
    pub timestamp: String,
    pub hash: String,
    #[serde(default)]
    pub state_root: String,
}

pub async fn get_block_by_number(
    client: &reqwest::Client,
    rpc_url: &Url,
    block: &str,
) -> Result<Option<EthBlock>, Error> {
    // Use Value to avoid serde's Option<Option<T>> flattening issue:
    // when T = Option<EthBlock>, a JSON null result maps to None for the
    // outer Option in JsonRpcResponse, causing a spurious "missing result" error.
    let val: Value = json_rpc_call(client, rpc_url, "eth_getBlockByNumber", json!([block, false])).await?;
    if val.is_null() {
        return Ok(None);
    }
    let block: EthBlock = serde_json::from_value(val)
        .map_err(|e| Error::other(format!("failed to parse EthBlock: {e}")))?;
    Ok(Some(block))
}

// ---------------------------------------------------------------------------
// eth_getTransactionCount (nonce)
// ---------------------------------------------------------------------------

pub async fn get_transaction_count(
    client: &reqwest::Client,
    rpc_url: &Url,
    address: &str,
) -> Result<u64, Error> {
    let hex_nonce: String = json_rpc_call(
        client,
        rpc_url,
        "eth_getTransactionCount",
        json!([address, "latest"]),
    )
    .await?;
    parse_hex_u64(&hex_nonce)
}

fn parse_hex_u64(s: &str) -> Result<u64, Error> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).map_err(|e| Error::other(format!("invalid hex u64: {e}")))
}

// ---------------------------------------------------------------------------
// eth_sendRawTransaction
// ---------------------------------------------------------------------------

pub async fn send_raw_transaction(
    client: &reqwest::Client,
    rpc_url: &Url,
    raw_tx: &str,
) -> Result<String, Error> {
    json_rpc_call(
        client,
        rpc_url,
        "eth_sendRawTransaction",
        json!([raw_tx]),
    )
    .await
}

// ---------------------------------------------------------------------------
// eth_getTransactionReceipt
// ---------------------------------------------------------------------------

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TxReceipt {
    pub status: String,
    pub block_number: String,
    #[serde(default)]
    pub gas_used: String,
    #[serde(default)]
    pub logs: Vec<Value>,
    pub transaction_hash: String,
}

pub async fn get_transaction_receipt(
    client: &reqwest::Client,
    rpc_url: &Url,
    tx_hash: &str,
) -> Result<Option<TxReceipt>, Error> {
    let val: Value = json_rpc_call(client, rpc_url, "eth_getTransactionReceipt", json!([tx_hash])).await?;
    if val.is_null() {
        return Ok(None);
    }
    let receipt: TxReceipt = serde_json::from_value(val)
        .map_err(|e| Error::other(format!("failed to parse TxReceipt: {e}")))?;
    Ok(Some(receipt))
}
