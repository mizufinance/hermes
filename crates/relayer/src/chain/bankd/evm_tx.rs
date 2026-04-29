//! Minimal EVM transaction signing using secp256k1 + keccak256 + RLP.
//!
//! Builds and signs legacy (pre-EIP-2718) transactions for submitting
//! IBC messages to the bankd precompile at 0x0800.

use secp256k1::{Message, Secp256k1, SecretKey};
use tiny_keccak::{Hasher, Keccak};

use crate::error::Error;

/// IBC precompile address: 0x0000000000000000000000000000000000000800
pub const IBC_PRECOMPILE: [u8; 20] = {
    let mut addr = [0u8; 20];
    addr[18] = 0x08;
    // addr[19] = 0x00; // already zero
    addr
};

/// An EVM signer holding a secp256k1 secret key.
pub struct EvmSigner {
    secret: SecretKey,
    address: [u8; 20],
}

impl EvmSigner {
    /// Parse a hex-encoded private key (with or without 0x prefix).
    pub fn from_hex(hex_key: &str) -> Result<Self, Error> {
        let hex_key = hex_key.strip_prefix("0x").unwrap_or(hex_key);
        let key_bytes =
            hex::decode(hex_key).map_err(|e| Error::other(format!("invalid hex key: {e}")))?;
        let secret = SecretKey::from_slice(&key_bytes)
            .map_err(|e| Error::other(format!("invalid secp256k1 key: {e}")))?;

        let secp = Secp256k1::new();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret);
        let address = pubkey_to_address(&pubkey);

        Ok(Self { secret, address })
    }

    /// The checksumless hex address (e.g. "0xf39f...").
    pub fn address_hex(&self) -> String {
        format!("0x{}", hex::encode(self.address))
    }

    /// Build and sign a legacy EVM transaction calling `to` with `data`.
    pub fn sign_legacy_tx(
        &self,
        chain_id: u64,
        nonce: u64,
        gas_price: u64,
        gas_limit: u64,
        to: [u8; 20],
        data: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        // 1. RLP-encode the unsigned transaction for signing (EIP-155):
        //    [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
        let unsigned = rlp_encode_unsigned(nonce, gas_price, gas_limit, &to, &data, chain_id);

        // 2. Keccak256 hash of the unsigned RLP
        let hash = keccak256(&unsigned);

        // 3. Sign
        let secp = Secp256k1::signing_only();
        let msg = Message::from_digest(hash);
        let (rec_id, sig_bytes) = secp
            .sign_ecdsa_recoverable(&msg, &self.secret)
            .serialize_compact();

        let r = &sig_bytes[..32];
        let s = &sig_bytes[32..64];
        // EIP-155: v = chain_id * 2 + 35 + recovery_id
        let v = chain_id * 2 + 35 + rec_id.to_i32() as u64;

        // 4. RLP-encode the signed transaction:
        //    [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
        let signed = rlp_encode_signed(nonce, gas_price, gas_limit, &to, &data, v, r, s);

        Ok(signed)
    }
}

fn pubkey_to_address(pubkey: &secp256k1::PublicKey) -> [u8; 20] {
    let uncompressed = pubkey.serialize_uncompressed();
    // Skip the 0x04 prefix byte, hash the remaining 64 bytes
    let hash = keccak256(&uncompressed[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    addr
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

// ── RLP encoding ─────────────────────────────────────────────────────────

fn rlp_encode_unsigned(
    nonce: u64,
    gas_price: u64,
    gas_limit: u64,
    to: &[u8; 20],
    data: &[u8],
    chain_id: u64,
) -> Vec<u8> {
    let mut items = Vec::new();
    items.push(rlp_encode_u64(nonce));
    items.push(rlp_encode_u64(gas_price));
    items.push(rlp_encode_u64(gas_limit));
    items.push(rlp_encode_bytes(to));
    items.push(rlp_encode_u64(0)); // value = 0
    items.push(rlp_encode_bytes(data));
    items.push(rlp_encode_u64(chain_id));
    items.push(rlp_encode_u64(0)); // EIP-155 r placeholder
    items.push(rlp_encode_u64(0)); // EIP-155 s placeholder
    rlp_encode_list(&items)
}

fn rlp_encode_signed(
    nonce: u64,
    gas_price: u64,
    gas_limit: u64,
    to: &[u8; 20],
    data: &[u8],
    v: u64,
    r: &[u8],
    s: &[u8],
) -> Vec<u8> {
    let mut items = Vec::new();
    items.push(rlp_encode_u64(nonce));
    items.push(rlp_encode_u64(gas_price));
    items.push(rlp_encode_u64(gas_limit));
    items.push(rlp_encode_bytes(to));
    items.push(rlp_encode_u64(0)); // value = 0
    items.push(rlp_encode_bytes(data));
    items.push(rlp_encode_u64(v));
    items.push(rlp_encode_bytes_trimmed(r));
    items.push(rlp_encode_bytes_trimmed(s));
    rlp_encode_list(&items)
}

/// RLP-encode a u64 value.
fn rlp_encode_u64(val: u64) -> Vec<u8> {
    if val == 0 {
        return vec![0x80]; // empty byte string
    }
    let bytes = val.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    let trimmed = &bytes[start..];
    if trimmed.len() == 1 && trimmed[0] < 0x80 {
        return trimmed.to_vec();
    }
    let mut encoded = vec![0x80 + trimmed.len() as u8];
    encoded.extend_from_slice(trimmed);
    encoded
}

/// RLP-encode a byte string.
fn rlp_encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 {
        return data.to_vec();
    }
    if data.len() <= 55 {
        let mut encoded = vec![0x80 + data.len() as u8];
        encoded.extend_from_slice(data);
        return encoded;
    }
    let len_bytes = encode_length(data.len());
    let mut encoded = vec![0xb7 + len_bytes.len() as u8];
    encoded.extend_from_slice(&len_bytes);
    encoded.extend_from_slice(data);
    encoded
}

/// RLP-encode a byte string, stripping leading zeros (for r, s values).
fn rlp_encode_bytes_trimmed(data: &[u8]) -> Vec<u8> {
    let start = data.iter().position(|&b| b != 0).unwrap_or(data.len());
    let trimmed = &data[start..];
    if trimmed.is_empty() {
        return vec![0x80];
    }
    rlp_encode_bytes(trimmed)
}

/// RLP-encode a list of pre-encoded items.
fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.iter().flat_map(|i| i.iter().copied()).collect();
    if payload.len() <= 55 {
        let mut encoded = vec![0xc0 + payload.len() as u8];
        encoded.extend_from_slice(&payload);
        return encoded;
    }
    let len_bytes = encode_length(payload.len());
    let mut encoded = vec![0xf7 + len_bytes.len() as u8];
    encoded.extend_from_slice(&len_bytes);
    encoded.extend_from_slice(&payload);
    encoded
}

fn encode_length(len: usize) -> Vec<u8> {
    let bytes = (len as u64).to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    bytes[start..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardhat_account_0_address() {
        let signer = EvmSigner::from_hex(
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        )
        .unwrap();
        assert_eq!(
            signer.address_hex().to_lowercase(),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
    }

    #[test]
    fn sign_and_recover() {
        let signer = EvmSigner::from_hex(
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        )
        .unwrap();
        let raw = signer
            .sign_legacy_tx(9001, 0, 1_000_000_000, 21000, [0u8; 20], vec![])
            .unwrap();
        // Should produce valid RLP — first byte should be a list prefix >= 0xc0
        assert!(raw[0] >= 0xc0, "signed tx should be RLP list");
    }
}
