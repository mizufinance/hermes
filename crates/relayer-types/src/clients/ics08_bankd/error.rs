use flex_error::{define_error, TraceError};

use crate::core::ics02_client::error::Error as Ics02Error;
use crate::Height;

define_error! {
    #[derive(Debug, PartialEq, Eq)]
    Error {
        InvalidRawClientState
            { reason: String }
            |e| { format_args!("invalid raw bankd client state: {}", e.reason) },

        InvalidRawConsensusState
            { reason: String }
            |e| { format_args!("invalid raw bankd consensus state: {}", e.reason) },

        InvalidRawHeader
            { reason: String }
            |e| { format_args!("invalid raw bankd header: {}", e.reason) },

        Decode
            [ TraceError<prost::DecodeError> ]
            |_| { "decode error" },

        MissingLatestHeight
            |_| { "missing latest height" },

        MissingTimestamp
            |_| { "missing timestamp" },

        InvalidGroupPublicKey
            { length: usize }
            |e| { format_args!("invalid BLS group public key length: expected 96 bytes, got {}", e.length) },

        InvalidThresholdSignature
            { length: usize }
            |e| { format_args!("invalid BLS threshold signature length: expected 48 bytes, got {}", e.length) },

        InsufficientHeight
            {
                latest_height: Height,
                target_height: Height,
            }
            |e| {
                format_args!("the height is insufficient: latest_height={0} target_height={1}", e.latest_height, e.target_height)
            },

        ClientFrozen
            {
                frozen_height: Height,
                target_height: Height,
            }
            |e| {
                format_args!("the client is frozen: frozen_height={0} target_height={1}", e.frozen_height, e.target_height)
            },
    }
}

impl From<Error> for Ics02Error {
    fn from(e: Error) -> Self {
        Self::client_specific(e.to_string())
    }
}
