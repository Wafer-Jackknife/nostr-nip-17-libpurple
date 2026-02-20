//! Error types for nostr-core

use thiserror::Error;

#[derive(Error, Debug)]
pub enum NostrError {
    #[error("Invalid argument: {0}")]
    InvalidArg(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Internal error: {0}")]
    Internal(String),
}
