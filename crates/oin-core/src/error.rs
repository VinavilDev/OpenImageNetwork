use thiserror::Error;

#[derive(Error, Debug)]
pub enum OinError {
    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Invalid chunk format: {0}")]
    ChunkFormat(String),

    #[error("Chunk integrity check failed: expected CRC {expected:#010x}, got {actual:#010x}")]
    ChunkIntegrity { expected: u32, actual: u32 },

    #[error("Erasure coding failed: {0}")]
    ErasureCoding(String),

    #[error("Manifest error: {0}")]
    Manifest(String),

    #[error("Link encoding error: {0}")]
    LinkEncoding(String),

    #[error("Image expired at {0}")]
    Expired(String),

    #[error("View limit exceeded: {current}/{max}")]
    ViewLimitExceeded { current: u64, max: u64 },

    #[error("Password required")]
    PasswordRequired,

    #[error("Invalid credentials")]
    InvalidPassword,

    #[error("Image has been deleted")]
    Deleted,

    #[error("Insufficient data shards: have {have}, need {need}")]
    InsufficientShards { have: usize, need: usize },

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Storage error: {0}")]
    Storage(String),
}

pub type Result<T> = std::result::Result<T, OinError>;
