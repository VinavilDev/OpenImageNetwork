pub mod crypto;
pub mod pqc;
pub mod chunk;
pub mod erasure;
pub mod manifest;
pub mod link;
pub mod storage;
pub mod error;

pub use error::{OinError, Result};

pub const MAGIC_BYTES: [u8; 4] = [0x4F, 0x49, 0x4E, 0x43];
pub const PROTOCOL_VERSION: (u8, u8) = (0, 1);
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;
pub const DEFAULT_DATA_SHARDS: usize = 4;
pub const DEFAULT_PARITY_SHARDS: usize = 2;
