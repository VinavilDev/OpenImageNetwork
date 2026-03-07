use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::chunk::ChunkId;
use crate::crypto::{self, SealedBlock, DataKey};
use crate::erasure::ErasureConfig;
use crate::error::{OinError, Result};

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

pub type ImageId = String;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChunkLocation {
    pub chunk_id: ChunkId,
    pub index: u32,
    pub is_parity: bool,
    pub node_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImagePermissions {
    pub expires_at: Option<DateTime<Utc>>,
    pub max_views: Option<u64>,
    pub view_count: u64,
    pub passphrase_protected: bool,
    pub passphrase_salt: Option<[u8; 16]>,
    pub deleted: bool,
    pub persistence: PersistenceMode,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum PersistenceMode {
    Standard,
    Permanent,
}

impl Default for ImagePermissions {
    fn default() -> Self {
        Self {
            expires_at: None,
            max_views: None,
            view_count: 0,
            passphrase_protected: false,
            passphrase_salt: None,
            deleted: false,
            persistence: PersistenceMode::Standard,
        }
    }
}

impl ImagePermissions {
    pub fn check_access(&self) -> Result<()> {
        if self.deleted {
            return Err(OinError::Deleted);
        }
        if let Some(expires_at) = self.expires_at {
            if Utc::now() > expires_at {
                return Err(OinError::Expired(expires_at.to_rfc3339()));
            }
        }
        if let Some(max_views) = self.max_views {
            if self.view_count >= max_views {
                return Err(OinError::ViewLimitExceeded {
                    current: self.view_count,
                    max: max_views,
                });
            }
        }
        if self.passphrase_protected {
            return Err(OinError::PasswordRequired);
        }
        Ok(())
    }

    pub fn set_expiry(&mut self, duration: chrono::Duration) {
        self.expires_at = Some(Utc::now() + duration);
    }

    pub fn set_max_views(&mut self, max: u64) {
        self.max_views = Some(max);
    }

    pub fn record_view(&mut self) -> bool {
        self.view_count += 1;
        match self.max_views {
            Some(max) => self.view_count <= max,
            None => true,
        }
    }

    pub fn set_passphrase(&mut self, salt: [u8; 16]) {
        self.passphrase_protected = true;
        self.passphrase_salt = Some(salt);
    }

    pub fn delete(&mut self) {
        self.deleted = true;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub image_id: ImageId,
    pub original_hash: [u8; 32],
    pub original_size: u64,
    pub mime_type: String,
    pub filename: Option<String>,
    pub chunk_size: usize,
    pub data_shards: usize,
    pub parity_shards: usize,
    pub last_shard_original_len: usize,
    pub chunks: Vec<ChunkLocation>,
    pub image_key: DataKey,
    pub permissions: ImagePermissions,
    pub control_token: String,
    pub created_at: DateTime<Utc>,
    pub protocol_version: (u8, u8),
}

impl Manifest {
    pub fn new(
        original_data: &[u8],
        mime_type: &str,
        filename: Option<String>,
        chunk_size: usize,
        erasure_config: &ErasureConfig,
    ) -> Self {
        Self {
            image_id: random_hex(6),
            original_hash: crypto::sha256(original_data),
            original_size: original_data.len() as u64,
            mime_type: mime_type.to_string(),
            filename,
            chunk_size,
            data_shards: erasure_config.data_shards,
            parity_shards: erasure_config.parity_shards,
            last_shard_original_len: 0,
            chunks: Vec::new(),
            image_key: DataKey::generate(),
            permissions: ImagePermissions::default(),
            control_token: random_hex(16),
            created_at: Utc::now(),
            protocol_version: crate::PROTOCOL_VERSION,
        }
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(self)
            .map_err(|e| OinError::Serialization(e.to_string()))
    }

    pub fn from_json(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data)
            .map_err(|e| OinError::Serialization(e.to_string()))
    }

    pub fn encrypt(&self, key: &DataKey) -> Result<SealedBlock> {
        let json = self.to_json()?;
        crypto::encrypt(key, &json)
    }

    pub fn decrypt(key: &DataKey, enc: &SealedBlock) -> Result<Self> {
        let json = crypto::decrypt(key, enc)?;
        Self::from_json(&json)
    }

    pub fn encrypt_with_passphrase(&mut self, passphrase: &str) -> Result<SealedBlock> {
        let salt = crypto::generate_salt();
        self.permissions.set_passphrase(salt);

        let pw_key = DataKey::from_passphrase(passphrase, &salt)?;
        let json = self.to_json()?;
        crypto::encrypt(&pw_key, &json)
    }

    pub fn decrypt_with_passphrase(
        passphrase: &str,
        salt: &[u8; 16],
        enc: &SealedBlock,
    ) -> Result<Self> {
        let pw_key = DataKey::from_passphrase(passphrase, salt)?;
        let json = crypto::decrypt(&pw_key, enc)
            .map_err(|_| OinError::InvalidPassword)?;
        Self::from_json(&json)
    }

    pub fn verify_integrity(&self, data: &[u8]) -> bool {
        crypto::sha256(data) == self.original_hash
    }

    pub fn total_chunks(&self) -> usize {
        self.chunks.len()
    }

    pub fn data_chunks(&self) -> Vec<&ChunkLocation> {
        self.chunks.iter().filter(|c| !c.is_parity).collect()
    }

    pub fn parity_chunks(&self) -> Vec<&ChunkLocation> {
        self.chunks.iter().filter(|c| c.is_parity).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_json_roundtrip() {
        let data = vec![42u8; 1024];
        let config = ErasureConfig::default();
        let manifest = Manifest::new(&data, "image/png", Some("test.png".into()), 1024, &config);

        let json = manifest.to_json().unwrap();
        let parsed = Manifest::from_json(&json).unwrap();

        assert_eq!(parsed.image_id, manifest.image_id);
        assert_eq!(parsed.original_size, 1024);
        assert_eq!(parsed.mime_type, "image/png");
    }

    #[test]
    fn manifest_encrypt_decrypt() {
        let data = vec![42u8; 2048];
        let config = ErasureConfig::default();
        let manifest = Manifest::new(&data, "image/jpeg", None, 1024, &config);

        let key = DataKey::generate();
        let encrypted = manifest.encrypt(&key).unwrap();
        let decrypted = Manifest::decrypt(&key, &encrypted).unwrap();

        assert_eq!(decrypted.image_id, manifest.image_id);
        assert_eq!(decrypted.original_hash, manifest.original_hash);
    }

    #[test]
    fn permissions_expiry() {
        let mut perms = ImagePermissions::default();
        perms.set_expiry(chrono::Duration::hours(1));
        assert!(perms.check_access().is_ok());

        perms.expires_at = Some(Utc::now() - chrono::Duration::hours(1));
        assert!(perms.check_access().is_err());
    }

    #[test]
    fn permissions_view_limit() {
        let mut perms = ImagePermissions::default();
        perms.set_max_views(3);

        assert!(perms.record_view());
        assert!(perms.record_view());
        assert!(perms.record_view());
        assert!(!perms.record_view());
    }

    #[test]
    fn permissions_delete() {
        let mut perms = ImagePermissions::default();
        assert!(perms.check_access().is_ok());
        perms.delete();
        assert!(perms.check_access().is_err());
    }

    #[test]
    fn integrity_check() {
        let data = vec![1u8; 4096];
        let config = ErasureConfig::default();
        let manifest = Manifest::new(&data, "image/png", None, 1024, &config);

        assert!(manifest.verify_integrity(&data));
        assert!(!manifest.verify_integrity(&vec![2u8; 4096]));
    }
}
