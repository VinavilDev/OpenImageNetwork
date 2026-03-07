use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::{OinError, Result};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

#[derive(Clone, Serialize, Deserialize)]
pub struct DataKey(pub [u8; KEY_LEN]);

impl DataKey {
    pub fn generate() -> Self {
        let mut key = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut key);
        DataKey(key)
    }

    pub fn derive(&self, info: &[u8]) -> Self {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut okm = [0u8; KEY_LEN];
        hk.expand(info, &mut okm)
            .expect("HKDF expand should not fail with 32-byte output");
        DataKey(okm)
    }
    pub fn from_passphrase(passphrase: &str, salt: &[u8; 16]) -> Result<Self> {
        let mut ikm = Vec::with_capacity(passphrase.len() + salt.len());
        ikm.extend_from_slice(passphrase.as_bytes());
        ikm.extend_from_slice(salt);

        let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
        let mut okm = [0u8; KEY_LEN];
        hk.expand(b"oin:passphrase-key", &mut okm)
            .expect("HKDF expand should not fail with 32-byte output");

        Ok(DataKey(okm))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DataKey([REDACTED])")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedBlock {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl SealedBlock {
    pub fn auth_tag(&self) -> [u8; TAG_LEN] {
        let len = self.ciphertext.len();
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&self.ciphertext[len - TAG_LEN..]);
        tag
    }

    pub fn ciphertext_without_tag(&self) -> &[u8] {
        &self.ciphertext[..self.ciphertext.len() - TAG_LEN]
    }

    pub fn total_size(&self) -> usize {
        NONCE_LEN + self.ciphertext.len()
    }
}

pub fn encrypt(key: &DataKey, plaintext: &[u8]) -> Result<SealedBlock> {
    let cipher = Aes256Gcm::new_from_slice(&key.0)
        .map_err(|e| OinError::Encryption(format!("init: {}", e)))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| OinError::Encryption(format!("seal: {}", e)))?;

    Ok(SealedBlock {
        nonce: nonce_bytes,
        ciphertext,
    })
}

pub fn decrypt(key: &DataKey, enc: &SealedBlock) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(&key.0)
        .map_err(|e| OinError::Decryption(format!("init: {}", e)))?;

    let nonce = Nonce::from_slice(&enc.nonce);

    cipher
        .decrypt(nonce, enc.ciphertext.as_ref())
        .map_err(|e| OinError::Decryption(format!("open: {}", e)))
}

pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = DataKey::generate();
        let plaintext = b"Hello, Open Image Network!";

        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = DataKey::generate();
        let key2 = DataKey::generate();

        let encrypted = encrypt(&key1, b"secret image data").unwrap();
        assert!(decrypt(&key2, &encrypted).is_err());
    }

    #[test]
    fn key_derivation_deterministic() {
        let master = DataKey::generate();
        let child1 = master.derive(b"image:abc123:chunk:0");
        let child2 = master.derive(b"image:abc123:chunk:0");
        assert_eq!(child1.0, child2.0);
    }

    #[test]
    fn key_derivation_different_info() {
        let master = DataKey::generate();
        let child1 = master.derive(b"chunk:0");
        let child2 = master.derive(b"chunk:1");
        assert_ne!(child1.0, child2.0);
    }

    #[test]
    fn passphrase_key_derivation() {
        let salt = generate_salt();
        let key1 = DataKey::from_passphrase("correct-horse-battery-staple", &salt).unwrap();
        let key2 = DataKey::from_passphrase("correct-horse-battery-staple", &salt).unwrap();
        let key3 = DataKey::from_passphrase("wrong-passphrase", &salt).unwrap();

        assert_eq!(key1.0, key2.0);
        assert_ne!(key1.0, key3.0);
    }

    #[test]
    fn large_data_roundtrip() {
        let key = DataKey::generate();
        let mut plaintext = vec![0u8; 2 * 1024 * 1024];
        OsRng.fill_bytes(&mut plaintext);

        let encrypted = encrypt(&key, &plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}

pub fn hmac_sha256(secret: &str, message: &str) -> String {
    use sha2::{Sha256, Digest};
    let k = secret.as_bytes();
    let mut block = [0u8; 64];
    if k.len() > 64 { block[..32].copy_from_slice(&Sha256::digest(k)); }
    else { block[..k.len()].copy_from_slice(k); }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 { ipad[i] ^= block[i]; opad[i] ^= block[i]; }
    let mut h = Sha256::new(); h.update(&ipad); h.update(message.as_bytes());
    let inner = h.finalize();
    let mut h = Sha256::new(); h.update(&opad); h.update(&inner);
    format!("{:x}", h.finalize())
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}
