use serde::{Deserialize, Serialize};

use crate::crypto::{self, SealedBlock, DataKey, NONCE_LEN, TAG_LEN};
use crate::error::{OinError, Result};
use crate::{MAGIC_BYTES, PROTOCOL_VERSION};

pub const HEADER_SIZE: usize = 4 + 2 + 32 + NONCE_LEN + TAG_LEN + 4;
pub const CRC_SIZE: usize = 4;

pub type ChunkId = [u8; 32];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Chunk {
    pub id: ChunkId,
    pub nonce: [u8; NONCE_LEN],
    pub auth_tag: [u8; TAG_LEN],
    pub data: Vec<u8>,
    pub index: u32,
    pub is_parity: bool,
}

impl Chunk {
    pub fn to_bytes(&self) -> Vec<u8> {
        let data_len = self.data.len() as u32;
        let total = HEADER_SIZE + self.data.len() + CRC_SIZE;
        let mut buf = Vec::with_capacity(total);

        buf.extend_from_slice(&MAGIC_BYTES);
        buf.push(PROTOCOL_VERSION.0);
        buf.push(PROTOCOL_VERSION.1);
        buf.extend_from_slice(&self.id);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.auth_tag);
        buf.extend_from_slice(&data_len.to_be_bytes());
        buf.extend_from_slice(&self.data);

        let crc = crc32fast::hash(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());

        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE + CRC_SIZE {
            return Err(OinError::ChunkFormat("data too short".into()));
        }

        let mut pos = 0;

        if &data[pos..pos + 4] != &MAGIC_BYTES {
            return Err(OinError::ChunkFormat(format!(
                "invalid magic: {:?}", &data[pos..pos + 4]
            )));
        }
        pos += 4;

        let _major = data[pos];
        let _minor = data[pos + 1];
        pos += 2;

        let mut id = [0u8; 32];
        id.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&data[pos..pos + NONCE_LEN]);
        pos += NONCE_LEN;

        let mut auth_tag = [0u8; TAG_LEN];
        auth_tag.copy_from_slice(&data[pos..pos + TAG_LEN]);
        pos += TAG_LEN;

        let data_len =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if data.len() < pos + data_len + CRC_SIZE {
            return Err(OinError::ChunkFormat("truncated data".into()));
        }

        let chunk_data = data[pos..pos + data_len].to_vec();
        pos += data_len;

        let expected_crc =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        let actual_crc = crc32fast::hash(&data[..pos]);

        if expected_crc != actual_crc {
            return Err(OinError::ChunkIntegrity {
                expected: expected_crc,
                actual: actual_crc,
            });
        }

        Ok(Chunk {
            id,
            nonce,
            auth_tag,
            data: chunk_data,
            index: 0,
            is_parity: false,
        })
    }

    pub fn data_size(&self) -> usize {
        self.data.len()
    }

    pub fn wire_size(&self) -> usize {
        HEADER_SIZE + self.data.len() + CRC_SIZE
    }
}

pub fn split_data(data: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
    data.chunks(chunk_size).map(|c| c.to_vec()).collect()
}

pub fn seal_chunk(
    image_key: &DataKey,
    piece: &[u8],
    chunk_index: u32,
    is_parity: bool,
) -> Result<Chunk> {
    let chunk_key = image_key.derive(format!("oin:chunk:{}", chunk_index).as_bytes());
    let encrypted = crypto::encrypt(&chunk_key, piece)?;
    let id = crypto::sha256(&encrypted.ciphertext);

    Ok(Chunk {
        id,
        nonce: encrypted.nonce,
        auth_tag: encrypted.auth_tag(),
        data: encrypted.ciphertext,
        index: chunk_index,
        is_parity,
    })
}

pub fn unseal_chunk(image_key: &DataKey, chunk: &Chunk) -> Result<Vec<u8>> {
    let chunk_key = image_key.derive(format!("oin:chunk:{}", chunk.index).as_bytes());

    let enc_data = SealedBlock {
        nonce: chunk.nonce,
        ciphertext: chunk.data.clone(),
    };

    crypto::decrypt(&chunk_key, &enc_data)
}

pub fn chunk_and_encrypt(
    image_key: &DataKey,
    data: &[u8],
    chunk_size: usize,
) -> Result<Vec<Chunk>> {
    let pieces = split_data(data, chunk_size);
    let mut chunks = Vec::with_capacity(pieces.len());

    for (i, piece) in pieces.iter().enumerate() {
        chunks.push(seal_chunk(image_key, piece, i as u32, false)?);
    }

    Ok(chunks)
}

pub fn decrypt_and_reassemble(
    image_key: &DataKey,
    chunks: &mut [Chunk],
) -> Result<Vec<u8>> {
    chunks.sort_by_key(|c| c.index);

    let mut data = Vec::new();
    for chunk in chunks.iter().filter(|c| !c.is_parity) {
        data.extend_from_slice(&unseal_chunk(image_key, chunk)?);
    }

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_roundtrip() {
        let key = DataKey::generate();
        let data = b"Hello, this is test image data for OIN!";

        let chunk = seal_chunk(&key, data, 0, false).unwrap();
        let decrypted = unseal_chunk(&key, &chunk).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn binary_format_roundtrip() {
        let key = DataKey::generate();
        let chunk = seal_chunk(&key, &vec![42u8; 1024], 5, false).unwrap();
        let bytes = chunk.to_bytes();
        let parsed = Chunk::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.id, chunk.id);
        assert_eq!(parsed.nonce, chunk.nonce);
        assert_eq!(parsed.auth_tag, chunk.auth_tag);
        assert_eq!(parsed.data, chunk.data);
    }

    #[test]
    fn corrupted_chunk_fails_crc() {
        let key = DataKey::generate();
        let chunk = seal_chunk(&key, b"data", 0, false).unwrap();
        let mut bytes = chunk.to_bytes();

        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        assert!(Chunk::from_bytes(&bytes).is_err());
    }

    #[test]
    fn split_and_reassemble() {
        let key = DataKey::generate();
        let mut data = vec![0u8; 3584];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut data);

        let mut chunks = chunk_and_encrypt(&key, &data, 1024).unwrap();
        assert_eq!(chunks.len(), 4);

        let reassembled = decrypt_and_reassemble(&key, &mut chunks).unwrap();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn chunk_wire_size() {
        let key = DataKey::generate();
        let chunk = seal_chunk(&key, &vec![0u8; 512], 0, false).unwrap();
        let bytes = chunk.to_bytes();
        assert_eq!(bytes.len(), HEADER_SIZE + chunk.data.len() + CRC_SIZE);
    }
}

pub fn chunk_id_to_hex(id: &ChunkId) -> String {
    id.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn hex_to_chunk_id(hex: &str) -> std::result::Result<ChunkId, ()> {
    if hex.len() != 64 { return Err(()); }
    let mut id = [0u8; 32];
    for i in 0..32 { id[i] = u8::from_str_radix(&hex[i*2..i*2+2], 16).map_err(|_| ())?; }
    Ok(id)
}
