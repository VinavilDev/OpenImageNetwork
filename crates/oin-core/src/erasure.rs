use reed_solomon_erasure::galois_8::ReedSolomon;

use crate::error::{OinError, Result};
use crate::{DEFAULT_DATA_SHARDS, DEFAULT_PARITY_SHARDS};

#[derive(Clone, Debug)]
pub struct ErasureConfig {
    pub data_shards: usize,
    pub parity_shards: usize,
}

impl Default for ErasureConfig {
    fn default() -> Self {
        Self {
            data_shards: DEFAULT_DATA_SHARDS,
            parity_shards: DEFAULT_PARITY_SHARDS,
        }
    }
}

impl ErasureConfig {
    pub fn new(data_shards: usize, parity_shards: usize) -> Self {
        Self { data_shards, parity_shards }
    }

    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }
}

pub fn encode(config: &ErasureConfig, data: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    if data.len() != config.data_shards {
        return Err(OinError::ErasureCoding(format!(
            "expected {} data shards, got {}", config.data_shards, data.len()
        )));
    }

    if data.is_empty() {
        return Err(OinError::ErasureCoding("no data shards".into()));
    }

    let shard_len = data[0].len();
    for (i, shard) in data.iter().enumerate() {
        if shard.len() != shard_len {
            return Err(OinError::ErasureCoding(format!(
                "shard {} has length {}, expected {}", i, shard.len(), shard_len
            )));
        }
    }

    let rs = ReedSolomon::new(config.data_shards, config.parity_shards)
        .map_err(|e| OinError::ErasureCoding(format!("init: {}", e)))?;

    let mut shards: Vec<Vec<u8>> = data.to_vec();
    for _ in 0..config.parity_shards {
        shards.push(vec![0u8; shard_len]);
    }

    rs.encode(&mut shards)
        .map_err(|e| OinError::ErasureCoding(format!("encode: {}", e)))?;

    Ok(shards[config.data_shards..].to_vec())
}

pub fn reconstruct(
    config: &ErasureConfig,
    shards: &mut Vec<Option<Vec<u8>>>,
) -> Result<Vec<Vec<u8>>> {
    let present = shards.iter().filter(|s| s.is_some()).count();
    if present < config.data_shards {
        return Err(OinError::InsufficientShards {
            have: present,
            need: config.data_shards,
        });
    }

    let rs = ReedSolomon::new(config.data_shards, config.parity_shards)
        .map_err(|e| OinError::ErasureCoding(format!("init: {}", e)))?;

    rs.reconstruct(shards)
        .map_err(|e| OinError::ErasureCoding(format!("reconstruct: {}", e)))?;

    Ok(shards[..config.data_shards]
        .iter()
        .map(|s| s.as_ref().unwrap().clone())
        .collect())
}

pub fn pad_shards(shards: &mut Vec<Vec<u8>>) -> usize {
    if shards.is_empty() {
        return 0;
    }

    let max_len = shards.iter().map(|s| s.len()).max().unwrap_or(0);
    let last_original_len = shards.last().map(|s| s.len()).unwrap_or(0);

    for shard in shards.iter_mut() {
        shard.resize(max_len, 0);
    }

    last_original_len
}

pub fn unpad_last_shard(shards: &mut Vec<Vec<u8>>, original_last_len: usize) {
    if let Some(last) = shards.last_mut() {
        last.truncate(original_last_len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let config = ErasureConfig::new(4, 2);
        let data: Vec<Vec<u8>> = (0..4).map(|i| vec![i as u8; 1024]).collect();

        let parity = encode(&config, &data).unwrap();
        assert_eq!(parity.len(), 2);

        let mut shards: Vec<Option<Vec<u8>>> = data
            .iter().chain(parity.iter())
            .map(|s| Some(s.clone()))
            .collect();
        shards[0] = None;
        shards[2] = None;

        let reconstructed = reconstruct(&config, &mut shards).unwrap();
        assert_eq!(reconstructed, data);
    }

    #[test]
    fn too_many_missing_fails() {
        let config = ErasureConfig::new(4, 2);
        let data: Vec<Vec<u8>> = (0..4).map(|i| vec![i as u8; 512]).collect();
        let parity = encode(&config, &data).unwrap();

        let mut shards: Vec<Option<Vec<u8>>> = data
            .iter().chain(parity.iter())
            .map(|s| Some(s.clone()))
            .collect();
        shards[0] = None;
        shards[1] = None;
        shards[2] = None;

        assert!(reconstruct(&config, &mut shards).is_err());
    }

    #[test]
    fn pad_unpad() {
        let mut shards = vec![
            vec![1u8; 1024],
            vec![2u8; 1024],
            vec![3u8; 512],
        ];

        let original_last = pad_shards(&mut shards);
        assert_eq!(original_last, 512);
        assert!(shards.iter().all(|s| s.len() == 1024));

        unpad_last_shard(&mut shards, original_last);
        assert_eq!(shards[2].len(), 512);
    }
}
