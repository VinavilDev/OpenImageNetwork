use std::fs;
use std::path::{Path, PathBuf};

use crate::chunk::{Chunk, ChunkId};
use crate::error::{OinError, Result};

pub struct LocalStore {
    root: PathBuf,
}

impl LocalStore {
    pub fn new(root: &Path) -> Result<Self> {
        let chunks_dir = root.join("chunks");
        let manifests_dir = root.join("manifests");

        fs::create_dir_all(&chunks_dir)?;
        fs::create_dir_all(&manifests_dir)?;

        Ok(Self { root: root.to_path_buf() })
    }

    pub fn default_path() -> PathBuf {
        dirs_fallback()
    }

    fn chunk_path(&self, id: &ChunkId) -> PathBuf {
        let hex: String = id.iter().map(|b| format!("{:02x}", b)).collect();
        self.root.join("chunks").join(hex)
    }

    pub fn store_chunk(&self, chunk: &Chunk) -> Result<()> {
        let path = self.chunk_path(&chunk.id);
        let bytes = chunk.to_bytes();
        fs::write(&path, &bytes)?;
        Ok(())
    }

    pub fn load_chunk(&self, id: &ChunkId) -> Result<Chunk> {
        let path = self.chunk_path(id);
        if !path.exists() {
            return Err(OinError::ChunkFormat(format!(
                "chunk not found: {}", crate::chunk::chunk_id_to_hex(id)
            )));
        }
        let bytes = fs::read(&path)?;
        Chunk::from_bytes(&bytes)
    }

    pub fn delete_chunk(&self, id: &ChunkId) -> Result<()> {
        let path = self.chunk_path(id);
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }

    pub fn has_chunk(&self, id: &ChunkId) -> bool {
        self.chunk_path(id).exists()
    }

    pub fn chunk_count(&self) -> usize {
        let dir = self.root.join("chunks");
        fs::read_dir(dir).map(|d| d.count()).unwrap_or(0)
    }

    fn manifest_path(&self, image_id: &str) -> PathBuf {
        let sanitized: String = image_id.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(24)
            .collect();
        if sanitized.is_empty() || sanitized != image_id {
            return self.root.join("manifests").join("_invalid_.enc");
        }
        self.root.join("manifests").join(format!("{}.enc", sanitized))
    }

    pub fn store_manifest(&self, image_id: &str, encrypted_data: &[u8]) -> Result<()> {
        let path = self.manifest_path(image_id);
        fs::write(&path, encrypted_data)?;
        Ok(())
    }

    pub fn load_manifest(&self, image_id: &str) -> Result<Vec<u8>> {
        let path = self.manifest_path(image_id);
        if !path.exists() {
            return Err(OinError::Manifest(format!(
                "manifest not found: {}", image_id
            )));
        }
        Ok(fs::read(&path)?)
    }

    pub fn delete_manifest(&self, image_id: &str) -> Result<()> {
        let path = self.manifest_path(image_id);
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }

    pub fn has_manifest(&self, image_id: &str) -> bool {
        self.manifest_path(image_id).exists()
    }

    pub fn list_manifests(&self) -> Result<Vec<String>> {
        let dir = self.root.join("manifests");
        let mut ids = Vec::new();
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.filter_map(|e| e.ok()) {
                if let Some(name) = entry.file_name().to_str() {
                    if let Some(id) = name.strip_suffix(".enc") {
                        ids.push(id.to_string());
                    }
                }
            }
        }
        Ok(ids)
    }

    pub fn list_chunks(&self) -> Result<Vec<String>> {
        let dir = self.root.join("chunks");
        let mut ids = Vec::new();
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.filter_map(|e| e.ok()) {
                if let Some(name) = entry.file_name().to_str() {
                    ids.push(name.to_string());
                }
            }
        }
        Ok(ids)
    }

    pub fn disk_usage(&self) -> u64 {
        let dir = self.root.join("chunks");
        fs::read_dir(dir)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter_map(|e| e.metadata().ok())
                    .map(|m| m.len())
                    .sum()
            })
            .unwrap_or(0)
    }
}

#[cfg(target_os = "windows")]
fn dirs_fallback() -> PathBuf {
    return PathBuf::from(
        std::env::var_os("USERPROFILE")
        .expect("%USERPROFILE% is not set!")
    ).join(".oin");
}

#[cfg(target_os = "macos")]
fn dirs_fallback() -> PathBuf {
    return PathBuf::from(
        std::env::var_os("HOME")
        .expect("$HOME is not set!")
    ).join(".oin");
}

#[cfg(target_os = "linux")]
fn dirs_fallback() -> PathBuf {

    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(xdg).join("oin");
    }
    else if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".local/share/oin");
    }
    else {
        panic!("both $XDG_DATA_DIR and $HOME are unset!");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::seal_chunk;
    use crate::crypto::DataKey;
    use std::sync::atomic::{AtomicU32, Ordering};

    static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

    fn temp_store() -> (LocalStore, PathBuf) {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("oin_test_st_{}", id));
        let _ = std::fs::remove_dir_all(&dir);
        let store = LocalStore::new(&dir).unwrap();
        (store, dir)
    }

    #[test]
    fn store_and_load_chunk() {
        let (store, dir) = temp_store();
        let key = DataKey::generate();
        let chunk = seal_chunk(&key, b"test data", 0, false).unwrap();

        store.store_chunk(&chunk).unwrap();
        assert!(store.has_chunk(&chunk.id));

        let loaded = store.load_chunk(&chunk.id).unwrap();
        assert_eq!(loaded.data, chunk.data);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_chunk() {
        let (store, dir) = temp_store();
        let key = DataKey::generate();
        let chunk = seal_chunk(&key, b"delete me", 0, false).unwrap();

        store.store_chunk(&chunk).unwrap();
        store.delete_chunk(&chunk.id).unwrap();
        assert!(!store.has_chunk(&chunk.id));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn store_and_load_manifest() {
        let (store, dir) = temp_store();
        store.store_manifest("abc123", b"encrypted manifest blob").unwrap();
        assert!(store.has_manifest("abc123"));

        let loaded = store.load_manifest("abc123").unwrap();
        assert_eq!(loaded, b"encrypted manifest blob");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
