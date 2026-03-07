
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use oin_core::chunk::{Chunk, ChunkId};
use oin_core::error::{OinError, Result as OinResult};
use oin_core::storage::LocalStore;
use serde::Serialize;
use tracing::{info, warn};

const DEFAULT_STORAGE_PCT: f64 = 3.5;

const MIN_ALLOCATION_BYTES: u64 = 64 * 1024 * 1024;

const DISK_SAFETY_MARGIN_BYTES: u64 = 1_073_741_824;

const MIN_TOTAL_ALLOCATION: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct DiskInfo {
    pub mount_point: PathBuf,
    pub fs_type: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
}

pub fn detect_disks() -> Vec<DiskInfo> {
    let mut disks: Vec<DiskInfo> = Vec::new();

    if let Ok(content) = std::fs::read_to_string("/proc/mounts") {
        let mut seen_devices: HashMap<String, usize> = HashMap::new();

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 { continue; }

            let device = parts[0];
            let mount = parts[1];
            let fs = parts[2];

            if !is_real_filesystem(fs, device, mount) { continue; }

            if let Some(&existing_idx) = seen_devices.get(device) {
                if mount.len() > disks[existing_idx].mount_point.to_str().unwrap_or("").len() {
                    if let Some(info) = query_disk_space(Path::new(mount), fs) {
                        disks[existing_idx] = info;
                    }
                }
                continue;
            }

            if let Some(info) = query_disk_space(Path::new(mount), fs) {
                if info.total_bytes < 100 * 1024 * 1024 { continue; }
                seen_devices.insert(device.to_string(), disks.len());
                disks.push(info);
            }
        }
    }

    #[cfg(target_os = "macos")]
    if disks.is_empty() {
        for mount in &["/", "/System/Volumes/Data"] {
            let p = Path::new(mount);
            if p.exists() {
                if let Some(info) = query_disk_space(p, "apfs") {
                    if info.total_bytes >= 100 * 1024 * 1024 {
                        let already = disks.iter().any(|d| d.total_bytes == info.total_bytes);
                        if !already { disks.push(info); }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    if disks.is_empty() {
        for letter in b'A'..=b'Z' {
            let drive = format!("{}:\\", letter as char);
            let path = Path::new(&drive);
            if path.exists() {
                if let Some(info) = query_disk_space(path, "ntfs") {
                    if info.total_bytes >= 100 * 1024 * 1024 {
                        disks.push(info);
                    }
                }
            }
        }
    }

    disks.sort_by(|a, b| a.mount_point.cmp(&b.mount_point));
    disks.dedup_by(|a, b| a.mount_point == b.mount_point);

    disks
}

fn is_real_filesystem(fs_type: &str, device: &str, mount: &str) -> bool {
    let real_fs = [
        "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs",
        "ntfs", "ntfs3", "vfat", "fat32", "exfat", "hfs", "hfsplus", "apfs",
        "jfs", "reiserfs", "ufs", "nilfs2", "bcachefs",
    ];

    if !real_fs.contains(&fs_type) { return false; }

    if !device.starts_with("/dev/") { return false; }

    let skip_mounts = ["/boot/efi", "/boot", "/snap", "/var/snap"];
    if skip_mounts.iter().any(|s| mount == *s) { return false; }

    if mount.starts_with("/proc") || mount.starts_with("/sys") || mount.starts_with("/run") {
        return false;
    }

    true
}

fn query_disk_space(mount: &Path, fs_type: &str) -> Option<DiskInfo> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        let c_path = CString::new(mount.to_str()?).ok()?;

        unsafe {
            let mut stat: libc::statvfs = std::mem::zeroed();
            if libc::statvfs(c_path.as_ptr(), &mut stat) != 0 {
                return None;
            }

            let block_size = stat.f_frsize as u64;
            let total = stat.f_blocks as u64 * block_size;
            let available = stat.f_bavail as u64 * block_size;

            Some(DiskInfo {
                mount_point: mount.to_path_buf(),
                fs_type: fs_type.to_string(),
                total_bytes: total,
                available_bytes: available,
            })
        }
    }

    #[cfg(not(unix))]
    {
        use std::ffi::CString;
        extern "system" {
            fn GetDiskFreeSpaceExA(
                path: *const u8,
                free_bytes_available: *mut u64,
                total_bytes: *mut u64,
                total_free_bytes: *mut u64,
            ) -> i32;
        }
        let c_path = CString::new(mount.to_str()?).ok()?;
        let mut free_avail: u64 = 0;
        let mut total: u64 = 0;
        let mut total_free: u64 = 0;
        unsafe {
            if GetDiskFreeSpaceExA(
                c_path.as_ptr() as *const u8,
                &mut free_avail,
                &mut total,
                &mut total_free,
            ) != 0 {
                Some(DiskInfo {
                    mount_point: mount.to_path_buf(),
                    fs_type: fs_type.to_string(),
                    total_bytes: total,
                    available_bytes: free_avail,
                })
            } else {
                None
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct StorageAllocation {
    pub mount_point: PathBuf,
    pub store_path: PathBuf,
    pub quota_bytes: u64,
    pub disk_available: u64,
}

#[derive(Debug)]
pub struct StoragePlan {
    pub total_system_bytes: u64,
    pub oin_allocation_bytes: u64,
    pub storage_pct: f64,
    pub allocations: Vec<StorageAllocation>,
}

#[derive(Debug)]
pub enum PlanError {
    NoDisksFound,
    InsufficientSpace {
        needed: u64,
        available: u64,
    },
    AllDisksFull,
    StoreCreationFailed(String),
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanError::NoDisksFound =>
                write!(f, "no usable disks detected on this system"),
            PlanError::InsufficientSpace { needed, available } =>
                write!(f, "insufficient disk space: need {} but only {} available across all disks",
                    fmt_bytes(*needed), fmt_bytes(*available)),
            PlanError::AllDisksFull =>
                write!(f, "all detected disks are full (less than {} free after safety margin)",
                    fmt_bytes(MIN_ALLOCATION_BYTES)),
            PlanError::StoreCreationFailed(msg) =>
                write!(f, "failed to create storage directory: {}", msg),
        }
    }
}

pub fn plan_storage(
    disks: &[DiskInfo],
    storage_pct: f64,
    node_id: &str,
) -> Result<StoragePlan, PlanError> {
    if disks.is_empty() {
        return Err(PlanError::NoDisksFound);
    }

    let total_system: u64 = disks.iter().map(|d| d.total_bytes).sum();
    let oin_total = ((total_system as f64) * (storage_pct / 100.0)) as u64;

    if oin_total < MIN_TOTAL_ALLOCATION {
        return Err(PlanError::InsufficientSpace {
            needed: MIN_TOTAL_ALLOCATION,
            available: total_system,
        });
    }

    let usable_disks: Vec<&DiskInfo> = disks.iter()
        .filter(|d| d.available_bytes > DISK_SAFETY_MARGIN_BYTES + MIN_ALLOCATION_BYTES)
        .collect();

    if usable_disks.is_empty() {
        return Err(PlanError::AllDisksFull);
    }

    let total_available: u64 = usable_disks.iter()
        .map(|d| d.available_bytes.saturating_sub(DISK_SAFETY_MARGIN_BYTES))
        .sum();

    if total_available < oin_total {
        return Err(PlanError::InsufficientSpace {
            needed: oin_total,
            available: total_available,
        });
    }

    let primary_mount: Option<PathBuf> = usable_disks.iter()
        .find(|d| is_home_disk(&d.mount_point))
        .map(|d| d.mount_point.clone());

    let mut allocations = Vec::new();
    let even_share = oin_total / usable_disks.len() as u64;
    let mut remaining = oin_total;

    let mut capped_disks = Vec::new();
    let mut uncapped_disks = Vec::new();
    let mut _capped_total = 0u64;

    for disk in &usable_disks {
        let max_for_disk = disk.available_bytes.saturating_sub(DISK_SAFETY_MARGIN_BYTES);
        if max_for_disk < even_share {
            capped_disks.push((*disk, max_for_disk));
            _capped_total += max_for_disk;
        } else {
            uncapped_disks.push(*disk);
        }
    }

    for (disk, max) in &capped_disks {
        let is_primary = primary_mount.as_ref() == Some(&disk.mount_point);
        let store_path = disk_store_path(&disk.mount_point, node_id, is_primary);
        allocations.push(StorageAllocation {
            mount_point: disk.mount_point.clone(),
            store_path,
            quota_bytes: *max,
            disk_available: disk.available_bytes,
        });
        remaining -= max;
    }

    if !uncapped_disks.is_empty() {
        let share = remaining / uncapped_disks.len() as u64;
        let mut leftover = remaining - (share * uncapped_disks.len() as u64);

        for (i, disk) in uncapped_disks.iter().enumerate() {
            let extra = if i == 0 { leftover } else { 0 };
            if i == 0 { leftover = 0; }

            let is_primary = primary_mount.as_ref() == Some(&disk.mount_point);
            let store_path = disk_store_path(&disk.mount_point, node_id, is_primary);
            allocations.push(StorageAllocation {
                mount_point: disk.mount_point.clone(),
                store_path,
                quota_bytes: share + extra,
                    disk_available: disk.available_bytes,
            });
        }
    }

    Ok(StoragePlan {
        total_system_bytes: total_system,
        oin_allocation_bytes: oin_total,
        storage_pct,
        allocations,
    })
}

fn disk_store_path(mount: &Path, node_id: &str, is_primary: bool) -> PathBuf {
    if is_primary {
        oin_core::storage::LocalStore::default_path()
    } else {
        let short_id = &node_id[..8.min(node_id.len())];
        mount.join(".oin-node").join(short_id)
    }
}

fn is_home_disk(mount: &Path) -> bool {
    let default = oin_core::storage::LocalStore::default_path();
    if let Ok(canonical_default) = std::fs::canonicalize(&default).or_else(|_| {
        default.parent().map(|p| p.to_path_buf()).ok_or(std::io::Error::new(
            std::io::ErrorKind::NotFound, "no parent"))
    }) {
        return canonical_default.starts_with(mount);
    }
    if let Some(home) = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
    {
        return PathBuf::from(home).starts_with(mount);
    }
    false
}

struct StoreSlot {
    store: LocalStore,
    quota_bytes: u64,
    mount_point: PathBuf,
}

pub struct MultiStore {
    stores: Vec<StoreSlot>,
    total_quota: u64,
}

impl MultiStore {
    pub fn from_plan(plan: &StoragePlan) -> Result<Self, PlanError> {
        let mut stores = Vec::new();
        let mut total_quota = 0u64;

        for alloc in &plan.allocations {
            match LocalStore::new(&alloc.store_path) {
                Ok(store) => {
                    info!("  disk {} - quota {} (available: {}) -> {}",
                        alloc.mount_point.display(),
                        fmt_bytes(alloc.quota_bytes),
                        fmt_bytes(alloc.disk_available),
                        alloc.store_path.display());
                    total_quota += alloc.quota_bytes;
                    stores.push(StoreSlot {
                        store,
                        quota_bytes: alloc.quota_bytes,
                        mount_point: alloc.mount_point.clone(),
                    });
                }
                Err(e) => {
                    warn!("failed to create store on {}: {} (skipping disk)",
                        alloc.mount_point.display(), e);
                }
            }
        }

        if stores.is_empty() {
            return Err(PlanError::StoreCreationFailed(
                "could not create storage on any disk".into()
            ));
        }

        Ok(Self {
            stores,
            total_quota,
        })
    }

    pub fn from_single_path(path: &Path, quota_bytes: u64) -> Result<Self, PlanError> {
        let store = LocalStore::new(path)
            .map_err(|e| PlanError::StoreCreationFailed(e.to_string()))?;

        Ok(Self {
            stores: vec![StoreSlot {
                store,
                quota_bytes,
                mount_point: path.to_path_buf(),
            }],
            total_quota: quota_bytes,
        })
    }

    pub fn total_quota(&self) -> u64 {
        self.total_quota
    }

    pub fn disk_usage(&self) -> u64 {
        self.stores.iter().map(|s| s.store.disk_usage()).sum()
    }

    pub fn chunk_count(&self) -> usize {
        self.stores.iter().map(|s| s.store.chunk_count()).sum()
    }

    pub fn has_capacity(&self, bytes: u64) -> bool {
        self.disk_usage() + bytes <= self.total_quota
    }

    pub fn verify_disk_health(&self) -> Vec<DiskHealthIssue> {
        let mut issues = Vec::new();
        for slot in &self.stores {
            if let Some(info) = query_disk_space(&slot.mount_point, "") {
                if info.available_bytes < DISK_SAFETY_MARGIN_BYTES {
                    issues.push(DiskHealthIssue {
                        mount: slot.mount_point.clone(),
                        issue: format!("critically low space: {} free",
                            fmt_bytes(info.available_bytes)),
                    });
                }
            } else {
                issues.push(DiskHealthIssue {
                    mount: slot.mount_point.clone(),
                    issue: "disk unreachable or unmounted".into(),
                });
            }
        }
        issues
    }

    fn pick_store_for_write(&self, size: u64) -> Option<usize> {
        let mut best_idx = None;
        let mut best_remaining = 0u64;

        for (i, slot) in self.stores.iter().enumerate() {
            let usage = slot.store.disk_usage();
            if usage + size > slot.quota_bytes { continue; }

            if let Some(info) = query_disk_space(&slot.mount_point, "") {
                if info.available_bytes < DISK_SAFETY_MARGIN_BYTES + size {
                    continue;
                }
            }

            let remaining = slot.quota_bytes.saturating_sub(usage);
            if remaining > best_remaining {
                best_remaining = remaining;
                best_idx = Some(i);
            }
        }

        best_idx
    }

    pub fn store_chunk(&self, chunk: &Chunk) -> OinResult<()> {
        let bytes = chunk.to_bytes();
        let size = bytes.len() as u64;

        let idx = self.pick_store_for_write(size)
            .ok_or_else(|| OinError::Storage(
                "all disks at capacity - cannot store chunk".into()
            ))?;

        self.stores[idx].store.store_chunk(chunk)
    }

    pub fn load_chunk(&self, id: &ChunkId) -> OinResult<Chunk> {
        for slot in &self.stores {
            if slot.store.has_chunk(id) {
                return slot.store.load_chunk(id);
            }
        }
        Err(OinError::ChunkFormat(format!(
            "chunk not found on any disk: {}", oin_core::chunk::chunk_id_to_hex(id)
        )))
    }

    pub fn has_chunk(&self, id: &ChunkId) -> bool {
        self.stores.iter().any(|s| s.store.has_chunk(id))
    }

    pub fn delete_chunk(&self, id: &ChunkId) -> OinResult<()> {
        for slot in &self.stores {
            if slot.store.has_chunk(id) {
                return slot.store.delete_chunk(id);
            }
        }
        Ok(())
    }

    pub fn store_manifest(&self, image_id: &str, data: &[u8]) -> OinResult<()> {
        let size = data.len() as u64;
        let idx = self.pick_store_for_write(size)
            .ok_or_else(|| OinError::Storage(
                "all disks at capacity - cannot store manifest".into()
            ))?;
        self.stores[idx].store.store_manifest(image_id, data)
    }

    pub fn load_manifest(&self, image_id: &str) -> OinResult<Vec<u8>> {
        for slot in &self.stores {
            if slot.store.has_manifest(image_id) {
                return slot.store.load_manifest(image_id);
            }
        }
        Err(OinError::Manifest(format!("manifest not found: {}", image_id)))
    }

    pub fn has_manifest(&self, image_id: &str) -> bool {
        self.stores.iter().any(|s| s.store.has_manifest(image_id))
    }

    pub fn delete_manifest(&self, image_id: &str) -> OinResult<()> {
        for slot in &self.stores {
            if slot.store.has_manifest(image_id) {
                return slot.store.delete_manifest(image_id);
            }
        }
        Ok(())
    }

    pub fn list_manifests(&self) -> OinResult<Vec<String>> {
        let mut all = Vec::new();
        for slot in &self.stores {
            if let Ok(ids) = slot.store.list_manifests() {
                all.extend(ids);
            }
        }
        all.sort();
        all.dedup();
        Ok(all)
    }

    pub fn summary(&self) -> String {
        let usage = self.disk_usage();
        let pct = if self.total_quota > 0 {
            (usage as f64 / self.total_quota as f64 * 100.0) as u64
        } else { 0 };
        format!("{} disks, {} / {} used ({}%)",
            self.stores.len(), fmt_bytes(usage), fmt_bytes(self.total_quota), pct)
    }

    pub fn per_disk_info(&self) -> Vec<DiskUsageInfo> {
        self.stores.iter().map(|s| DiskUsageInfo {
            mount: s.mount_point.display().to_string(),
            quota: s.quota_bytes,
            used: s.store.disk_usage(),
            chunks: s.store.chunk_count(),
        }).collect()
    }

    fn sanitize_map_id(image_id: &str) -> Option<String> {
        let clean: String = image_id.chars().filter(|c| c.is_ascii_alphanumeric()).take(24).collect();
        if clean.is_empty() || clean != image_id { None } else { Some(clean) }
    }

    pub fn store_chunk_map(&self, image_id: &str, chunk_ids: &[String]) {
        let id = match Self::sanitize_map_id(image_id) { Some(id) => id, None => return };
        if let Some(slot) = self.stores.first() {
            let dir = slot.mount_point.join(".oin-maps");
            let _ = std::fs::create_dir_all(&dir);
            let _ = std::fs::write(dir.join(format!("{}.map", id)), chunk_ids.join("\n"));
        }
    }

    pub fn load_chunk_map(&self, image_id: &str) -> Vec<String> {
        let id = match Self::sanitize_map_id(image_id) { Some(id) => id, None => return vec![] };
        for slot in &self.stores {
            let path = slot.mount_point.join(".oin-maps").join(format!("{}.map", id));
            if let Ok(data) = std::fs::read_to_string(&path) {
                return data.lines().filter(|l| !l.is_empty()).map(String::from).collect();
            }
        }
        vec![]
    }

    pub fn delete_chunk_map(&self, image_id: &str) {
        let id = match Self::sanitize_map_id(image_id) { Some(id) => id, None => return };
        for slot in &self.stores {
            let _ = std::fs::remove_file(slot.mount_point.join(".oin-maps").join(format!("{}.map", id)));
        }
    }
}

#[derive(Debug)]
pub struct DiskHealthIssue {
    pub mount: PathBuf,
    pub issue: String,
}

#[derive(Debug, Serialize)]
pub struct DiskUsageInfo {
    pub mount: String,
    pub quota: u64,
    pub used: u64,
    pub chunks: usize,
}

pub fn init_storage(
    explicit_path: Option<PathBuf>,
    node_id: &str,
) -> Result<MultiStore, PlanError> {
    let storage_pct: f64 = std::env::var("OIN_STORAGE_PCT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_STORAGE_PCT);

    if let Some(path) = explicit_path {
        info!("storage mode: single disk (OIN_STORE={})", path.display());

        let parent = find_mount_point(&path);
        let (total, available) = if let Some(info) = query_disk_space(&parent, "") {
            (info.total_bytes, info.available_bytes)
        } else {
            warn!("could not query disk space for {}, using 10GB default quota", path.display());
            (300_000_000_000, 100_000_000_000)
        };

        let quota = ((total as f64) * (storage_pct / 100.0)) as u64;

        if quota < MIN_ALLOCATION_BYTES {
            return Err(PlanError::InsufficientSpace {
                needed: MIN_ALLOCATION_BYTES,
                available: quota,
            });
        }

        if available < DISK_SAFETY_MARGIN_BYTES + quota {
            let usable = available.saturating_sub(DISK_SAFETY_MARGIN_BYTES);
            if usable < MIN_ALLOCATION_BYTES {
                return Err(PlanError::InsufficientSpace {
                    needed: MIN_ALLOCATION_BYTES,
                    available: usable,
                });
            }
            info!("disk space limited: allocating {} ({}% of {} available)",
                fmt_bytes(usable), storage_pct, fmt_bytes(available));
            return MultiStore::from_single_path(&path, usable);
        }

        info!("single disk quota: {} ({}% of {})",
            fmt_bytes(quota), storage_pct, fmt_bytes(total));
        return MultiStore::from_single_path(&path, quota);
    }

    info!("storage mode: auto-detect (allocating {:.1}% of total disk space)", storage_pct);

    let disks = detect_disks();

    if disks.is_empty() {
        warn!("no real disks detected (container/VM/Windows?), falling back to ~/.oin");
        let fallback = oin_core::storage::LocalStore::default_path();
        let parent = find_mount_point(&fallback);
        if let Some(info) = query_disk_space(&parent, "") {
            let quota = ((info.total_bytes as f64) * (storage_pct / 100.0)) as u64;
            let usable = quota.min(info.available_bytes.saturating_sub(DISK_SAFETY_MARGIN_BYTES));
            if usable >= MIN_ALLOCATION_BYTES {
                info!("fallback: single store at {} with {} quota",
                    fallback.display(), fmt_bytes(usable));
                return MultiStore::from_single_path(&fallback, usable);
            }
        }

        let default_quota = 1_073_741_824u64;
        warn!("could not detect disk space, using default quota of {}",
            fmt_bytes(default_quota));
        return MultiStore::from_single_path(&fallback, default_quota);
    }

    info!("detected {} disk(s):", disks.len());
    for d in &disks {
        info!("  {} ({}) - total: {}, available: {}",
            d.mount_point.display(), d.fs_type,
            fmt_bytes(d.total_bytes), fmt_bytes(d.available_bytes));
    }

    let plan = plan_storage(&disks, storage_pct, node_id)?;

    info!("storage plan: {} total across {} disk(s) ({:.1}% of {})",
        fmt_bytes(plan.oin_allocation_bytes),
        plan.allocations.len(),
        plan.storage_pct,
        fmt_bytes(plan.total_system_bytes));

    MultiStore::from_plan(&plan)
}

fn find_mount_point(path: &Path) -> PathBuf {
    let mut current = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };

    loop {
        if current.exists() { return current; }
        if !current.pop() {
            #[cfg(windows)]
            return PathBuf::from("C:\\");
            #[cfg(not(windows))]
            return PathBuf::from("/");
        }
    }
}

pub fn fmt_bytes(b: u64) -> String {
    if b == 0 { return "0 B".into(); }
    if b < 1024 { return format!("{} B", b); }
    if b < 1_048_576 { return format!("{:.1} KB", b as f64 / 1024.0); }
    if b < 1_073_741_824 { return format!("{:.1} MB", b as f64 / 1_048_576.0); }
    format!("{:.2} GB", b as f64 / 1_073_741_824.0)
}

