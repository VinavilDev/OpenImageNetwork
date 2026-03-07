mod disk;

use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{StatusCode, HeaderMap},
    response::IntoResponse,
    routing::{get, put, delete},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, warn, error};

use oin_core::chunk::{Chunk, ChunkId, hex_to_chunk_id};
use oin_core::crypto::{hmac_sha256, constant_time_eq};
use disk::MultiStore;

const GATEWAY: &str = "https://oin.vinavildev.com";

struct NodeState {
    store: MultiStore,
    node_id: String,
    started_at: Instant,
    stats: RwLock<Stats>,
    cfg: Cfg,
}

struct Cfg {
    port: u16,
    public_url: Option<String>,
    gateway: String,
    passkey: Option<String>,
    lat: f64,
    lon: f64,
    country: String,
    city: String,
    region: String,
}

#[derive(Default)]
struct Stats {
    chunks_served: u64,
    chunks_stored: u64,
    bytes_in: u64,
    bytes_out: u64,
}

fn gw(s: &NodeState) -> &str { s.cfg.gateway.as_str() }

fn auth_url(base: &str, key: &Option<String>, nid: &str) -> String {
    let sep = if base.contains('?') { "&" } else { "?" };
    match key {
        Some(k) if !k.is_empty() => format!("{}{}node_id={}&passkey={}", base, sep, nid, k),
        _ => format!("{}{}node_id={}", base, sep, nid),
    }
}

async fn http_get(url: &str, key: &Option<String>, nid: &str) -> Option<Vec<u8>> {
    let url = auth_url(url, key, nid);
    tokio::task::spawn_blocking(move || {
        match ureq::get(&url).timeout(Duration::from_secs(10)).call() {
            Ok(resp) => {
                let mut buf = Vec::new();
                resp.into_reader().read_to_end(&mut buf).ok().map(|_| buf)
            }
            Err(ureq::Error::Status(code, _)) => { warn!("gateway HTTP {}", code); None }
            Err(ureq::Error::Transport(t)) => { warn!("gateway: {}", t); None }
        }
    }).await.ok().flatten()
}

async fn http_post(url: &str, json: &str) -> bool {
    let url = url.to_string();
    let json = json.to_string();
    tokio::task::spawn_blocking(move || {
        ureq::post(&url).timeout(Duration::from_secs(10))
            .set("Content-Type", "application/json")
            .send_string(&json).is_ok()
    }).await.unwrap_or(false)
}

async fn http_put(url: &str, key: &Option<String>, nid: &str, data: &[u8]) -> bool {
    let url = auth_url(url, key, nid);
    let data = data.to_vec();
    tokio::task::spawn_blocking(move || {
        ureq::put(&url).set("Content-Type", "application/octet-stream")
            .send_bytes(&data).is_ok()
    }).await.unwrap_or(false)
}

fn is_hex(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn check_auth(state: &NodeState, headers: &HeaderMap) -> bool {
    let secret = match &state.cfg.passkey {
        None => return true,
        Some(s) if s.is_empty() => return true,
        Some(s) => s,
    };
    for name in ["x-oin-secret", "authorization"] {
        if let Some(val) = headers.get(name).and_then(|h| h.to_str().ok()) {
            let tok = val.strip_prefix("Bearer ").unwrap_or(val);
            if tok.len() == secret.len() && constant_time_eq(tok.as_bytes(), secret.as_bytes()) { return true; }
        }
    }
    warn!("rejected unauthorized request");
    false
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let port: u16 = std::env::var("OIN_NODE_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(9090);
    let store_path = std::env::var("OIN_STORE").ok().map(PathBuf::from)
        .unwrap_or_else(|| oin_core::storage::LocalStore::default_path());
    std::fs::create_dir_all(&store_path)?;

    let node_id = std::env::var("OIN_NODE_ID").ok()
        .or_else(|| load_id(&store_path))
        .unwrap_or_else(|| { let id = gen_id(); save_id(&store_path, &id); id });

    let (lat, lon, country, city, region) = detect_geo();

    let store = match disk::init_storage(std::env::var("OIN_STORE").ok().map(PathBuf::from), &node_id) {
        Ok(s) => { info!("storage: {}", s.summary()); s }
        Err(e) => { error!("storage failed: {}", e); std::process::exit(1); }
    };

    let bad = store.verify_disk_health();
    if bad.len() == store.per_disk_info().len() && !bad.is_empty() { error!("all disks failing"); std::process::exit(1); }
    for d in &bad { warn!("disk: {} — {}", d.mount.display(), d.issue); }

    let state = Arc::new(NodeState {
        store, node_id: node_id.clone(), started_at: Instant::now(),
        stats: RwLock::new(Stats::default()),
        cfg: Cfg {
            port, public_url: std::env::var("OIN_PUBLIC_URL").ok(),
            gateway: GATEWAY.into(), passkey: std::env::var("OIN_NET_KEY").ok(),
            lat, lon, country, city, region,
        },
    });

    info!("gateway: {}", gw(&state));
    timers(&state);

    info!("OIN Node [{}] on :{}", &node_id[..12], port);

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/info", get(h_info))
        .route("/chunk/:id", get(h_get_chunk).put(h_put_chunk).delete(h_del_chunk))
        .route("/manifest/:id", get(h_get_manifest).put(h_put_manifest).delete(h_del_manifest))
        .layer(DefaultBodyLimit::max(15 * 1024 * 1024))
        .with_state(state);

    axum::serve(tokio::net::TcpListener::bind(SocketAddr::from(([0,0,0,0], port))).await?, app).await?;
    Ok(())
}

fn timers(state: &Arc<NodeState>) {
    macro_rules! timer {
        ($s:expr, $delay:expr, $interval:expr, $f:expr) => {{
            let s = Arc::clone($s);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs($delay)).await;
                loop { $f(&s).await; tokio::time::sleep(Duration::from_secs($interval)).await; }
            });
        }};
    }
    let s = Arc::clone(state);
    tokio::spawn(async move { heartbeat(&s).await; loop { tokio::time::sleep(Duration::from_secs(30)).await; heartbeat(&s).await; } });
    timer!(state, 5, 10, sync_images);
    timer!(state, 3, 2, deliver_images);
    timer!(state, 8, 30, process_deletes);

    let s = Arc::clone(state);
    tokio::spawn(async move { loop {
        tokio::time::sleep(Duration::from_secs(300)).await;
        for d in s.store.verify_disk_health() { warn!("DISK: {} — {}", d.mount.display(), d.issue); }
        let (u, t) = (s.store.disk_usage(), s.store.total_quota());
        if t > 0 && u * 100 / t > 90 { warn!("storage >90%"); }
    }});
}

#[derive(Deserialize)]
struct SyncJob {
    image_id: String,
    #[serde(default)]
    chunk_ids: Vec<String>,
}

#[derive(Deserialize)]
struct FetchJob {
    image_id: String,
    #[serde(default)]
    priority: u32,
}

#[derive(Deserialize)]
struct DeleteJob {
    image_id: String,
}

async fn sync_images(state: &Arc<NodeState>) {
    let url = format!("{}/api/sync/pending", gw(state));
    let data = match http_get(&url, &state.cfg.passkey, &state.node_id).await { Some(b) => b, None => return };
    let jobs: Vec<SyncJob> = serde_json::from_slice(&data).unwrap_or_default();

    for job in &jobs {
        if state.store.has_manifest(&job.image_id) { ack(state, &job.image_id).await; continue; }
        info!("sync {}", job.image_id);

        let url = format!("{}/api/sync/manifest/{}", gw(state), job.image_id);
        let md = match http_get(&url, &state.cfg.passkey, &state.node_id).await { Some(d) => d, None => continue };
        if !state.store.has_capacity(md.len() as u64) { continue; }
        if state.store.store_manifest(&job.image_id, &md).is_err() { continue; }

        let mut ok = 0usize;
        for hex in &job.chunk_ids {
            if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) { continue; }
            let id = match hex_to_chunk_id(hex) { Ok(id) => id, Err(_) => continue };
            if state.store.has_chunk(&id) { ok += 1; continue; }
            let url = format!("{}/api/sync/chunk/{}", gw(state), hex);
            let cd = match http_get(&url, &state.cfg.passkey, &state.node_id).await { Some(d) => d, None => continue };
            if let Ok(chunk) = Chunk::from_bytes(&cd) {
                if !state.store.has_capacity(cd.len() as u64) { break; }
                if state.store.store_chunk(&chunk).is_ok() {
                    ok += 1;
                    let mut s = state.stats.write().await;
                    s.chunks_stored += 1; s.bytes_in += cd.len() as u64;
                }
            }
        }
        info!("synced {} — {}/{} chunks", job.image_id, ok, job.chunk_ids.len());
        state.store.store_chunk_map(&job.image_id, &job.chunk_ids);
        ack(state, &job.image_id).await;
    }
}

async fn deliver_images(state: &Arc<NodeState>) {
    let url = format!("{}/api/fetch/needed", gw(state));
    let data = match http_get(&url, &state.cfg.passkey, &state.node_id).await { Some(b) => b, None => return };
    let jobs: Vec<FetchJob> = serde_json::from_slice(&data).unwrap_or_default();

    for job in &jobs {
        if !state.store.has_manifest(&job.image_id) { continue; }
        let md = match state.store.load_manifest(&job.image_id) { Ok(d) => d, Err(_) => continue };

        info!("delivering {} to gateway ({} bytes manifest)", job.image_id, md.len());
        let url = format!("{}/api/fetch/manifest/{}", gw(state), job.image_id);
        if !http_put(&url, &state.cfg.passkey, &state.node_id, &md).await {
            warn!("manifest delivery failed for {}", job.image_id);
            continue;
        }

        let chunk_map = state.store.load_chunk_map(&job.image_id);
        let mut delivered = 0usize;
        for hex in &chunk_map {
            if let Ok(id) = hex_to_chunk_id(hex) {
                if let Ok(chunk) = state.store.load_chunk(&id) {
                    let b = chunk.to_bytes();
                    let url = format!("{}/api/fetch/chunk/{}", gw(state), hex);
                    if http_put(&url, &state.cfg.passkey, &state.node_id, &b).await {
                        delivered += 1;
                        let mut s = state.stats.write().await;
                        s.chunks_served += 1; s.bytes_out += b.len() as u64;
                    }
                }
            }
        }
        if delivered > 0 { info!("delivered {} — {}/{} chunks", job.image_id, delivered, chunk_map.len()); }
    }
}

async fn process_deletes(state: &Arc<NodeState>) {
    let url = format!("{}/api/delete/pending", gw(state));
    let data = match http_get(&url, &state.cfg.passkey, &state.node_id).await { Some(b) => b, None => return };
    let jobs: Vec<DeleteJob> = serde_json::from_slice(&data).unwrap_or_default();

    for job in &jobs {
        if !state.store.has_manifest(&job.image_id) { continue; }
        let chunk_map = state.store.load_chunk_map(&job.image_id);
        for hex in &chunk_map {
            if let Ok(id) = hex_to_chunk_id(hex) { let _ = state.store.delete_chunk(&id); }
        }
        state.store.delete_chunk_map(&job.image_id);
        let _ = state.store.delete_manifest(&job.image_id);
        info!("deleted {}", job.image_id);
        let url = format!("{}/api/delete/ack", gw(state));
        http_post(&url, &serde_json::json!({"node_id": state.node_id, "image_id": job.image_id, "passkey": state.cfg.passkey}).to_string()).await;
    }
}

async fn heartbeat(state: &Arc<NodeState>) {
    let s = state.stats.read().await;
    let chunks = state.store.chunk_count() as u64;
    let ts = chrono::Utc::now().timestamp();

    let manifests: Vec<String> = if chunks > 0 {
        state.store.list_manifests().unwrap_or_default()
    } else {
        for id in state.store.list_manifests().unwrap_or_default() { let _ = state.store.delete_manifest(&id); }
        vec![]
    };

    let body = serde_json::json!({
        "node_id": state.node_id, "port": state.cfg.port, "public_url": state.cfg.public_url,
        "latitude": state.cfg.lat, "longitude": state.cfg.lon,
        "country": state.cfg.country, "city": state.cfg.city, "region": state.cfg.region,
        "chunks_stored": chunks, "disk_usage": state.store.disk_usage(),
        "disk_capacity": state.store.total_quota(), "uptime_secs": state.started_at.elapsed().as_secs(),
        "chunks_served": s.chunks_served, "bytes_in": s.bytes_in, "bytes_out": s.bytes_out,
        "version": "0.3.0", "passkey": state.cfg.passkey, "manifest_ids": manifests, "timestamp": ts,
    });
    drop(s);

    let sig = state.cfg.passkey.as_ref().filter(|k| !k.is_empty())
        .map(|k| hmac_sha256(k, &format!("{}:{}:{}", state.node_id, state.cfg.port, ts)));

    let url = format!("{}/api/nodes/heartbeat", gw(state));
    let body_str = body.to_string();
    let failed = tokio::task::spawn_blocking(move || {
        let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(5)).build();
        let mut r = agent.post(&url).set("Content-Type", "application/json");
        if let Some(ref sig) = sig { r = r.set("X-OIN-Signature", sig); }
        r.send_string(&body_str).is_err()
    }).await.unwrap_or(true);
    if failed { warn!("heartbeat failed"); }
}

async fn ack(state: &Arc<NodeState>, image_id: &str) {
    let url = format!("{}/api/sync/ack", gw(state));
    http_post(&url, &serde_json::json!({"node_id": state.node_id, "image_id": image_id, "passkey": state.cfg.passkey}).to_string()).await;
}

#[derive(Serialize)]
struct InfoResp {
    node_id: String, uptime_secs: u64, chunks: usize, manifests: usize, disk_usage: u64,
    chunks_served: u64, chunks_stored: u64, bytes_in: u64, bytes_out: u64,
    gateway: String, lat: f64, lon: f64, country: String, city: String,
}

async fn h_info(headers: HeaderMap, State(st): State<Arc<NodeState>>) -> Result<Json<InfoResp>, StatusCode> {
    if !check_auth(&st, &headers) { return Err(StatusCode::FORBIDDEN); }
    let s = st.stats.read().await;
    Ok(Json(InfoResp {
        node_id: st.node_id.clone(), uptime_secs: st.started_at.elapsed().as_secs(),
        chunks: st.store.chunk_count(), manifests: st.store.list_manifests().map(|m| m.len()).unwrap_or(0),
        disk_usage: st.store.disk_usage(), chunks_served: s.chunks_served, chunks_stored: s.chunks_stored,
        bytes_in: s.bytes_in, bytes_out: s.bytes_out, gateway: st.cfg.gateway.clone(),
        lat: st.cfg.lat, lon: st.cfg.lon, country: st.cfg.country.clone(), city: st.cfg.city.clone(),
    }))
}

async fn h_get_chunk(Path(hex): Path<String>, headers: HeaderMap, State(st): State<Arc<NodeState>>) -> Result<impl IntoResponse, StatusCode> {
    if !check_auth(&st, &headers) { return Err(StatusCode::FORBIDDEN); }
    if hex.len() != 64 || !is_hex(&hex, 64) { return Err(StatusCode::BAD_REQUEST); }
    let bytes = st.store.load_chunk(&hex_to_chunk_id(&hex).map_err(|_| StatusCode::BAD_REQUEST)?).map_err(|_| StatusCode::NOT_FOUND)?.to_bytes();
    let mut s = st.stats.write().await; s.chunks_served += 1; s.bytes_out += bytes.len() as u64;
    Ok((StatusCode::OK, bytes))
}

async fn h_put_chunk(Path(hex): Path<String>, headers: HeaderMap, State(st): State<Arc<NodeState>>, body: axum::body::Bytes) -> Result<StatusCode, (StatusCode, String)> {
    if !check_auth(&st, &headers) { return Err((StatusCode::FORBIDDEN, "unauthorized".into())); }
    if hex.len() != 64 || !is_hex(&hex, 64) { return Err((StatusCode::BAD_REQUEST, "bad id".into())); }
    if !st.store.has_capacity(body.len() as u64) { return Err((StatusCode::INSUFFICIENT_STORAGE, "full".into())); }
    let chunk = Chunk::from_bytes(&body).map_err(|e| (StatusCode::BAD_REQUEST, format!("{}", e)))?;
    let actual: String = chunk.id.iter().map(|b| format!("{:02x}", b)).collect();
    if actual != hex { return Err((StatusCode::BAD_REQUEST, "id mismatch".into())); }
    st.store.store_chunk(&chunk).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)))?;
    let mut s = st.stats.write().await; s.chunks_stored += 1; s.bytes_in += body.len() as u64;
    Ok(StatusCode::CREATED)
}

async fn h_del_chunk(Path(hex): Path<String>, headers: HeaderMap, State(st): State<Arc<NodeState>>) -> Result<StatusCode, StatusCode> {
    if !check_auth(&st, &headers) { return Err(StatusCode::FORBIDDEN); }
    let id = hex_to_chunk_id(&hex).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !st.store.has_chunk(&id) { return Err(StatusCode::NOT_FOUND); }
    st.store.delete_chunk(&id).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?; Ok(StatusCode::NO_CONTENT)
}

async fn h_get_manifest(Path(id): Path<String>, headers: HeaderMap, State(st): State<Arc<NodeState>>) -> Result<impl IntoResponse, StatusCode> {
    if !check_auth(&st, &headers) { return Err(StatusCode::FORBIDDEN); }
    if !is_hex(&id, 24) { return Err(StatusCode::BAD_REQUEST); }
    let data = st.store.load_manifest(&id).map_err(|_| StatusCode::NOT_FOUND)?;
    let mut s = st.stats.write().await; s.bytes_out += data.len() as u64;
    Ok((StatusCode::OK, data))
}

async fn h_put_manifest(Path(id): Path<String>, headers: HeaderMap, State(st): State<Arc<NodeState>>, body: axum::body::Bytes) -> Result<StatusCode, (StatusCode, String)> {
    if !check_auth(&st, &headers) { return Err((StatusCode::FORBIDDEN, "unauthorized".into())); }
    if !is_hex(&id, 24) { return Err((StatusCode::BAD_REQUEST, "bad id".into())); }
    if !st.store.has_capacity(body.len() as u64) { return Err((StatusCode::INSUFFICIENT_STORAGE, "full".into())); }
    st.store.store_manifest(&id, &body).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)))?;
    let mut s = st.stats.write().await; s.bytes_in += body.len() as u64;
    Ok(StatusCode::CREATED)
}

async fn h_del_manifest(Path(id): Path<String>, headers: HeaderMap, State(st): State<Arc<NodeState>>) -> Result<StatusCode, StatusCode> {
    if !check_auth(&st, &headers) { return Err(StatusCode::FORBIDDEN); }
    if !st.store.has_manifest(&id) { return Err(StatusCode::NOT_FOUND); }
    st.store.delete_manifest(&id).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?; Ok(StatusCode::NO_CONTENT)
}

fn gen_id() -> String { let mut b = [0u8; 16]; getrandom::getrandom(&mut b).expect("rng"); b.iter().map(|x| format!("{:02x}", x)).collect() }

fn load_id(p: &std::path::Path) -> Option<String> {
    let id = std::fs::read_to_string(p.join("node_id")).ok()?.trim().to_string();
    (id.len() == 32 && id.chars().all(|c| c.is_ascii_hexdigit())).then_some(id)
}

fn save_id(p: &std::path::Path, id: &str) { let _ = std::fs::write(p.join("node_id"), id); }

fn detect_geo() -> (f64, f64, String, String, String) {
    let e = |k: &str| std::env::var(k).ok().filter(|s| !s.is_empty());
    let ef = |k: &str| e(k).and_then(|s| s.parse::<f64>().ok());

    if let (Some(lat), Some(lon), Some(c)) = (ef("OIN_LAT"), ef("OIN_LON"), e("OIN_COUNTRY")) {
        info!("geo: manual ({}, {})", lat, lon);
        return (lat, lon, c, e("OIN_CITY").unwrap_or_default(), e("OIN_REGION").unwrap_or_default());
    }

    info!("auto-detecting location...");
    let apis: &[(&str, fn(&serde_json::Value) -> Option<(f64,f64,String,String,String)>)] = &[
        ("http://ip-api.com/json/?fields=status,lat,lon,country,city,regionName", |v| {
            (v["status"].as_str()? == "success").then(|| ())?;
            Some((v["lat"].as_f64()?, v["lon"].as_f64()?, v["country"].as_str()?.into(), v["city"].as_str().unwrap_or("").into(), v["regionName"].as_str().unwrap_or("").into()))
        }),
        ("https://ipapi.co/json/", |v| {
            Some((v["latitude"].as_f64()?, v["longitude"].as_f64()?, v["country_name"].as_str()?.into(), v["city"].as_str().unwrap_or("").into(), v["region"].as_str().unwrap_or("").into()))
        }),
    ];

    for (url, parse) in apis {
        if let Ok(resp) = ureq::get(url).timeout(Duration::from_secs(5)).call() {
            let mut body = String::new();
            if resp.into_reader().read_to_string(&mut body).is_ok() {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some((lat, lon, country, city, region)) = parse(&v) {
                        info!("location: {}, {} ({:.2}, {:.2})", city, country, lat, lon);
                        return (ef("OIN_LAT").unwrap_or(lat), ef("OIN_LON").unwrap_or(lon),
                            e("OIN_COUNTRY").unwrap_or(country), e("OIN_CITY").unwrap_or(city), e("OIN_REGION").unwrap_or(region));
                    }
                }
            }
        }
    }
    warn!("geo failed");
    (0.0, 0.0, String::new(), String::new(), String::new())
}
