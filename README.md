<div align="center">

<img src="https://img.shields.io/badge/rust-100%25-B7410E?style=for-the-badge&logo=rust&logoColor=white" alt="rust" />
<img src="https://img.shields.io/badge/post--quantum-FIPS%20203%20·%20204%20·%20205-7b3fe4?style=for-the-badge" alt="pqc" />
<img src="https://img.shields.io/badge/encryption-AES--256--GCM-2dd4a0?style=for-the-badge" alt="encryption" />
<img src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge" alt="license" />

<br/><br/>

# 🔐 Open Image Network

**Hybrid-decentralized image hosting with end-to-end and post-quantum encryption.**

Upload → get a link → share it. No accounts. No tracking. No ads.

<br/>

<img src="https://img.shields.io/badge/E2E_encrypted-✓-2dd4a0?style=flat-square" alt="e2e" />
<img src="https://img.shields.io/badge/zero_knowledge_nodes-✓-2dd4a0?style=flat-square" alt="zk" />
<img src="https://img.shields.io/badge/browser_decryption-✓-2dd4a0?style=flat-square" alt="browser" />
<img src="https://img.shields.io/badge/reed--solomon-✓-2dd4a0?style=flat-square" alt="erasure" />
<img src="https://img.shields.io/badge/cross_platform-✓-2dd4a0?style=flat-square" alt="cross" />
<img src="https://img.shields.io/badge/NAT_friendly-✓-2dd4a0?style=flat-square" alt="nat" />

</div>

---

## How it works

```
 Browser                        Gateway                         Nodes
    │                              │                               │
    ├── AES-256-GCM encrypt ──────→│                               │
    │   (key stays in browser)     ├── chunk + Reed-Solomon        │
    │                              ├── AES-256-GCM per chunk       │
    │                              ├── ML-KEM-1024 key exchange    │
    │                              ├── ML-DSA-87 + SLH-DSA sign   │
    │                              ├── distribute ────────────────→│
    │←── link with key in #fragment│                               │
    │                              │                               │
    ├── request image ────────────→│                               │
    │                              ├── verify PQC signatures       │
    │                              ├── pull from nodes ←──────────│
    │←── encrypted response ──────│                               │
    ├── HMAC-SHA256 verify         │                               │
    ├── AES-256-GCM decrypt        │                               │
    ├── display                    │                               │
```

The decryption key lives in the URL fragment (`#key`). Browsers never send fragments to servers. The gateway handles encrypted ciphertext only. Nodes store opaque blobs.

---

## 🔑 Encryption layers

| Layer | Where | What |
|-------|-------|------|
| **E2E** | Browser | AES-256-GCM + HKDF-SHA256. Key never leaves your browser. HMAC-SHA256 integrity check in every link. |
| **PQC** | Gateway | ML-KEM-1024 key exchange → AES-256-GCM manifest encryption. Dual-signed with ML-DSA-87 + SLH-DSA-SHAKE-256s. |
| **Transport** | Everywhere | HTTPS between all parties. |

---

## 🛡️ Post-quantum cryptography

<div align="center">

| Algorithm | Standard | Role |
|-----------|----------|------|
| **ML-KEM-1024** | FIPS 203 | Key encapsulation |
| **ML-DSA-87** | FIPS 204 | Lattice signatures |
| **SLH-DSA-SHAKE-256s** | FIPS 205 | Hash-based signatures |

</div>

All three at **Security Level 5** (highest tier). Classical AES-256 randomness combined with ML-KEM-1024 via HKDF-SHA3-256 both must be broken simultaneously. Dual signatures mean if lattice math breaks, the hash layer holds.

---

## 🏗️ Architecture

> **This is hybrid-decentralized.** The gateway is a central coordinator it receives uploads, encrypts, distributes to nodes, and reassembles on download. It does not store data permanently. Nodes are the persistent storage layer holding only opaque encrypted blobs they cannot decrypt. If the gateway goes down, share links stop working until it returns. Node data is preserved.

```
crates/
├── oin-core/     Crypto, chunking, erasure coding, PQC, manifests
└── oin-node/     Storage daemon with multi-disk support and gateway sync
```

---

## ⚡ Quick start

### Download a binary

Grab the latest from [**Releases**](https://github.com/VinavilDev/OpenImageNetwork/releases):

| Platform | Binary |
|----------|--------|
| 🪟 Windows x64 | [`oin-node-windows-x64.exe`](https://github.com/VinavilDev/OpenImageNetwork/releases/latest) |
| 🍎 macOS Apple Silicon | [`oin-node-macos-arm64`](https://github.com/VinavilDev/OpenImageNetwork/releases/latest) |
| 🍎 macOS Intel | [`oin-node-macos-x64`](https://github.com/VinavilDev/OpenImageNetwork/releases/latest) |
| 🐧 Linux x64 | [`oin-node-linux-x64`](https://github.com/VinavilDev/OpenImageNetwork/releases/latest) |

Then run it:

```bash
# Linux / macOS
chmod +x oin-node-*
./oin-node-linux-x64

# Windows
oin-node-windows-x64.exe
```

**That's it.** No config, no port forwarding, no accounts. The node connects and starts storing encrypted chunks.

### Build from source

```bash
git clone https://github.com/VinavilDev/OpenImageNetwork.git
cd OpenImageNetwork
cargo build --release -p oin-node
./target/release/oin-node
```

---

<div align="center">
<sub>Built with Rust. Secured with <3 and Sweat.</sub>
</div>
