# Open Image Network

End-to-end encrypted image hosting with post-quantum cryptography.

Upload an image, get a link, share it. No accounts, no tracking, no ads. The gateway never sees your image.

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

## Encryption layers

**Layer 1 — Browser (E2E):** AES-256-GCM with HKDF-SHA256 key derivation. The gateway receives only ciphertext. An HMAC-SHA256 of the ciphertext is embedded in every share link so the viewer can detect tampering before decryption.

**Layer 2 — Gateway (PQC):** Each manifest is encrypted with AES-256-GCM using keys exchanged via ML-KEM-1024 (FIPS 203). Every envelope is dual-signed with ML-DSA-87 (FIPS 204) and SLH-DSA-SHAKE-256s (FIPS 205). Chunks are encrypted per-image with AES-256-GCM. Data is split with Reed-Solomon erasure coding so images can survive partial node loss.

**Layer 3 — Transport:** HTTPS between all parties.

## Post-quantum cryptography

Three NIST FIPS standards at Security Level 5:

| Algorithm | Standard | Role |
|-----------|----------|------|
| ML-KEM-1024 | FIPS 203 | Key encapsulation |
| ML-DSA-87 | FIPS 204 | Lattice signatures |
| SLH-DSA-SHAKE-256s | FIPS 205 | Hash-based signatures |

Classical AES-256 randomness is combined with ML-KEM-1024 via HKDF-SHA3-256. Both must be broken simultaneously. Dual signatures mean if lattice math breaks, the hash layer holds.

## Architecture

The gateway is a central coordinator — it receives uploads, chunks and encrypts data, distributes to nodes, and reassembles on download. It does not store data permanently. Nodes are the persistent storage layer; they hold only opaque encrypted blobs and cannot decrypt anything.

This is **not fully decentralized**: the gateway is a single point of coordination. Nodes are independent and distributed, but they rely on the gateway for job assignment. If the gateway goes down, existing share links stop working until it comes back. Node data is preserved and will re-sync when the gateway returns.

```
crates/
├── oin-core/     Crypto, chunking, erasure coding, PQC, manifests, storage
└── oin-node/     Storage daemon with multi-disk support and gateway sync
```

## Run a node

Download the binary for your platform from [Releases](https://github.com/VinavilDev/OpenImageNetwork/releases), then run it:

**Linux / macOS:**
```
chmod +x oin-node-*
./oin-node-linux-x64
```

**Windows:**
```
oin-node-windows-x64.exe
```

No configuration needed. The node connects to the network automatically and starts storing encrypted chunks. No port forwarding required — pull architecture works behind any NAT/firewall.

## Build from source

```
git clone https://github.com/VinavilDev/OpenImageNetwork.git
cd OpenImageNetwork
cargo build --release -p oin-node
./target/release/oin-node
```

## Security

Nodes never decrypt anything. They store and serve opaque encrypted blobs. The node codebase imports zero cryptographic decryption functions. All endpoints require authentication when the network key is set. HMAC-SHA256 signed heartbeats with replay protection. Constant-time comparisons on all secrets. Input validation on every HTTP parameter. Path traversal protection. No shell commands. Pure Rust, memory safe with 2 `unsafe` blocks (FFI calls for disk space queries on Unix/Windows, both bounds-checked).

## License

MIT
