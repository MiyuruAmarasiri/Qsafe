# Cryptographic Architecture & Rationale

## Handshake Overview
1. **Capability discovery**: Client and gateway exchange supported PQ primitives, AEAD suites, and policy hints via `CapabilityExchange` (see `proto/api/v1/handshake.proto`).
2. **Mutual attestation**: Each endpoint submits TPM/HSM-backed quotes signed with ML-DSA (Dilithium) linked to hardware roots. Attestation is validated against policy (certificate chains, nonce freshness, PCR expectations).
3. **Hybrid key establishment**: Client executes ML-KEM (Kyber) encapsulation against gateway's PQ public key. Gateway produces decapsulation plus a Dilithium-signed transcript commitment. Optional classical ECDHE handshake runs in parallel for downgrade compatibility.
4. **Key schedule**: Derived shared secret feeds HKDF-Expand steps producing traffic keys, exporter secrets, and rekey seeds. Deterministic rotation occurs every 900s or 2^20 packets, whichever comes first.
5. **Channel confirmation**: Endpoints exchange AEAD-protected Finished messages and activate transport adapters (gRPC/WebSocket).

## Algorithm Selections
- **ML-KEM (Kyber-768)**: NIST-selected KEM balancing security margin and performance. PQ mode can escalate to ML-KEM-1024 for classified workloads.
- **ML-DSA (Dilithium-3)**: Digital signature scheme used for endpoint authentication, attestation packaging, and transcript binding.
- **XChaCha20-Poly1305 AEAD**: Provides nonce-misuse resilience and high throughput. Frames include monotonic counters enforced by replay vault logic.
- **HKDF-SHA3-512**: Extractor/expander tuned for PQ secrets and high min-entropy outputs.
- **BLAKE3**: Secondary hashing for transcript accumulation due to speed and parallelism, wrapped by domain-separated contexts.

## Key Management
- Long-term signing keys stored in HSMs or hardware-backed secure enclaves; short-lived KEM keys rotated daily.
- Session keys rotated automatically via deterministic schedule; rotation requests included in control frames.
- Key material stored transiently in memory; enforced zeroization via Rust `zeroize` and Go `memguard`.
- Exporter interface allows higher layers to derive service-specific keys without re-running handshake.

## Resilience & Hardening
- Hybrid fallback ensures classical security if PQ algorithms fail but requires policy allow-list.
- Side-channel protections include constant-time decapsulation, timing jitter during attestation checks, and CPU pinning for crypto operations.
- Replay protection uses per-session Bloom filters and signed nonce windows.
- Transcript binding encapsulates capabilities, attestation artifacts, and transport metadata to prevent renegotiation tampering.

## Compliance Alignment
- NIST PQC standards for algorithm selection; FIPS 140-3 compliance tracked via `docs/regulatory_mapping.md`.
- Cryptographic agility achieved by config-driven algorithm registry with policy-as-code checks.
- Supply-chain integrity enforced by build attestations and deterministic toolchains (Bazel/Pants).
