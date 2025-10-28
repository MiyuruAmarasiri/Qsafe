# Quantum-Safe Communication Protocol

This repository scaffolds an advanced MVP for a post-quantum secure communication stack. It focuses on hybrid authenticated key exchange, mutual hardware-backed attestation, and transport-agnostic encrypted messaging with deep observability and supply-chain hardening.

## Highlights
- Dual-track handshake combining ML-KEM (Kyber) encapsulation with ML-DSA (Dilithium) signatures and controlled downgrades to classical TLS 1.3.
- Mutual device identity enforced through TPM/HSM attestations prior to session key derivation.
- Transport-neutral framing (gRPC/WebSocket) with AEAD-protected payloads seeded from PQ-derived keys and deterministic rotation schedules.
- Integrated telemetry, threat modeling, fuzzing, and CI pipelines to detect downgrade attempts, side channels, and crypto drift.

Refer to `docs/` for design, threat modeling, and compliance collateral, and to `infra/` and `.ci/` for environment automation.
