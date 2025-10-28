# `pkg/crypto`

Implements the post-quantum primitive adapters, hybrid key scheduler, and deterministic entropy expansion utilities.

## Components
- **kem/**: Bindings to liboqs ML-KEM implementations with constant-time wrappers and zeroization.
- **sign/**: Dilithium signing helpers, transcript binding support, and attestation packaging.
- **scheduler/**: HKDF-SHA3 based key schedule, epoch management, and exporter interfaces.
- **entropy/**: Hardware entropy collectors, deterministic expanders (BLAKE3), and self-test harnesses.
- **storage/**: Tamper-evident secure storage for long-lived PQ keys with HSM/PKCS#11 adapters.

## Development Notes
- All cryptographic operations must be constant-time; enforce via dudect and ctgrind jobs in CI.
- Provide Go and Rust bindings; Bazel macros select language-specific targets.
- Feature flags gate experimental algorithms (e.g., BIKE, HQC) without touching stable APIs.
