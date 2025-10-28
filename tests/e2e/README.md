# End-to-End Test Harness

## Goals
- Validate ML-KEM/Dilithium handshake across gateway and agent binaries.
- Exercise deterministic key rotation, exporter derivations, and replay vault enforcement.
- Capture latency and throughput baselines versus classical TLS 1.3 benchmark.
- Emit structured telemetry for anomaly detection regression.

## Tooling
- Uses Bazel test targets invoking docker-compose or kind clusters for integration scenarios.
- Leverages SoftHSMv2 fixtures for HSM emulation and policy-as-code profiles.
- Supports scenario definitions via YAML to drive transport permutations and PQ mode toggles.

## Running Locally
```
bazel test //tests/e2e:handshake_suite --config=ci
```
Requires liboqs, SoftHSMv2, and Vault dev server availability (see `.envrc`).
