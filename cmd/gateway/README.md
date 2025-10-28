# Gateway Service

Edge ingress that terminates hybrid PQ handshakes, enforces attestation policy, and brokers secure messaging to downstream services.

## Responsibilities
- Accept HTTP-based handshake initiations, validate PQ compatibility, and orchestrate key schedule derivation.
- Maintain session registry with replay protection, deterministic rotation hints, and policy enforcement.
- Emit structured logs for handshake lifecycle, rotation triggers, and decrypt outcomes.
- Provide REST endpoints for encrypted messaging that leverage `pkg/session` orchestration.

## Implementation Notes
- Written in Go with Bazel target `//cmd/gateway`.
- Uses `pkg/crypto` ML-KEM/Dilithium primitives and `pkg/session` state machines for runtime orchestration.
- HTTP surface is intentionally lightweight for MVP; future revisions can front-end Envoy/gRPC once transports stabilise.
- Rotation and replay controls are configurable via CLI flags (`--rotation`, `--mode`, `--aead`).
