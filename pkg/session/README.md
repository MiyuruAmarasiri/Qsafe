# `pkg/session`

Hosts handshake orchestration, transcript binding, replay protection, and key rotation logic for transport-agnostic sessions.

## Subpackages
- **state/**: Finite state machines covering negotiation, attestation validation, and recovery.
- **transcript/**: Hash accumulators (BLAKE3, SHA3) with domain separation and tamper evidence.
- **replay/**: Bloom filter and sliding window implementations for ciphertext sequence enforcement.
- **rotation/**: Epoch scheduler, deterministic rekey calculations, and coordination with transport control channels.
- **policy/**: Runtime evaluators for PQ mode enforcement, downgrade exceptions, and algorithm registries.
- **state/session.go**: Runtime session orchestrator providing AEAD sealing/unsealing, replay protection enforcement, and rotation hints for transport layers.

## Testing Strategy
- Model state transitions using TLA+/PlusCal for safety invariants.
- Fuzz handshake frames with libFuzzer + honggfuzz connectors (`tests/fuzz`).
- Run deterministic integration suites against reference agent/gateway in `tests/e2e`.
