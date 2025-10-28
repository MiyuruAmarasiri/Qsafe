# Agent Reference Client

Lightweight client that negotiates PQ-protected sessions with the gateway while running on constrained or edge devices.

## Responsibilities
- Discover gateway capabilities, initiate ML-KEM encapsulation, and manage deterministic rekeys.
- Collect TPM-based attestation evidence and package Dilithium-signed claims.
- Provide pluggable transport adapters (gRPC, WebSocket, QUIC) and local secure storage for session state.
- Surface telemetry hooks for handshake metrics and anomaly reporting.
- Enforce policy updates delivered over control channel, including PQ mode changes and rotation cadence.

## Implementation Notes
- Implemented in Go for tight integration with shared PQ crypto/session libraries.
- Issues HTTP(S) calls against the gateway’s REST façade to drive handshake and secure messaging.
- Session state is maintained in-memory with replay windows and rotation hints surfaced via CLI output.
