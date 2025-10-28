# Threat Model

## Assets
- Session keys, exporter secrets, and long-term PQ key material.
- Device attestation claims and transcript commitments.
- Control plane telemetry (handshake logs, anomaly events).
- Source code, build artifacts, and supply-chain metadata.

## Adversaries
- **Quantum-capable nation state**: Full visibility, cryptanalysis at scale, attempts to break PQ primitives or force downgrades.
- **Insider with privileged infrastructure access**: Targets HSMs, build pipeline, or telemetry for exfiltration.
- **Malicious peer**: Attempts handshake downgrade, replay, or oracle exploitation.
- **Side-channel attacker**: Measures timing, cache, or power signatures.
- **Supply-chain attacker**: Injects malicious dependencies or compromises build tooling.

## Attack Surfaces
- Network handshake endpoints (gRPC/WebSocket ingress).
- Device attestation workflow (quote validation, policy evaluation).
- Configuration management (algorithm registry, PQ mode flags).
- CI/CD system, build cache, container registries.
- Secrets distribution (Vault agents, PKCS#11 middleware).

## Controls
- Hybrid handshake with transcript binding prevents silent downgrade; classical fallback gated by policy.
- TPM/HSM attested identities mitigate credential theft and device spoofing.
- Envoy filters enforce ALPN and mTLS; SPIFFE identities restrict service interactions.
- Replay vaults and nonce windows detect repeated encapsulations.
- Observability pipeline emits structured security events with anomaly detection budgets.
- CI/CD uses hermetic builds, SLSA provenance, and Cosign signing.
- Secrets delivered via short-lived tokens; SoftHSMv2 used only in dev with strict segregation.

## Testing & Validation
- Red-team harness exercises downgrade, oracle, and timing attacks.
- Fuzzers target handshake transcripts, state machine transitions, and deserialization paths.
- Side-channel baselines captured via tooling (e.g., dudect, CacheAudit) to detect regressions.
- Continuous compliance checks ensure cryptographic policies and supply-chain attestations remain current.

## Residual Risks
- Early PQ implementations may harbor unknown vulnerabilities; maintain crypto-agility to swap primitives.
- Hardware attestation depends on vendor firmware integrity; monitor CVEs and supply firmware updates quickly.
- Telemetry pipelines could become high-value targets; enforce zero-trust egress and encrypt at rest.
