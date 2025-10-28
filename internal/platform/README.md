# `internal/platform`

Shared platform components for logging, telemetry export, policy evaluation, and infrastructure integration.

## Modules
- **logging/**: Zap-based structured logging with secure redaction filters and per-tenant correlation IDs.
- **metrics/**: OpenTelemetry exporters with adaptive sampling and anomaly guardrails.
- **tracing/**: Context propagation utilities standardizing trace IDs across Go/Rust services.
- **policy/**: Rego (OPA) bundles and evaluators enforcing PQ mode, attestation, and transport requirements.
- **secrets/**: Vault agent integration, workload identity federation clients, PKCS#11 middleware adapters.
- **compliance/**: Policy-as-code checks verifying crypto configuration and supply-chain attestations.

## Operational Hooks
- Envoy/mesh filters emit span events for negotiation lifecycle.
- All telemetry flows through zero-trust egress proxies with rate governance.
- Secrets clients renew short-lived credentials automatically and surface metrics for leading indicators of drift.
