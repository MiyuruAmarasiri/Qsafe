# Helm Charts

Provides Kubernetes deployment templates for the gateway, agent sidecar, telemetry collectors, and supporting services.

## Chart Composition
- **gateway/**: Deploys PQ-enabled ingress, Envoy sidecars, HSM connectors, and configmaps for algorithm registries.
- **agent/**: Packages edge connectors, policy bundles, and secret mount wiring for SoftHSMv2 in staging.
- **telemetry/**: Installs OTLP collectors, anomaly detectors, and redacted log shipping.
- **vault-agent/**: Manages secret injection sidecars with identity federation configuration.

## Deployment Flow
- Charts consume Terraform outputs via `.tfvars.json` or secrets references.
- GitOps pipelines (Argo CD/Flux) promote revisions after SLSA provenance verification.
- Values files segmented per environment (`values-dev.yaml`, `values-prod.yaml`) with PQ mode toggles.

## Security Hardening
- Enforce PodSecurity admission profiles, seccomp, and distroless images.
- Enable mTLS between pods using SPIFFE identities and envoy authorization policies.
- Integrate continuous compliance checks via `kubescape`/`kyverno` within CI.
