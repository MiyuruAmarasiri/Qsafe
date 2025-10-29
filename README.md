# Quantum-Safe Communication Protocol

This repository scaffolds an advanced MVP for a post-quantum secure communication stack. It focuses on hybrid authenticated key exchange, mutual hardware-backed attestation, and transport-agnostic encrypted messaging with deep observability and supply-chain hardening.

## Highlights
- Dual-track handshake combining ML-KEM (Kyber) encapsulation with ML-DSA (Dilithium) signatures and controlled downgrades to classical TLS 1.3.
- Mutual device identity enforced through TPM/HSM attestations prior to session key derivation.
- Transport-neutral framing (gRPC/WebSocket) with AEAD-protected payloads seeded from PQ-derived keys and deterministic rotation schedules.
- Integrated telemetry, threat modeling, fuzzing, and CI pipelines to detect downgrade attempts, side channels, and crypto drift.

Refer to `docs/` for design, threat modeling, and compliance collateral, and to `infra/` and `.ci/` for environment automation.

## Getting Started

```bash
make bootstrap   # optional: toolchains + direnv
make tidy        # ensure go.sum is up-to-date
make test        # run unit test suites
make build       # build gateway and agent binaries into dist/
```

To exercise an end-to-end handshake locally:

```bash
# ensure Docker Desktop/daemon is running
make compose-up   # launches gateway on :8443 and runs the reference agent once
make compose-down # tear down containers when finished
```

## Deploying

- Update `infra/terraform/providers.tf` (and/or add `backend` blocks) with your team’s remote state location, VPC settings, and IAM wiring prior to applying infrastructure.
- Edit `infra/helm/gateway/values.yaml` to point `image.repository` and `image.tag` at the container registry used by your release pipeline. Provide environment-specific overrides (e.g., `values-prod.yaml`) as needed.
- CI already emits SBOMs and vulnerability scan reports; ensure the GitHub Actions runner has access to Cosign/Trivy/Syft credentials in your environment.

Once infrastructure and image references are configured, apply Terraform, publish the gateway/agent images, and install the Helm chart to bring the quantum-safe handshake service online.
