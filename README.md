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

### Send a message locally

```bash
# ensure Docker Desktop/daemon is running
make compose-up   # starts the gateway on :8443

# run the reference agent and send an encrypted message
go run ./cmd/agent -gateway http://localhost:8443 -message "hello quantum"
```

The agent fetches gateway metadata, performs the PQ handshake, encrypts your payload, and prints the gateway’s decrypted response plus any rotation hint.

### Manual HTTP flow (advanced)

1. Discover server parameters: `curl http://localhost:8443/handshake/config`
2. Build a `ClientInit` (Kyber768 encapsulation to `kem_public`, include your capabilities/nonce/timestamp) and POST it:  
   `curl -X POST http://localhost:8443/handshake/init -H "Content-Type: application/json" -d @client_init.json`
3. Derive session keys from the response, create a `state.Session` (RoleClient), encrypt with `Session.Encrypt`, then POST the envelope:  
   `curl -X POST http://localhost:8443/message -H "Content-Type: application/json" -d '{"session_id":"<id>","envelope":{...}}'`

See `pkg/session/state` for the exact structs used in the handshake and message envelope.

### Testing tips (Windows)

If your environment blocks writes to `%APPDATA%`, point Go caches to the workspace before running tests:

```powershell
$base = Get-Location
$env:APPDATA     = Join-Path $base '.appdata'
$env:LOCALAPPDATA= $env:APPDATA
$env:TEMP        = Join-Path $base '.gotmp'
$env:TMP         = $env:TEMP
$env:GOTMPDIR    = $env:TEMP
$env:GOPATH      = Join-Path $base '.gopath'
$env:GOCACHE     = Join-Path $base '.gocache'
$env:GOMODCACHE  = Join-Path $base '.gomodcache'
go test ./...
```

## Deploying

- Update `infra/terraform/providers.tf` (and/or add `backend` blocks) with your team's remote state location, VPC settings, and IAM wiring prior to applying infrastructure.
- Edit `infra/helm/gateway/values.yaml` to point `image.repository` and `image.tag` at the container registry used by your release pipeline. Provide environment-specific overrides (e.g., `values-prod.yaml`) as needed.
- CI already emits SBOMs and vulnerability scan reports; ensure the GitHub Actions runner has access to Cosign/Trivy/Syft credentials in your environment.

Once infrastructure and image references are configured, apply Terraform, publish the gateway/agent images, and install the Helm chart to bring the quantum-safe handshake service online.
