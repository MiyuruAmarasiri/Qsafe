# Container Builds

Multi-stage Dockerfiles producing hardened runtime images for gateway and agent components.

## Build Strategy
- Builder stages rely on the official Go 1.22 image with module caching to compile static linux/amd64 binaries.
- Runtime stages are based on distroless images to minimise the attack surface while running as non-root.
- SBOM and vulnerability scan steps are executed in CI via Syft/Trivy actions.

## Files
- Dockerfile.gateway – Builds the Go gateway binary and packages it into a distroless image.
- Dockerfile.agent – Builds the Go agent binary with the same toolchain for parity.
- Dockerfile.devbase – Development base image used by VS Code devcontainers.
- docker-compose.yml – Spins up gateway and agent containers for local smoke testing.

## Usage
- make compose-up starts both services using Docker Compose (ensure go mod tidy has fetched dependencies first).
- docker build -f infra/docker/Dockerfile.gateway . builds the gateway image manually.
- docker build -f infra/docker/Dockerfile.agent . builds the agent image manually.
