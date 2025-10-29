# Contributing to Qsafe

Thank you for helping advance Qsafe’s quantum-safe communication stack. This guide explains how to set up your environment, propose changes, and collaborate with the maintainer team.

## Project Overview

Key directories:

- `cmd/gateway`, `cmd/agent` – reference binaries that exercise the hybrid handshake and transport.
- `pkg/crypto`, `pkg/session` – shared libraries for PQ primitives, transcript binding, and key rotation.
- `proto/api/v1` – gRPC and message definitions for capabilities, handshake, and runtime messaging.
- `docs/` – architectural deep dives, threat model, and regulatory mapping.
- `infra/`, `.ci/`, `scripts/` – automation, containerization, and provenance helpers.
- `tests/` – red-team harnesses, integration smoke tests, and fuzz entry points.

Review the README and documents in `docs/` to understand design goals before making significant changes.

## Getting Started

1. Install Go (see `go.mod` for the required version).
2. Clone the repository and `cd` into the project root.
3. (Optional) Run `make bootstrap` to configure asdf/direnv if you use them.
4. Run `make tidy` to ensure module dependencies are consistent.

For development, you may also want Docker (for infra tests) and `protoc` with the Go protobuf toolchain if you plan to modify `.proto` files.

## Development Workflow

1. Create a topic branch from `main` (e.g., `git checkout -b feat/telemetry-export`).
2. Make focused changes with descriptive commit messages in imperative mood (e.g., `Add downgrade detector for Kyber fallback`).
3. Keep pull requests tightly scoped. Coordinate large changes via a design discussion issue before coding.

### Local Verification

Before opening a pull request, ensure these commands pass:

```shell
make lint      # formats Go sources
make test      # runs unit tests
make build     # builds gateway and agent binaries
```

Consider running extra checks when relevant:

- `go test -race ./...` for concurrency-sensitive changes.
- `go test ./... -run TestIntegration` (or package-specific tests) when touching session flows.
- Regenerate protobuf code using your toolchain (e.g., `buf`, `protoc`) if you modify files in `proto/api/v1`.
- Exercise the binaries locally: `make run-gateway` and `make run-agent`.

### Protocol and Security Changes

Changes that affect cryptography, attestation, or policy enforcement require extra diligence:

- Update `docs/crypto_design.md`, `docs/threat_model.md`, and `docs/regulatory_mapping.md` as needed.
- Summarize threat-model impact in the pull request form.
- Include regression tests covering downgrade attempts, invalid transcripts, or rotation edge cases.
- Engage maintainers early if you plan to update PQ primitives or attestation requirements.

### Documentation

- Update README or docs when behavior or configuration changes.
- Add comments for complex state machines or key-schedule logic (avoid trivial comments).
- If you introduce new telemetry or alerts, document expectations in `docs/executive_brief.md` or operator guides.

## Pull Requests

When opening a PR:

- Fill out the pull request form (`.github/PULL_REQUEST_TEMPLATE/pull_request.yml`) completely.
- Link related issues using `Fixes #123` or `Refs #123`.
- Attach logs, traces, or diagrams if they help reviewers.
- Ensure CI passes; if CI fails due to a known flaky test, explain the status in the PR discussion.

## Community Expectations

- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).
- Respect reviewer time—respond to feedback promptly or set expectations if you need more time.
- Keep discussions public unless they involve sensitive security topics.

## Security Guidance

If you discover a vulnerability, follow the process in [SECURITY.md](SECURITY.md) rather than opening a public issue. Feature work that touches security-critical code should include a short risk analysis in the pull request description.

## Getting Help

- Open a draft PR to gather early feedback.
- Use GitHub Discussions for architectural questions or roadmap suggestions.
- Reach out to `miyubhashi2002@gmail.com` for urgent support.` for coordination on complex contributions.

We appreciate your time and expertise—thank you for helping make Qsafe resilient and inclusive.
