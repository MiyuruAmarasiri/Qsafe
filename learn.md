# Learning Qsafe

This guide gives newcomers a structured path to become productive with Qsafe’s quantum-safe communication protocol. It combines reading assignments, hands-on labs, and checkpoints so you can build confidence in each subsystem.

## Learning Objectives
- Understand how Qsafe blends ML-KEM (Kyber) and ML-DSA (Dilithium) with hardware attestation.
- Navigate the repository, including gateway/agent binaries, shared libraries, and protocol buffers.
- Run the reference handshake end-to-end and observe telemetry.
- Evaluate security posture, threat model assumptions, and compliance artifacts.

## Prerequisites
- Familiarity with Go (see `go.mod` for the required toolchain) and basic TLS concepts.
- Access to a development machine with Go, Docker (optional), and `make`.
- A TPM 2.0 device or emulator is helpful but not required for the initial labs.

## Orientation
1. Read the `README.md` for an overview and quickstart commands.
2. Skim the following design documents to ground yourself in architecture and security posture:
   - `docs/crypto_design.md`
   - `docs/threat_model.md`
   - `docs/executive_brief.md`
   - `docs/regulatory_mapping.md`
3. Explore these directories to understand code layout:
   - `cmd/gateway`, `cmd/agent` – entry points for the reference binaries.
   - `pkg/crypto`, `pkg/session` – reusable building blocks for handshake, rotation, and policy enforcement.
   - `proto/api/v1` – capability discovery, handshake, and messaging definitions.
   - `.ci/`, `infra/`, `scripts/` – automation, containerization, and provenance tooling.

## Hands-On Labs

### Lab 1: Environment Setup
```shell
make bootstrap   # optional helper for asdf/direnv users
make tidy        # ensure dependencies are in sync
make lint
make test
```
Goal: verify the toolchain and baseline tests pass locally.

### Lab 2: Run the Hybrid Handshake
```shell
make run-gateway
# in another terminal
make run-agent
```
Observe gateway and agent logs for:
- Capability negotiation (ML-KEM, ML-DSA suites).
- Mutual attestation results.
- Session key rotation events and telemetry exports.

### Lab 3: Inspect Telemetry
1. Enable OpenTelemetry exporters as documented in `cmd/gateway` and `cmd/agent` flags.
2. Capture traces/metrics and note attributes for downgrade detection, attestation status, and rotation schedules.
3. Document findings in a lab journal or issue discussion for future contributors.

### Lab 4: Threat Model Alignment
- Cross-reference observed behavior with `docs/threat_model.md`.
- Identify which controls mitigate each adversary class.
- File notes or suggestions if you uncover gaps or unclear assumptions.

## Deep Dives
- **Attestation Policy**: Review policy evaluation logic under `pkg/session` and examine how TPM/HSM evidence is validated.
- **Key Rotation**: Trace deterministic rotation scheduling and enforcement hooks.
- **Protobuf Contracts**: Inspect `proto/api/v1/handshake.proto` to understand capability discovery and transcript commitments.
- **Provenance Pipeline**: Execute `scripts/gen-provenance.sh` to familiarize yourself with SLSA placeholders and planned improvements.

## Practice Projects
1. Add telemetry annotations for a new handshake metric and document the change.
2. Simulate a downgrade attempt in the red-team harness (under `tests/`) and capture mitigation evidence.
3. Draft an extension proposal in GitHub Discussions outlining support for an additional transport or PQ primitive.

## Knowledge Checks
- Can you explain how Qsafe enforces cryptographic agility (strict vs hybrid vs classical-canary modes)?
- Which artifacts prove supply-chain integrity during builds?
- How do TPM-backed attestations flow from device quote to policy enforcement?
- Where would you plug in new observability sinks or compliance evidence collectors?

## Next Steps
- Contribute improvements guided by `CONTRIBUTING.md`.
- Follow security handling guidance in `SECURITY.md` when encountering potential vulnerabilities.
- Join Discussions to collaborate on roadmap items, share lab findings, or request mentorship.

Mastering Qsafe is an iterative process. Use this learning path to build a solid foundation, then deepen expertise by contributing code, reviews, and documentation.
