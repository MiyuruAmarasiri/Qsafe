# Regulatory & Compliance Mapping

## Standards Alignment
- **NIST PQC**: ML-KEM and ML-DSA selections match final round winners; roadmap tracks implementation guidance updates.
- **FIPS 140-3**: Crypto modules target Level 2 validation; dev builds use FIPS-ready images with conditional self-tests enabled.
- **CMMC 2.0 / FedRAMP High**: Mutual attestation, mTLS, and telemetry controls align with access control (AC), risk assessment (RA), and audit/logging (AU) domains.
- **ISO/IEC 27001**: Key management policies, secure development lifecycle, and incident response documentation built into release management.

## Policy Controls
- PQ Mode gates enforce cryptographic agility: `strict`, `hybrid`, `classical-canary`.
- Key rotation policy: session keys ≤15 minutes; long-term PQ keys ≤24 hours in production.
- Attestation policy versioned and signed; updates require dual-approval workflow.
- Telemetry retention configured per compliance zone (30 days dev, 180 days prod) with PII redaction guarantees.

## Evidence Artifacts
- Threat model (`docs/threat_model.md`) and crypto design (`docs/crypto_design.md`) reviewed quarterly.
- CI pipeline emits SLSA L3 provenance, vulnerability scan reports, and dependency diffs.
- Vault audit logs, HSM usage logs, and attestation decision logs ingested into SIEM.
- Red-team findings and mitigations tracked in security backlog with SLA targets.

## Outstanding Actions
- Engage accredited lab for FIPS validation once cryptographic modules stabilize.
- Finalize data processing agreements covering PQ telemetry exports.
- Establish continuous compliance tooling to verify policy-as-code enforcement and certificate lifetimes.
