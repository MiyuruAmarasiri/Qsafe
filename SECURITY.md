# Security Policy

Qsafe safeguards post-quantum and classical communication channels. We appreciate responsible researchers and operators who help protect the project and its users.

## Supported Versions

Security fixes are provided for:

- `main`
- The most recent tagged release

Older releases may receive fixes on a best-effort basis only if maintainers have capacity.

## Reporting a Vulnerability

- Email: `miyubhashi2002@gmail.com`
- PGP: `miyubhashi2002@gmail.com` (fingerprint `5F91 6E36 4132 F3BE 4716  C5E9 7F5D A6AD 2D62 3F4B`)
- Please encrypt when possible and include a phone/Signal handle if you prefer synchronous follow-up.

### What to Include

- Affected components (`cmd/gateway`, `cmd/agent`, `pkg/*`, infrastructure, etc.) and commit or release.
- Environment details (PQ mode, hardware attestation vendor, deployment model).
- Step-by-step reproduction, proof of concept, or exploit scenario.
- Impact assessment: confidentiality, integrity, availability, or policy bypass implications.
- Suggested mitigations or references if you have them.

We acknowledge all reports within **3 business days** and provide status updates at least every **7 days** until resolution.

## Disclosure Process

1. Reporter submits findings via the channels above.
2. Maintainers triage, reproduce, and classify severity.
3. A coordinated remediation plan is developed, including patches and mitigations.
4. Fixes are released and backported as appropriate.
5. Reporter is credited (if desired) in release notes or advisories.

We aim to release fixes within **30 days** for high-impact issues and sooner for critical vulnerabilities.

## Safe Harbor

We will not pursue legal action against researchers who:

- Make a good-faith effort to comply with this policy.
- Avoid privacy violations, service disruption, or destruction of data.
- Provide us reasonable time to remediate before public disclosure.
- Do not access or modify data that is not their own.

If you are unsure whether your actions fall within scope, contact us first.

## Out of Scope

While we welcome all feedback, the following items are typically outside the scope of the security program:

- Denial-of-service issues caused by infrastructure limits without a realistic exploitation vector.
- Vulnerabilities in third-party dependencies without a demonstrated Qsafe impact (please report to the upstream project first).
- Social engineering, phishing, or physical attacks.
- Issues requiring root or kernel compromise on the host where Qsafe is running.
- Findings that rely on unsupported configurations or development-only tooling (e.g., SoftHSM setups used for local tests).

## Public Disclosure

Once a fix is available, we will publish details through release notes and, if warranted, GitHub security advisories. Please coordinate timing with us so users can patch promptly.

Thank you for helping keep Qsafe resilient and trustworthy.
