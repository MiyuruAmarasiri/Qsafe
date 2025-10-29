# Support Resources

We want every contributor, operator, and integrator to have a predictable path to help. Choose the option that best matches your question or incident.

## Self-Service

- **Documentation**: Start with the design and operations material in `docs/` (crypto design, threat model, regulatory mapping, executive brief).
- **Examples**: Review `cmd/gateway` and `cmd/agent` for reference configurations and CLI usage.
- **Automation**: The `Makefile`, `.ci/`, and `infra/` directories show how we build, test, and deploy the stack.

## Community Channels

- **GitHub Discussions** (`Q&A` category): Architecture questions, roadmap ideas, or integration tips.
- **Issue Templates**: Use the tailored forms under `.github/ISSUE_TEMPLATE/` for bugs, features, and support requests so triage is fast and complete.

## Opening a Support Request

When you cannot resolve an issue through documentation:

1. Gather environment details: commits or tags, PQ mode, transport, TPM/HSM vendor, host OS or container image.
2. Capture telemetry: logs from gateway/agent, OpenTelemetry traces, key rotation metrics, relevant policy files.
3. Search existing issues/discussions to avoid duplicates.
4. File a support issue using the template. Include:
   - Summary of the question/blocker.
   - Steps or commands to reproduce.
   - Telemetry excerpts with sensitive information removed.
   - Troubleshooting steps you already attempted.

Maintainers make a best effort to respond within **5 business days**. Complex incidents may take longer; we will update the issue with status.

## Security & Incident Handling

- Follow the coordinated disclosure process in [SECURITY.md](SECURITY.md) for suspected vulnerabilities or incidents. Do **not** post sensitive security reports publicly.
- For emergencies, email `miyubhashi2002@gmail.com` and include “URGENT” in the subject.

## Commercial Support

Qsafe is a community-driven project without commercial backing. If you need contractual SLAs or dedicated support, open a discussion so we can explore options or connect you with experienced contributors.

## Contributing Improvements

Support is a team effort. If you discover a useful diagnostic tip, script, or documentation improvement while troubleshooting, please open a pull request so others benefit.

Thank you for helping make Qsafe reliable and inclusive.
