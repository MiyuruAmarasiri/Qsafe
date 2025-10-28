# Terraform Stack

Defines baseline cloud infrastructure for the quantum-safe communication platform.

## Modules
- **networking/**: VPCs, subnets, private service endpoints, and zero-trust gateways.
- **security/**: KMS/HSM provisioning, IAM roles with least privilege, Vault clusters, and CloudHSM/CloudKMS integrations.
- **observability/**: OTLP collectors, SIEM ingestion pipelines, and logging sinks with data residency controls.
- **compute/**: Kubernetes clusters (GKE/EKS/AKS), node pools with TPM 2.0 availability, and autoscaling profiles tuned for crypto workloads.
- **ci/**: Build farm workers with Bazel remote cache, artifact registry, and provenance storage buckets.

## Conventions
- Modules emit outputs for Helm chart consumption (service endpoints, secrets references).
- State stored encrypted via Terraform Cloud or remote backend with dual control.
- Policy-as-code enforced via Sentinel/OPA prior to apply.
- Use `make plan` / `make apply` wrappers to ensure environment variable validation and drift detection.
