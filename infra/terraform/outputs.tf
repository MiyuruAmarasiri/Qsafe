output "vpc_id" {
  description = "Identifier for the provisioned VPC."
  value       = aws_vpc.qsafe.id
}

output "public_subnet_ids" {
  description = "Identifiers for public subnets hosting ingress components."
  value       = [for s in aws_subnet.public : s.id]
}

output "gateway_security_group_id" {
  description = "Security group attached to the gateway service."
  value       = aws_security_group.gateway.id
}

output "vault_root_token_example" {
  description = "Example Vault root token generated for bootstrap (rotate immediately in production)."
  sensitive   = true
  value       = random_password.vault_root_token.result
}
