output "agent_role_arn" {
  description = "ARN of the agent's IAM role"
  value       = aws_iam_role.agent.arn
}

output "agent_role_name" {
  description = "Name of the agent's IAM role"
  value       = aws_iam_role.agent.name
}

output "instance_profile_name" {
  description = "Name of the instance profile"
  value       = aws_iam_instance_profile.agent.name
}

output "instance_profile_arn" {
  description = "ARN of the instance profile"
  value       = aws_iam_instance_profile.agent.arn
}

output "permissions_boundary_arn" {
  description = "ARN of the permissions boundary policy"
  value       = aws_iam_policy.permissions_boundary.arn
}

output "iam_path" {
  description = "IAM path prefix for agent-created roles"
  value       = var.iam_path
}
