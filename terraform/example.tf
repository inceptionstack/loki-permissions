# Terraform Usage Example
#
# Add this to your project's Terraform to create IAM roles
# that comply with the agent's scoped permissions.

variable "account_id" {
  type = string
}

variable "project" {
  type = string
}

# Every IAM role MUST include:
#   path                 = "/loki/"
#   permissions_boundary = "arn:aws:iam::${var.account_id}:policy/loki/LokiPermissionsBoundary"

resource "aws_iam_role" "lambda_execution" {
  name                 = "${var.project}-lambda-role"
  path                 = "/loki/"
  permissions_boundary = "arn:aws:iam::${var.account_id}:policy/loki/LokiPermissionsBoundary"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "lambda_execution" {
  name = "${var.project}-lambda-policy"
  role = aws_iam_role.lambda_execution.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:${var.account_id}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "arn:aws:s3:::${var.project}-*/*"
      }
    ]
  })
}

# CodeBuild role example
resource "aws_iam_role" "codebuild" {
  name                 = "${var.project}-codebuild-role"
  path                 = "/loki/"
  permissions_boundary = "arn:aws:iam::${var.account_id}:policy/loki/LokiPermissionsBoundary"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "codebuild.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# CodePipeline role example
resource "aws_iam_role" "pipeline" {
  name                 = "${var.project}-pipeline-role"
  path                 = "/loki/"
  permissions_boundary = "arn:aws:iam::${var.account_id}:policy/loki/LokiPermissionsBoundary"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "codepipeline.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}
