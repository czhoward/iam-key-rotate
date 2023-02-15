data "aws_iam_policy_document" "policy" {
  statement {
    effect = "Allow"
    actions = [
      "ses:SendEmail",
      "ses:GetAccount",
      "iam:CreateAccessKey",
      "iam:DeleteAccessKey",
      "iam:GetAccessKeyLastUsed",
      "iam:UpdateAccessKey",
      "iam:ListUsers",
      "iam:ListUserTags",
      "iam:ListAccessKeys",
      "secretsmanager:ListSecrets",
      "secretsmanager:CreateSecret",
      "secretsmanager:UpdateSecret",
      "secretsmanager:DeleteSecret"
    ]
    resources = ["*"]
  }
  statement {
    effect = "Allow"
    actions = [
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
      "logs:DescribeLogGroups",
      "logs:CreateLogStream",
      "logs:CreateLogGroup"
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }
}