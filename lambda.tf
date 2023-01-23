data "archive_file" "zip_the_python_code" {
  type        = "zip"
  source_dir  = var.source_dir
  output_path = var.source_file
}

resource "aws_lambda_function" "lambda" {
  filename         = var.source_file
  function_name    = local.app_name
  description      = "Rotates the access keys for the specified usernames"
  role             = aws_iam_role.lambda_role.arn
  handler          = local.lambda_handler
  source_code_hash = filebase64sha256(var.source_file)
  runtime          = "python3.9"
  timeout          = 900
  # https://docs.aws.amazon.com/systems-manager/latest/userguide/ps-integration-lambda-extensions.html#ps-integration-lambda-extensions-add
  # layers = ["arn:aws:lambda:eu-west-2:133256977650:layer:AWS-Parameters-and-Secrets-Lambda-Extension:2"]

  tracing_config {
    mode = "Active"
  }

  depends_on = [aws_iam_role_policy_attachment.attach_iam_policy_to_iam_role]
}

resource "aws_lambda_permission" "allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cwe_rule.arn
}