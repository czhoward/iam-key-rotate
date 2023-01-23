resource "aws_cloudwatch_event_rule" "cwe_rule" {
  name                = "access-key-rotation-lambda"
  description         = "Triggers access key rotation lambda function according to schedule expression"
  schedule_expression = var.schedule_expression
}

resource "aws_cloudwatch_event_target" "cwe_target" {
  rule      = aws_cloudwatch_event_rule.cwe_rule.name
  target_id = local.app_name
  arn       = aws_lambda_function.lambda.arn
}

resource "aws_cloudwatch_log_group" "function_log_group" {
  name              = "/aws/lambda/${aws_lambda_function.lambda.function_name}"
  retention_in_days = 7
  lifecycle {
    prevent_destroy = false
  }
}
