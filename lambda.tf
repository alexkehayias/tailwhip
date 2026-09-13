# IAM role for the Lambda — trust + scoped SSM read perms.
resource "aws_iam_role" "lambda" {
  name = "tailwhip-lambda"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Allow reading the Tailscale auth key + HMAC shared secret from SSM. The path
# is scoped to /tailwhip/* so the role can't read anything else.
# Default AWS-managed CMK decrypts SecureString transparently — no KMS perms needed.
resource "aws_iam_role_policy" "ssm_read" {
  name = "ssm-read"
  role = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ssm:GetParameters"]
      Resource = "arn:aws:ssm:*:*:parameter/tailwhip/*"
    }]
  })
}

# CloudWatch Logs (basic execution role grants CreateLogStream/PutLogEvents).
resource "aws_iam_role_policy_attachment" "logs" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Zip the pre-built bootstrap binary at apply time. The user must run
# ./lambda/build.sh before `tofu apply` so this file exists; source_code_hash
# ensures the Lambda redeploys when the binary changes.
data "archive_file" "zip" {
  type        = "zip"
  source_file = "${path.module}/lambda/bootstrap"
  output_path = "${path.module}/build/webhook.zip"
}

# The Lambda function.
resource "aws_lambda_function" "webhook" {
  function_name    = "tailwhip"
  role             = aws_iam_role.lambda.arn
  runtime          = "provided.al2023"
  handler          = "bootstrap"
  filename         = data.archive_file.zip.output_path
  source_code_hash = data.archive_file.zip.output_base64sha256
  memory_size      = 512 # tsnet + Go runtime need headroom; 128MB risks OOM on cold start
  timeout          = 15  # less than the caller's 30s timeout

  environment {
    variables = {
      TARGET_URL         = var.target_url
      TAILSCALE_HOSTNAME = var.tailscale_hostname
      SIG_HEADER         = "X-Webhook-Signature"
    }
  }

  reserved_concurrent_executions = 10
  depends_on                     = [aws_iam_role_policy_attachment.logs]
}

# Public HTTPS endpoint. HMAC is the only auth — no AWS IAM gate on requests.
resource "aws_lambda_function_url" "webhook" {
  function_name      = aws_lambda_function.webhook.function_name
  authorization_type = "NONE"
}

# Function URLs with authorization_type = "NONE" need an explicit resource-based
# policy granting public invocation. AWS REQUIRES the FunctionUrlAuthType
# condition on a Principal "*" + InvokeFunctionUrl grant — omitting it makes
# AddPermission fail with InvalidParameterValueException. The console also wants
# lambda:InvokeFunction granted to "*" for public access; both statements are
# provided. depends_on orders them after the Function URL is created.
resource "aws_lambda_permission" "url" {
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.webhook.function_name
  principal              = "*"
  function_url_auth_type = "NONE"

  depends_on = [aws_lambda_function_url.webhook]
}

resource "aws_lambda_permission" "url_invoke" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.webhook.function_name
  principal     = "*"

  depends_on = [aws_lambda_function_url.webhook]
}

# Log group with 14-day retention (default never-expire costs money).
resource "aws_cloudwatch_log_group" "webhook" {
  name              = "/aws/lambda/${aws_lambda_function.webhook.function_name}"
  retention_in_days = 14
}