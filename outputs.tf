output "function_url" {
  description = "Public HTTPS URL for the webhook endpoint. The root path expects an X-Webhook-Signature header; reserved paths (e.g. /github) use that provider's native signature."
  value       = aws_lambda_function_url.webhook.function_url
}

output "log_group_name" {
  description = "CloudWatch log group for debugging HMAC failures and upstream errors."
  value       = aws_cloudwatch_log_group.webhook.name
}