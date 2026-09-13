variable "target_url" {
  description = "Full URL of the upstream webhook endpoint on the Tailnet (e.g., http://100.x.y.z:1234/webhook)."
  type        = string
}

variable "region" {
  description = "AWS region for the Lambda. Required — must be set explicitly."
  type        = string
}

variable "tailscale_hostname" {
  description = "Tailscale node hostname for the Lambda (visible in the admin console as an ephemeral node)."
  type        = string
  default     = "tailwhip"
}
