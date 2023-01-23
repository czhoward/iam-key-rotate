# resource "aws_ses_domain_identity" "example" {
#   domain = "example.com"
# }

# This is only necessary if running SES as a sandpit
resource "aws_sesv2_email_identity" "destination" {
  email_identity = var.destination
}

resource "aws_sesv2_email_identity" "sender" {
  email_identity = var.sender
}

# resource "aws_ses_domain_mail_from" "main" {
#   domain           = aws_ses_domain_identity.main.domain
#   mail_from_domain = local.stripped_mail_from_domain
# }