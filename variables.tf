variable "schedule_expression" {
  type        = string
  description = " Cloudwatch schedule expression for when to run the access key rotation.  Default 11am every day."
  default     = "cron(0 11 * * ? *)"
}

variable "source_file" {
  type        = string
  description = "The full or relative path to zipped binary of lambda handler"
  default     = "python/aws-access-key-rotation-lambda.zip"
}

variable "source_dir" {
  type        = string
  description = "The full or relative path to source code"
  default     = "python/"
}

variable "destination" {
  type        = string
  description = "The email address that will receive the notification, should match tag in user"
  default     = "youremail@youremailprovider.com"
}

variable "sender" {
  type        = string
  description = "The email address that will be used as the sender of the notification"
  default     = "youremail@youremailprovider.com"
}