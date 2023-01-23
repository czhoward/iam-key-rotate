# AWS IAM Key Rotate

Originally based on python code by [droidlabour](https://github.com/droidlabour/aws-iam-rotate-access-key) and then modified a little to inhibit the deletion of an old key if the new key has never been used.  Updated the email notification to use SESv2 API and then created the terraform to upload it into an account.  Stores the key in SecretsManager.

The terraform is pretty much the bare minimum and should NOT be used for production environments, the policies are way too relaxed for starters.  Likewise no backend configuration.

The sender and destination email resources need setting if you are using a sandbox SES environment but should not be necessary if running in production SES, then you may need the domain resources but I haven't an enabled SES to test that out.

The code should run every day and if any access key is outside the range it will start the process of replacing that key and informing the user.
