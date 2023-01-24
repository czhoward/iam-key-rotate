"""
Code to rotate the key of a user, selects users by TAG "KeyUser" only.

Checks the user for single or multiple access keys. If a single access key
will then check against the expiry date and if past, creates a new access key
stores the key in Secrets Manager and emails the user to inform them to rotate
they key in their environment.

If multiple access keys are found then checks the youngest key to see if it has
been used.  If it has NOT been used then this code will do nothing.  If the new
access key has been used then the old access key will be de-activated after a
defined number of days have passed, and then will be deleted after a further
defined number of days has passed.

TODO: Change or add storing keys in hashicorp vault
    : Add handling for error conditions on secret store
"""

import logging
from datetime import datetime

import boto3
from botocore.exceptions import ClientError

import json

log = logging.getLogger()
log.setLevel(logging.INFO)


# Send email notification
def notify(sender, destination, subject, text, html):
    """
    :param sender: The source email account.
    :param destination: The destination email account.
    :param subject: The subject of the email.
    :param text: The plain text version of the body of the email.
    :param html: The HTML version of the body of the email.
    :return: The ID of the message, assigned by Amazon SES.
    """
    client = boto3.client("sesv2")
    """
    Note: If your account is in the Amazon SES  sandbox, the source and
    destination email accounts must both be verified.
    """
    try:
        response = client.send_email(
            FromEmailAddress=sender,
            Destination={"ToAddresses": [destination]},
            Content={
                "Simple": {
                    "Subject": {"Data": subject},
                    "Body": {"Text": {"Data": text}, "Html": {"Data": html}},
                }
            },
        )
        message_id = response["MessageId"]
        log.info("Sent mail %s from %s to %s.", message_id, sender, destination)
    except ClientError:
        log.exception("Couldn't send mail from %s to %s.", sender, destination)
        raise
    else:
        return message_id


# Determine the number of days since the key was created
def key_age(key_created_date):
    tz_info = key_created_date.tzinfo
    age = datetime.now(tz_info) - key_created_date
    log.info("key age %s", age)

    key_age_str = str(age)
    if "days" not in key_age_str:
        return 0

    return int(key_age_str.split(",")[0].split(" ")[0])


# Check to see if the key has been used.
def is_access_key_ever_used(client, access_key):
    x = client.get_access_key_last_used(AccessKeyId=access_key)
    if "LastUsedDate" in x["AccessKeyLastUsed"].keys():
        log.info("Access key %s has been used", access_key)
        return True
    else:
        log.info("Access key %s has never been used", access_key)
        return False


# Get the email address of the key user based on a tag associated with
# the user account.  This should be the email of the person who uses
# the account access key rather than someone who manages the account
def get_owner_email(client, username):
    meta = client.list_user_tags(UserName=username)["Tags"]
    for i in meta:
        if i["Key"] == "KeyUser":
            log.info("Email for user %s is %s", username, i["Value"])
            return i["Value"]


# Save the access and the secret in Secrets Manager
def store_keys(secret, username, access_key, secret_access_key):
    key_info = str(json.dumps([{"Access Key":access_key},{"Secret Key":secret_access_key}]))
    try:
        response = secret.update_secret(
            SecretId=username,
            SecretString=key_info
        )
        log.info("Updated secret for %s", username)
    except ClientError:
        response = secret.create_secret(
            Name=username,
            SecretString=key_info
        )        
        log.info("Secret creating secret for %s", username)
    return response


# Main code
def lambda_handler(event, context):
    log.info("RotateAccessKey: starting...")
    EXPIRE_OLD_ACCESS_KEY_AFTER = 10  # Likely 10 in production
    DELETE_OLD_ACCESS_KEY_AFTER = 20  # Likely 20 in production
    CREATE_NEW_ACCESS_KEY_AFTER = 80  # Likely 80 in production
    NEW_ACCESS_KEY_NOTIFY_WINDOW = [7, 14]  # Likely 7 and 14 in production
    SENDER = "youremail@youremailprovider.com"
    client = boto3.client("iam")
    secret = boto3.client("secretsmanager")

    data = client.list_users()
    log.info(data)

    # Loop through IAM users
    for user in data["Users"]:
        username = user["UserName"]
        log.info("username %s", username)
        email = get_owner_email(
            client, username
        )  # Check for key user email tag populated and skip if not defined
        if not email:
            logging.info(
                "Skipping: Email address not found for access key user %s", username
            )
            continue

        access_keys = client.list_access_keys(UserName=username)[
            "AccessKeyMetadata"
        ]  # get the access keys
        if (
            len(access_keys) == 1
            and key_age(access_keys[0]["CreateDate"]) > CREATE_NEW_ACCESS_KEY_AFTER
        ):
            # Single access key and old enough to require rotating
            log.info("Only one access key defined. Creating a new access key")
            x = client.create_access_key(UserName=username)[
                "AccessKey"
            ]  # create the key
            # compose the email elements and email
            access_key, secret_access_key = x["AccessKeyId"], x["SecretAccessKey"]
            body = (
                "Access Key: "
                + access_key
                + "details have been stored in SecretsManager.  Please update your use."
            )
            html = (
                "<p>Access Key: "
                + access_key
                + "<br/>"
                + "details have been stored in SecretsManager.  Please update your use.<br/></p>"
            )
            subject = "New access keys created for user " + username
            notify(SENDER, email, subject, body, html)
            # store the keys in a Secret
            store_keys(secret, username, access_key, secret_access_key)
        elif len(access_keys) == 2:
            # There is more than one access key already - get details of newest access key
            log.info(
                "Two access keys already. Screening existing access keys for user %s",
                username,
            )
            # Determine which key is the younger and older
            zero_key, one_key = access_keys[0], access_keys[1]
            young_key_index, old_key_index = ((1, 0), (0, 1))[key_age(zero_key["CreateDate"]) <= key_age(one_key["CreateDate"])]
            younger_access_key = access_keys[young_key_index]
            younger_access_key_age = key_age(younger_access_key["CreateDate"])

            if not is_access_key_ever_used(client, younger_access_key["AccessKeyId"]):
                # Key has not been used, if necessary send a reminder
                logging.info("User %s Access Key has not been used", username)
                if younger_access_key_age in NEW_ACCESS_KEY_NOTIFY_WINDOW:
                    old_key_expire_timeout = (
                        EXPIRE_OLD_ACCESS_KEY_AFTER - younger_access_key_age
                    )
                    logging.info(
                        "User %s has %s days to use this new key %s",
                        username,
                        old_key_expire_timeout,
                        younger_access_key["AccessKeyId"],
                    )
                    body = (
                        "You have "
                        + str(old_key_expire_timeout)
                        + " days to use the new access keys."
                    )
                    html = (
                        "<p>You have <b>"
                        + str(old_key_expire_timeout)
                        + "</b> days to use the new access keys.</p>"
                    )
                    subject = "Please use the new access keys for " + username
                    notify(SENDER, email, subject, body, html)
            else:
                # key has been used and can be deactivated or deleted on day X
                logging.info("User %s Access Key has been used", username)
                if younger_access_key_age >= DELETE_OLD_ACCESS_KEY_AFTER:
                    logging.info(
                        "Deleting old key %s for user %s",
                        access_keys[old_key_index]["AccessKeyId"],
                        username,
                    )
                    client.delete_access_key(
                        UserName=username, AccessKeyId=access_keys[1]["AccessKeyId"]
                    )
                elif younger_access_key_age == EXPIRE_OLD_ACCESS_KEY_AFTER:
                    logging.info(
                        "Deactivating old key %s for user %s",
                        access_keys[old_key_index]["AccessKeyId"],
                        username,
                    )
                    client.update_access_key(
                        UserName=username,
                        AccessKeyId=access_keys[old_key_index]["AccessKeyId"],
                        Status="Inactive",
                    )

    log.info("Completed")
    return 0
