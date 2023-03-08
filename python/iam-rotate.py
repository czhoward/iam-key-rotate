"""
Code to rotate the key of a user, selects users by TAG "KeyUser" only.

Checks the user for single or multiple access keys. If a single access key
will then check against the expiry date and if past, creates a new access key
stores the key in Secrets Manager and emails the user to inform them to rotate
the key in their environment.

If multiple access keys are found then checks the youngest key to see if it has
been used.  If it has NOT been used then this code will do nothing.  If the new
access key has been used then the old access key will be de-activated after a
defined number of days have passed, and then will be deleted after a further
defined number of days has passed.

TODO: Change or add storing keys in hashicorp vault
"""

import os
import logging
from datetime import datetime

import boto3
from botocore.exceptions import ClientError

import json

log = logging.getLogger()
log.setLevel(logging.INFO)

def notify(destination, username, reminder=None):
    """
    Sends an email to inform user to rotate their access key, destination email
    address is taken from the tag that identifies this account.

    :param destination: TO email address
    :param username: The IAM username
    :param reminder: optional if configured this is a reminder email
    :returns: message id if send was successful
    :raises: error if send was a failure

    Note: If your account is in the Amazon SES  sandbox, the source and
    destination email accounts must both be verified.
    """
    client = boto3.client("sesv2")
    sender = "your@email-address.com"  # FROM email address
    body = (
            "A new Access Key has been generated for "
            + username
            + ".  Details have been stored in KMaaS.  Please update your use."
    )
    html = (
            "<p>A new Access Key has been generated for "
            + username
            + ".  Details have been stored in KMaaS.  Please update your use.<br/></p>"
    )
    if reminder:
        subject = "Reminder: New access keys created for user " + username
    else:
        subject = "New access keys created for user " + username

    try:
        response = client.send_email(
            FromEmailAddress=sender,
            Destination={"ToAddresses": [destination]},
            Content={
                "Simple": {
                    "Subject": {"Data": subject},
                    "Body": {"Text": {"Data": body}, "Html": {"Data": html}},
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


def key_age(key):
    """
    Function to determine the number of days a key has existed
    in comparison to today.
    :param key: Access key
    :returns: integer of days, 0 if less than 1 day
    """
    key_created_date = key["CreateDate"]
    tz_info = key_created_date.tzinfo
    age = datetime.now(tz_info) - key_created_date
    log.info("key age %s", age)

    key_age_str = str(age)
    if "days" not in key_age_str:
        return 0

    return int(key_age_str.split(",")[0].split(" ")[0])


def is_access_key_ever_used(key):
    """
    Check to see if there is a last date used for the key, if
    there is then the key has been used, if there is not then
    the key is still to be used
    :param key: Access key last used
    :returns: boolean
    """
    if "LastUsedDate" in key["AccessKeyLastUsed"].keys():
        log.info("Access key has been used")
        return True
    else:
        log.info("Access key has never been used")
        return False


def get_owner_email(client, username):
    """
    Get the email address of the key user based on a tag associated with
    the user account.  This should be the email of the person who uses
    the account access key rather than someone who manages the account
    :param client: boto3 iam client connection
    :param username: iam username
    :returns: contents of tag KeyUser or nothing
    """
    meta = client.list_user_tags(UserName=username)["Tags"]
    for i in meta:
        if i["Key"] == "KeyUser":
            log.info("Email for user %s is %s", username, i["Value"])
            return i["Value"]


def store_keys(client, username, access_key, secret_access_key):
    """
    Save the access key and the secret in Secrets Manager
    If the secret already exists then update otherwise create
    :param client: boto3 secret manager client connection
    :param username: iam username
    :param access_key: new access key for user
    :param secret_access_key: new secret access key for user
    :returns: boto3 response code
    """
    key_info = str(
        json.dumps([{"Access Key": access_key}, {"Secret Key": secret_access_key}])
    )
    try:
        response = client.update_secret(SecretId=username, SecretString=key_info)
        log.info("Updated secret for %s", username)
    except ClientError:
        response = client.create_secret(Name=username, SecretString=key_info)
        log.info("Secret creating secret for %s", username)
    return response


def store_key_in_vault(client, username, a_key, s_key):
    """
    TODO: Not in use yet, needs mechanism to decide secret manager or vault (or both)
    Save the access key and the secret in KMaaS
    If the secret already exists then update otherwise create
    :param client: boto3 IAM client connection
    :param username: iam username
    :param a_key: new access key for user
    :param s_key: new secret access key for user
    """
    url = os.getenv("VAULT_ADDR")
    dns = url.split("/")[2]
    namespace = os.getenv("VAULT_NAMESPACE")
    role = os.getenv("VAULT_AUTH_ROLE")

    # Set Vault Client Properties
    vault = hvac.Client(
        url=url,
        token=None,
        verify=False,
        allow_redirects=True,
        namespace=namespace,
    )

    # Vault client Login using AWS IAM Auth Method
    vault.auth.aws.iam_login(
        access_key=client.access_key,
        secret_key=client.secret_key,
        session_token=client.token,
        header_value=dns,
        role=role,
        use_token=True,
        mount_point="aws",
    )

    try:
        vault.secrets.kv.v2.create_or_update_secret(
            mount_point="secrets/",  # Secret Engine mount point
            path=username,
            secret=dict(access_key=a_key, secret_key=s_key),
        )
    except Forbidden:
        log.error("Vault access forbidden")
    except InvalidPath:
        log.error("Vault access issue Invalid Path")
    except Unauthorized:
        log.error("Vault access Unauthorized")
    except UnexpectedError:
        log.error("Vault unexpected error")
    except VaultDown:
        log.error("Vault Down")
    finally:
        log.info("Keys stored in Vault")

        
def rotate_key(client, email, username):
    """
    Account has a single access key at the moment and
    that key is old enough to require rotating
    :param client: iam client connection
    :param email: email address of user to send to
    :param username: iam username
    :returns: result of created access key
    """
    client_secret = boto3.client("secretsmanager")
    log.info("Only one access key defined. Creating a new access key")
    x = client.create_access_key(UserName=username)["AccessKey"]  # create the key
    access_key, secret_access_key = x["AccessKeyId"], x["SecretAccessKey"]
    # store the keys in a Secret
    store_keys(client_secret, username, access_key, secret_access_key)
    notify(email, username)  # send email to user about change
    return x


def delete_key(access_key, client, username):
    """
    Delete existing access key
    :param access_key: The access_key that will be deleted
    :param client: boto3 iam client connection
    :param username: iam username of account
    """
    try:
        client.delete_access_key(
            UserName=username, AccessKeyId=access_key["AccessKeyId"]
        )
        log.info(
            "Deleting old key %s for user %s",
            access_key["AccessKeyId"],
            username,
        )
    except ClientError:
        log.exception(
            "Failed to delete key %s for user %s",
            access_key["AccessKeyId"],
            username,
        )
        raise


def deactivate_key(access_key, client, username):
    """
    Set existing access key to deactivated state
    :param access_key: The access_key that will be deactivated
    :param client: boto3 iam client connection
    :param username: iam username of account
    """
    try:
        client.update_access_key(
            UserName=username,
            AccessKeyId=access_key["AccessKeyId"],
            Status="Inactive",
        )
        log.info(
            "Deactivating old key %s for user %s",
            access_key["AccessKeyId"],
            username,
        )
    except ClientError:
        log.exception(
            "Failed to deactivate key %s for user %s",
            access_key["AccessKeyId"],
            username,
        )
        raise


def determine_key_order(access_keys):
    """ Determine which key is the younger and older
    :param access_keys: Expects a list of access keys to be passed
    :returns: two individual access keys in order older, younger
    """
    young_key_index, old_key_index = ((1, 0), (0, 1))[
        key_age(access_keys[0]) <= key_age(access_keys[1])
        ]
    return (
        access_keys[old_key_index],
        access_keys[young_key_index],
    )


def lambda_handler(event, context):
    """
    main lambda function
    :param event: event-bridge generated event to call the function
    :param context: null, not used
    """
    log.info("RotateAccessKey: starting...")
    EXPIRE_OLD_ACCESS_KEY_AFTER = 10  # Likely 10 in production
    DELETE_OLD_ACCESS_KEY_AFTER = 20  # Likely 20 in production
    CREATE_NEW_ACCESS_KEY_AFTER = 80  # Likely 80 in production
    NEW_ACCESS_KEY_NOTIFY_WINDOW = [7, 14]  # Likely 7 and 14 in production
    client_iam = boto3.client("iam")

    data = client_iam.list_users()
    log.info(data)

    # Loop through IAM users
    for user in data["Users"]:
        username = user["UserName"]
        log.info("username %s", username)
        email = get_owner_email(
            client_iam, username
        )  # Check for key user email tag populated and skip if not defined
        if not email:
            log.info(
                "Skipping: Email address not found for access key user %s", username
            )
            continue

        access_keys = client_iam.list_access_keys(UserName=username)[
            "AccessKeyMetadata"
        ]
        if (
                len(access_keys) == 1
                and key_age(access_keys[0]) > CREATE_NEW_ACCESS_KEY_AFTER
        ):
            # There is a single access key, and it has passed renewal age
            rotate_key(client_iam, email, username)
        elif len(access_keys) == 2:
            # There is more than one access key already - get details of the newest access key
            log.info(
                "Two access keys already. Screening existing access keys for user %s",
                username,
            )
            (
                old_access_key,
                young_access_key,
            ) = determine_key_order(access_keys)

            young_access_key_age = key_age(young_access_key)
            if not is_access_key_ever_used(
                    client_iam.get_access_key_last_used(AccessKeyId=young_access_key["AccessKeyId"])
            ):
                # Key has not been used, if necessary send a reminder
                log.info("User %s Access Key has not been used", username)
                if young_access_key_age in NEW_ACCESS_KEY_NOTIFY_WINDOW:
                    notify(email, username, reminder=True)
            else:
                # key has been used and can be deactivated or deleted on day X
                log.info("User %s Access Key has been used", username)
                if young_access_key_age >= DELETE_OLD_ACCESS_KEY_AFTER:
                    delete_key(old_access_key, client_iam, username)
                elif young_access_key_age == EXPIRE_OLD_ACCESS_KEY_AFTER:
                    deactivate_key(old_access_key, client_iam, username)

    log.info("Completed")
    return 0
