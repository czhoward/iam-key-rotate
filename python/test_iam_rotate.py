# Useful links
# https://github.com/getmoto/moto/blob/master/tests/test_iam/test_iam.py
# https://github.com/getmoto/moto/blob/master/tests/test_secretsmanager/test_secretsmanager.py

import pytest
import os
from datetime import datetime, timedelta
import boto3
from botocore.exceptions import ClientError
from moto import mock_iam  # , mock_sesv2 (not yet available)
# from freezegun import freeze_time

from iam_rotate import key_age, is_access_key_ever_used, get_owner_email

USERNAME = 'testuser'

"""Mocked AWS Credentials for moto."""
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_SECURITY_TOKEN"] = "testing"
os.environ["AWS_SESSION_TOKEN"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture
def iam():
    with mock_iam():
        conn = boto3.client("iam", region_name="us-east-1")
        yield conn


@mock_iam
def test_key_age():
    # Test key age calculation
    key_created_date = datetime.now() - timedelta(days=7)
    key = {'CreateDate': key_created_date}
    assert key_age(key) == 7


@mock_iam
def test_is_access_key_ever_used():
    # Test that is_access_key_ever_used returns True if key has been used
    key = {'AccessKeyLastUsed': {'LastUsedDate': datetime.now()}}
    assert is_access_key_ever_used(key) == True

    # Test that is_access_key_ever_used returns False if key has never been used
    key = {'AccessKeyLastUsed': {}}
    assert is_access_key_ever_used(key) == False


@mock_iam
def test_get_owner_email(iam):
    iam.create_user(UserName=USERNAME)
    assert get_owner_email(iam, USERNAME) is None

    iam.tag_user(
        UserName=USERNAME,
        Tags=[
            {'Key': 'KeyUser', 'Value': 'testuser@example.com'},
        ]
    )
    assert get_owner_email(iam, USERNAME) == 'testuser@example.com'
