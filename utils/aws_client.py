import os

import boto3


def create_session(region: str | None = None) -> boto3.Session:
    """Create a boto3 session from environment credentials."""
    return boto3.Session(
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name=region or os.getenv("AWS_DEFAULT_REGION", "ap-south-1"),
    )
