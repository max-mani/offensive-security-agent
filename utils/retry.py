import logging
import time
from typing import Any, Callable, Union

import botocore

from models.report import CheckError

logger = logging.getLogger(__name__)


def safe_aws_call(func: Callable, check_id: str, *args, **kwargs) -> Union[Any, CheckError]:
    """
    Wrap a boto3 call with exponential backoff on throttling and explicit CheckError
    on access denied, timeout, and unexpected errors. Never raises.
    """
    max_retries = 3
    backoff_base = 2.0

    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)

        except botocore.exceptions.ClientError as e:
            code = e.response["Error"]["Code"]
            status = e.response["ResponseMetadata"]["HTTPStatusCode"]

            if code in ["AccessDenied", "AccessDeniedException", "AuthorizationError"]:
                logger.warning("[%s] Access denied: %s", check_id, code)
                return CheckError(
                    check_id=check_id,
                    error_type="access_denied",
                    error_message=f"Permission denied: {e.response['Error']['Message']}",
                    http_status=status,
                    aws_error_code=code,
                )

            if code in ["Throttling", "ThrottlingException", "RequestLimitExceeded"] or status == 429:
                wait = backoff_base ** attempt
                logger.warning(
                    "[%s] Throttled (attempt %d/%d), waiting %ss",
                    check_id,
                    attempt + 1,
                    max_retries,
                    wait,
                )
                time.sleep(wait)
                continue

            if attempt == max_retries - 1:
                return CheckError(
                    check_id=check_id,
                    error_type="api_error",
                    error_message=str(e),
                    http_status=status,
                    aws_error_code=code,
                )

        except botocore.exceptions.ConnectTimeoutError:
            if attempt == max_retries - 1:
                return CheckError(
                    check_id=check_id,
                    error_type="timeout",
                    error_message="Connection timeout after 3 attempts",
                )
            time.sleep(backoff_base ** attempt)

        except Exception as e:
            return CheckError(
                check_id=check_id,
                error_type="unknown",
                error_message=str(e),
            )

    return CheckError(check_id=check_id, error_type="unknown", error_message="Max retries exceeded")
