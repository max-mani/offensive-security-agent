from abc import ABC, abstractmethod
import logging
from typing import List, Union

import boto3

from models.config import CheckConfig
from models.finding import RawFinding
from models.report import CheckError

logger = logging.getLogger(__name__)

CheckResult = Union[List[RawFinding], CheckError]


class BaseCheck(ABC):
    """Base class for all security checks."""

    def __init__(self, config: CheckConfig, session: boto3.Session):
        self.config = config
        self.session = session
        self.check_id = config.id

    @abstractmethod
    def run(self) -> CheckResult:
        """Execute the check. Return findings or an error."""
        pass

    def _make_arn(self, service: str, resource: str, region: str = "", account: str = "") -> str:
        return f"arn:aws:{service}:{region}:{account}:{resource}"

    def _log(self, message: str) -> None:
        logger.info("[%s] %s", self.check_id, message)

    def _get_account_id(self) -> str:
        return self.session.client("sts").get_caller_identity()["Account"]
