import json
import logging
from datetime import datetime

from sqlalchemy.orm import Session

from storage.database import AuditLog

logger = logging.getLogger(__name__)


class AuditStore:
    """Append-only audit log."""

    def __init__(self, session: Session):
        self.session = session

    def log(
        self,
        action: str,
        entity_type: str | None = None,
        entity_id: str | None = None,
        details: dict | None = None,
        actor: str = "agent",
    ):
        entry = AuditLog(
            timestamp=datetime.utcnow(),
            actor=actor,
            action=action,
            entity_type=entity_type,
            entity_id=str(entity_id) if entity_id else None,
            details=json.dumps(details or {}, default=str),
        )
        self.session.add(entry)
        logger.debug("[audit] %s | %s | %s:%s", actor, action, entity_type, entity_id)

    def get_recent(self, limit: int = 50) -> list:
        return (
            self.session.query(AuditLog)
            .order_by(AuditLog.timestamp.desc())
            .limit(limit)
            .all()
        )
