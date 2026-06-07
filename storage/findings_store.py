"""Read helpers for dashboard and API."""

from datetime import datetime

from storage.database import AuditLog, FindingRecord, ScanHealthRecord, ScanRun, get_session


def get_open_findings(limit: int = 200) -> list[dict]:
    session = get_session()
    try:
        records = (
            session.query(FindingRecord)
            .filter(FindingRecord.status.in_(["opened", "updated", "re-opened"]))
            .order_by(FindingRecord.last_seen.desc())
            .limit(limit)
            .all()
        )
        return [_finding_to_dict(r) for r in records]
    finally:
        session.close()


def get_all_findings(limit: int = 200) -> list[dict]:
    session = get_session()
    try:
        records = (
            session.query(FindingRecord)
            .order_by(FindingRecord.last_seen.desc())
            .limit(limit)
            .all()
        )
        return [_finding_to_dict(r) for r in records]
    finally:
        session.close()


def get_recent_scan_runs(limit: int = 30) -> list[dict]:
    session = get_session()
    try:
        runs = (
            session.query(ScanRun)
            .order_by(ScanRun.started_at.desc())
            .limit(limit)
            .all()
        )
        return [_scan_run_to_dict(r) for r in runs]
    finally:
        session.close()


def get_latest_scan_run() -> dict | None:
    runs = get_recent_scan_runs(limit=1)
    return runs[0] if runs else None


def get_audit_tail(limit: int = 50) -> list[dict]:
    session = get_session()
    try:
        entries = (
            session.query(AuditLog)
            .order_by(AuditLog.timestamp.desc())
            .limit(limit)
            .all()
        )
        return [_audit_to_dict(e) for e in entries]
    finally:
        session.close()


def get_scan_health(scan_run_id: str | None = None) -> list[dict]:
    session = get_session()
    try:
        if not scan_run_id:
            latest = (
                session.query(ScanRun)
                .order_by(ScanRun.started_at.desc())
                .first()
            )
            if not latest:
                return []
            scan_run_id = latest.id

        records = (
            session.query(ScanHealthRecord)
            .filter(ScanHealthRecord.scan_run_id == scan_run_id)
            .order_by(ScanHealthRecord.check_id)
            .all()
        )
        return [_health_to_dict(r) for r in records]
    finally:
        session.close()


def get_sla_breached_count() -> int:
    session = get_session()
    try:
        return (
            session.query(FindingRecord)
            .filter(
                FindingRecord.sla_breached == True,  # noqa: E712
                FindingRecord.status.in_(["opened", "updated", "re-opened"]),
            )
            .count()
        )
    finally:
        session.close()


def _finding_to_dict(r: FindingRecord) -> dict:
    return {
        "id": r.id,
        "fingerprint": r.fingerprint,
        "check_id": r.check_id,
        "domain": r.domain,
        "resource_id": r.resource_id,
        "resource_arn": r.resource_arn,
        "severity": r.severity,
        "title": r.title,
        "status": r.status,
        "first_seen": r.first_seen.isoformat() if r.first_seen else None,
        "last_seen": r.last_seen.isoformat() if r.last_seen else None,
        "resolved_at": r.resolved_at.isoformat() if r.resolved_at else None,
        "sla_deadline": r.sla_deadline.isoformat() if r.sla_deadline else None,
        "sla_breached": r.sla_breached,
        "escalated": r.escalated,
        "confidence_score": r.confidence_score,
        "business_impact": r.business_impact,
        "remediation_command": r.remediation_command,
        "consecutive_misses": r.consecutive_misses,
        "auto_resolved": r.auto_resolved,
    }


def _scan_run_to_dict(r: ScanRun) -> dict:
    return {
        "id": r.id,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        "duration_seconds": r.duration_seconds,
        "health": r.health,
        "config_name": r.config_name,
        "total_findings": r.total_findings,
        "new_findings": r.new_findings,
        "updated_findings": r.updated_findings,
        "resolved_findings": r.resolved_findings,
        "reopened_findings": r.reopened_findings,
        "critical_count": r.critical_count,
        "high_count": r.high_count,
        "medium_count": r.medium_count,
        "low_count": r.low_count,
        "posture_score": r.posture_score,
    }


def _audit_to_dict(e: AuditLog) -> dict:
    return {
        "id": e.id,
        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        "actor": e.actor,
        "action": e.action,
        "entity_type": e.entity_type,
        "entity_id": e.entity_id,
        "details": e.details,
    }


def _health_to_dict(r: ScanHealthRecord) -> dict:
    return {
        "id": r.id,
        "scan_run_id": r.scan_run_id,
        "check_id": r.check_id,
        "domain": r.domain,
        "status": r.status,
        "error_type": r.error_type,
        "error_message": r.error_message,
        "timestamp": r.timestamp.isoformat() if r.timestamp else None,
    }
