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


def get_findings_by_status(status: str, limit: int = 200) -> list[dict]:
    """Return findings matching a specific status value."""
    session = get_session()
    try:
        records = (
            session.query(FindingRecord)
            .filter(FindingRecord.status == status)
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


def get_escalated_count() -> int:
    session = get_session()
    try:
        return (
            session.query(FindingRecord)
            .filter(FindingRecord.escalated == True)  # noqa: E712
            .count()
        )
    finally:
        session.close()


def get_lifecycle_counts() -> dict[str, int]:
    session = get_session()
    try:
        counts = {"opened": 0, "updated": 0, "resolved": 0, "re-opened": 0}
        for status in counts:
            counts[status] = (
                session.query(FindingRecord).filter(FindingRecord.status == status).count()
            )
        return counts
    finally:
        session.close()


def get_total_findings_count() -> int:
    session = get_session()
    try:
        return session.query(FindingRecord).count()
    finally:
        session.close()


def get_scan_run_count() -> int:
    session = get_session()
    try:
        return session.query(ScanRun).count()
    finally:
        session.close()


def delete_scan_run(scan_run_id: str) -> bool:
    """Delete one L3 scan run; clear all L3 data if it was the last run."""
    session = get_session()
    try:
        run = session.query(ScanRun).filter_by(id=scan_run_id).first()
        if not run:
            return False
        session.query(ScanHealthRecord).filter_by(scan_run_id=scan_run_id).delete()
        session.delete(run)
        session.commit()

        remaining = session.query(ScanRun).count()
        if remaining == 0:
            session.query(FindingRecord).delete()
            session.query(AuditLog).delete()
            session.query(ScanHealthRecord).delete()
            session.commit()
        return True
    finally:
        session.close()


def clear_all_data() -> dict[str, int]:
    """Delete all L3 persistence data. Returns row counts per table."""
    session = get_session()
    try:
        counts = {
            "findings": session.query(FindingRecord).delete(),
            "scan_runs": session.query(ScanRun).delete(),
            "audit_log": session.query(AuditLog).delete(),
            "scan_health": session.query(ScanHealthRecord).delete(),
        }
        session.commit()
        return counts
    finally:
        session.close()


def get_open_counts_by_severity() -> dict[str, int]:
    """Count open findings per severity directly in SQL."""
    session = get_session()
    try:
        counts = {s: 0 for s in ["critical", "high", "medium", "low"]}
        for severity in counts:
            counts[severity] = (
                session.query(FindingRecord)
                .filter(
                    FindingRecord.status.in_(["opened", "updated", "re-opened"]),
                    FindingRecord.severity == severity,
                )
                .count()
            )
        return counts
    finally:
        session.close()


def sync_sla_breached_flags() -> int:
    """Mark sla_breached on open findings past deadline (dashboard sync, no Slack)."""
    session = get_session()
    now = datetime.utcnow()
    try:
        overdue = (
            session.query(FindingRecord)
            .filter(
                FindingRecord.sla_deadline.isnot(None),
                FindingRecord.sla_deadline < now,
                FindingRecord.status.in_(["opened", "updated", "re-opened"]),
                FindingRecord.sla_breached == False,  # noqa: E712
            )
            .all()
        )
        for record in overdue:
            record.sla_breached = True
        if overdue:
            session.commit()
        return len(overdue)
    finally:
        session.close()


def get_sla_breached_count() -> int:
    """Open findings whose SLA deadline has passed (matches SLATracker logic)."""
    sync_sla_breached_flags()
    session = get_session()
    now = datetime.utcnow()
    try:
        return (
            session.query(FindingRecord)
            .filter(
                FindingRecord.sla_deadline.isnot(None),
                FindingRecord.sla_deadline < now,
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
