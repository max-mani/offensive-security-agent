import os
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()
DB_PATH = os.getenv("DB_PATH", "storage/findings.db")


class FindingRecord(Base):
    """Persistent finding across scan runs (one row per fingerprint)."""

    __tablename__ = "findings"

    id = Column(String, primary_key=True)
    fingerprint = Column(String, nullable=False, unique=True, index=True)
    check_id = Column(String, nullable=False)
    domain = Column(String, nullable=False)
    resource_id = Column(String, nullable=False)
    resource_arn = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    title = Column(String, nullable=False)
    status = Column(String, nullable=False, default="opened")
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    sla_deadline = Column(DateTime, nullable=True)
    sla_breached = Column(Boolean, default=False)
    sla_alert_sent = Column(Boolean, default=False)
    confidence_score = Column(Integer, nullable=False)
    business_impact = Column(Text, nullable=True)
    remediation_command = Column(Text, nullable=True)
    raw_evidence = Column(Text, nullable=True)
    scan_run_id = Column(String, nullable=True)
    consecutive_misses = Column(Integer, default=0)
    auto_resolved = Column(Boolean, default=False)
    escalated = Column(Boolean, default=False)


class ScanRun(Base):
    """One record per scan execution."""

    __tablename__ = "scan_runs"

    id = Column(String, primary_key=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    health = Column(String, nullable=True)
    config_name = Column(String, nullable=True)
    total_findings = Column(Integer, default=0)
    new_findings = Column(Integer, default=0)
    updated_findings = Column(Integer, default=0)
    resolved_findings = Column(Integer, default=0)
    reopened_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    posture_score = Column(Float, nullable=True)


class AuditLog(Base):
    """Append-only audit trail."""

    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    actor = Column(String, nullable=False)
    action = Column(String, nullable=False)
    entity_type = Column(String, nullable=True)
    entity_id = Column(String, nullable=True)
    details = Column(Text, nullable=True)


class ScanHealthRecord(Base):
    """Per-check health for each scan run."""

    __tablename__ = "scan_health"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_run_id = Column(String, nullable=False)
    check_id = Column(String, nullable=False)
    domain = Column(String, nullable=False)
    status = Column(String, nullable=False)
    error_type = Column(String, nullable=True)
    error_message = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)


_engine = None
_SessionLocal = None


def get_engine():
    global _engine
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    if _engine is None:
        _engine = create_engine(f"sqlite:///{DB_PATH}", echo=False)
    return _engine


def init_db():
    """Create all tables if they don't exist."""
    engine = get_engine()
    Base.metadata.create_all(engine)
    return engine


def get_session():
    global _SessionLocal
    engine = init_db()
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=engine)
    return _SessionLocal()


def reset_engine(db_path: str | None = None):
    """Reset engine/session factory (for tests)."""
    global _engine, _SessionLocal, DB_PATH
    if db_path is not None:
        DB_PATH = db_path
        os.environ["DB_PATH"] = db_path
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None
