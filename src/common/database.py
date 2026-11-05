"""
Persistent state — Record v2, Analysis, ThreatIntel, Canary.
"""
from __future__ import annotations
import uuid
from datetime import datetime
from enum import StrEnum
import os
from urllib.parse import quote_plus
from functools import lru_cache

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine, AsyncEngine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

def _database_url() -> str:
    user = quote_plus(os.environ.get("POSTGRES_USER", "aegis"))
    pwd = quote_plus(os.environ["POSTGRES_PASSWORD"])
    host = os.environ.get("POSTGRES_HOST", "db")
    port = os.environ.get("POSTGRES_PORT", "5432")
    db = os.environ.get("POSTGRES_DB", "aegis")
    return f"postgresql+asyncpg://{user}:{pwd}@{host}:{port}/{db}"

class Base(DeclarativeBase):
    pass

class ThreatLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AttackVector(StrEnum):
    NONE = "None"
    PROMPT_INJECTION = "Prompt Injection"
    DATA_EXFILTRATION = "Data Exfiltration"
    SQL_INJECTION = "SQL Injection"
    COMMAND_INJECTION = "Command Injection"
    XSS = "XSS"
    PORT_SCAN = "Port Scan"
    RECON = "Recon"
    CREDENTIAL_STUFFING = "Credential Stuffing"
    ANOMALOUS_BEHAVIOR = "Anomalous Behavior"
    UNKNOWN = "Unknown"

class MitigationAction(StrEnum):
    NONE = "None"
    QUARANTINED = "Quarantined"
    ROUTED_TO_HONEYPOT = "Routed to Honeypot"
    BANNED = "Banned"

class IntelEventType(StrEnum):
    SIGNATURE_HIT = "signature_hit"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    TARPIT_ENGAGED = "tarpit_engaged"
    DECOY_SERVED = "decoy_served"
    CANARY_TRIGGERED = "canary_triggered"
    LLM_ESCALATION = "llm_escalation"

class Record(Base):
    __tablename__ = "records"
    __table_args__ = (
        CheckConstraint("length(sha256_hash) = 64", name="ck_records_hash_len"),
        CheckConstraint("length(source) BETWEEN 1 AND 128", name="ck_records_source_len"),
        Index("ix_records_sha256_hash", "sha256_hash"),
        Index("ix_records_created_at", "created_at"),
    )
    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    raw_payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    analysis: Mapped["Analysis | None"] = relationship(back_populates="record", uselist=False, cascade="all, delete-orphan", lazy="selectin")

class Analysis(Base):
    __tablename__ = "analyses"
    __table_args__ = (
        CheckConstraint("threat_level IN ('LOW','MEDIUM','HIGH','CRITICAL')", name="ck_analyses_level"),
        CheckConstraint("mitigation_action IN ('None','Quarantined','Routed to Honeypot','Banned')", name="ck_analyses_action"),
    )
    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    record_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("records.id", ondelete="CASCADE"), nullable=False, unique=True)
    threat_level: Mapped[str] = mapped_column(String(16), nullable=False)
    attack_vector: Mapped[str] = mapped_column(String(64), nullable=False)
    mitigation_action: Mapped[str] = mapped_column(String(32), nullable=False)
    reasoning: Mapped[str] = mapped_column(Text, nullable=False)
    model_name: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    record: Mapped[Record] = relationship(back_populates="analysis")

class ThreatIntel(Base):
    __tablename__ = "threat_intel"
    __table_args__ = (Index("ix_ti_created_at", "created_at"), Index("ix_ti_ip", "ip_address"))
    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    ip_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    signature_category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    endpoint: Mapped[str] = mapped_column(String(256), nullable=False)
    method: Mapped[str] = mapped_column(String(8), nullable=False)
    payload_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    decision: Mapped[str] = mapped_column(String(32), nullable=False, default="deception")
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

class Canary(Base):
    __tablename__ = "canaries"
    __table_args__ = (UniqueConstraint("token", name="uq_canary_token"),)
    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token: Mapped[str] = mapped_column(String(64), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    ip_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    issued_path: Mapped[str] = mapped_column(String(256), nullable=False)
    triggered: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    triggered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    triggered_request: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

@lru_cache(maxsize=1)
def get_engine() -> AsyncEngine:
    return create_async_engine(
        _database_url(), echo=False, pool_size=5, max_overflow=5, pool_pre_ping=True, pool_recycle=1800,
        connect_args={"timeout": 10, "command_timeout": 15, "server_settings": {"application_name": "aegis-ledger", "statement_timeout": "15000"}}
    )

@lru_cache(maxsize=1)
def get_session_factory() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(get_engine(), expire_on_commit=False, autoflush=False)

async def get_session():
    async with get_session_factory()() as session:
        try: yield session
        except Exception: await session.rollback(); raise

async def init_models() -> None:
    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
async def dispose_engine() -> None:
    await get_engine().dispose()
    get_engine.cache_clear()
    get_session_factory.cache_clear()
