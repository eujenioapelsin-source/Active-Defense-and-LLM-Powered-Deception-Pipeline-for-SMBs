from __future__ import annotations
from datetime import datetime
from typing import Any
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field
from src.common.database import AttackVector, IntelEventType, MitigationAction, ThreatLevel

class SealRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    source: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
    payload: dict[str, Any]

class SealResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: UUID
    source: str
    sha256_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: datetime
    status: str = "sealed"

class AnalysisOut(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    threat_level: ThreatLevel
    attack_vector: AttackVector
    mitigation_action: MitigationAction
    reasoning: str = Field(min_length=1, max_length=2000)
    model_name: str = Field(min_length=1, max_length=64)
    created_at: datetime

class ThreatEventOut(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: UUID
    ip_address: str
    ip_hash: str
    event_type: IntelEventType
    severity: ThreatLevel
    signature_category: str | None = None
    endpoint: str
    method: str
    decision: str
    created_at: datetime

class ThreatEventList(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    total: int = Field(ge=0)
    items: list[ThreatEventOut]