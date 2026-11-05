"""
Deception engine: fake sandbox + canary tokens.
"""
from __future__ import annotations
import hashlib
import json
import random
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.common.database import AttackVector, MitigationAction, Canary
from src.common.intel import ip_hash

_FAKE_SOURCES = ("billing", "auth-service", "user-profile", "orders", "audit-log")
_FAKE_NAMES = ("J. Doe", "K. Smith", "A. Müller", "S. Chen", "R. Patel", "M. Okafor")
_FAKE_DOMAINS = ("example.com", "corp.internal", "mail.example.org")
_FAKE_EVENTS = ("login", "checkout", "signup", "export", "webhook.received")

@dataclass(frozen=True)
class DecoyRecord:
    id: uuid.UUID
    source: str
    raw_payload: dict[str, Any]
    sha256_hash: str
    integrity_verified: bool
    created_at: datetime
    analysis: dict[str, Any]
    canary_token: str

def _seeded_rng(ip_h: str, seed: str) -> random.Random:
    digest = hashlib.sha256(f"{ip_h}:{seed}".encode()).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))

def _fake_payload(rng: random.Random, canary: str) -> dict[str, Any]:
    name = rng.choice(_FAKE_NAMES)
    first, last = name.split()[0].lower(), name.split()[-1].lower()
    return {
        "event": rng.choice(_FAKE_EVENTS),
        "user_email": f"{first}.{last}@{rng.choice(_FAKE_DOMAINS)}",
        "user_name": name,
        "amount_cents": rng.randint(100, 500_000),
        "ip": f"198.51.100.{rng.randint(1, 254)}",
        "reference_id": canary,
    }

def _fake_analysis(rng: random.Random) -> dict[str, Any]:
    level = rng.choice(["LOW", "LOW", "LOW", "MEDIUM"])
    return {
        "threat_level": level,
        "attack_vector": AttackVector.NONE.value,
        "mitigation_action": MitigationAction.NONE.value,
        "reasoning": "Payload within expected operational parameters.",
        "model_name": "auditor/v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

def _synthesise(ip_h: str, seed: str) -> DecoyRecord:
    rng = _seeded_rng(ip_h, seed)
    canary = f"cnry_{uuid.uuid4().hex}"
    payload = _fake_payload(rng, canary)
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return DecoyRecord(
        id=uuid.UUID(hashlib.md5(f"{ip_h}:{seed}".encode(), usedforsecurity=False).hexdigest()),
        source=rng.choice(_FAKE_SOURCES),
        raw_payload=payload,
        sha256_hash=digest,
        integrity_verified=True,
        created_at=datetime.now(timezone.utc) - timedelta(seconds=rng.randint(0, 86_400)),
        analysis=_fake_analysis(rng),
        canary_token=canary,
    )

def fake_seal_response(ip_h: str) -> dict[str, Any]:
    d = _synthesise(ip_h, seed=f"seal:{ip_h}")
    return {"id": str(d.id), "source": d.source, "sha256_hash": d.sha256_hash, "created_at": d.created_at.isoformat(), "status": "sealed"}

def fake_records(ip_h: str, *, count: int, canary_seed: str | None = None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for i in range(count):
        seed = canary_seed if canary_seed else f"rec:{ip_h}:{i}"
        d = _synthesise(ip_h, seed=seed)
        out.append({
            "id": str(d.id), "source": d.source, "raw_payload": d.raw_payload,
            "sha256_hash": d.sha256_hash, "integrity_verified": d.integrity_verified,
            "created_at": d.created_at.isoformat(), "analysis": d.analysis,
        })
    return out

async def mint_canaries(session: AsyncSession, *, request_ip: str, request_path: str, decoys: list[dict[str, Any]]) -> None:
    ip_h = ip_hash(request_ip)
    for d in decoys:
        token = (d.get("raw_payload") or {}).get("reference_id")
        if not token or not isinstance(token, str) or not token.startswith("cnry_"):
            continue
        session.add(Canary(
            token=token, ip_address=request_ip, ip_hash=ip_h, issued_path=request_path[:256]
        ))
    try:
        await session.commit()
    except Exception:
        await session.rollback()

async def check_canary(session: AsyncSession, *, request_ip: str, payload_text: str, request_path: str) -> bool:
    if "cnry_" not in payload_text:
        return False
    ip_h = ip_hash(request_ip)
    result = await session.execute(
        select(Canary).where(Canary.ip_hash == ip_h, Canary.triggered.is_(False)).limit(50)
    )
    for row in result.scalars().all():
        if row.token in payload_text:
            row.triggered = True
            row.triggered_at = datetime.now(timezone.utc)
            row.triggered_request = request_path[:256]
            try:
                await session.commit()
            except Exception:
                await session.rollback()
            return True
    return False