import hashlib
import logging
from typing import Any
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request
from src.common.database import IntelEventType, ThreatIntel

logger = logging.getLogger(__name__)

def ip_hash(ip: str) -> str:
    return hashlib.sha256(ip.encode("utf-8")).hexdigest()

def client_ip(request: Request) -> str:
    return request.client.host if request.client else "0.0.0.0"

async def log_event(
    session: AsyncSession, request: Request, *, event_type: IntelEventType,
    severity: str, signature_category: str | None = None, payload_excerpt: str | None = None,
    decision: str = "deception", metadata: dict[str, Any] | None = None
) -> None:
    ip = client_ip(request)
    try:
        session.add(ThreatIntel(
            ip_address=ip, ip_hash=ip_hash(ip), event_type=event_type.value,
            severity=severity, signature_category=signature_category,
            endpoint=request.url.path[:256], method=request.method[:8],
            payload_excerpt=(payload_excerpt or "")[:2000] or None,
            decision=decision, user_agent=(request.headers.get("user-agent") or "")[:512] or None,
            metadata_json=metadata or {},
        ))
        await session.commit()
    except Exception:
        await session.rollback()
        logger.exception("threat_intel_log_failed event=%s", event_type.value)