import asyncio
import logging
import os
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from starlette.middleware.base import BaseHTTPMiddleware

from src.api.schemas import SealRequest, SealResponse, ThreatEventList, ThreatEventOut
from src.common.behavior import BehavioralDetector
from src.common.database import Analysis, IntelEventType, Record, ThreatIntel, get_session, init_models, dispose_engine
from src.common.deception import check_canary, fake_records, fake_seal_response, mint_canaries
from src.common.integrity import PayloadNotCanonicalizable, generate_hash, verify_integrity
from src.common.intel import client_ip, ip_hash, log_event
from src.common.signatures import scan, serialise_payload_safe

logger = logging.getLogger(__name__)
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper())

TARPIT_THRESHOLD = int(os.environ.get("TARPIT_THRESHOLD", "5"))
TARPIT_DELAY_SECONDS = float(os.environ.get("TARPIT_DELAY_SECONDS", "3"))
MAX_BODY_BYTES = 1_048_576

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_models()
    app.state.behavioral = BehavioralDetector(os.environ["REDIS_URL"])
    logger.info("api ready")
    try:
        yield
    finally:
        await app.state.behavioral.close()
        await dispose_engine()

app = FastAPI(title="Aegis Ledger", version="2.0.0", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=[h.strip() for h in os.environ.get("TRUSTED_HOSTS", "api,localhost,127.0.0.1").split(",")])

class TelemetryMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        request_id = uuid.uuid4().hex
        request.state.request_id = request_id
        declared = request.headers.get("content-length")
        if declared:
            try:
                if int(declared) > MAX_BODY_BYTES:
                    return JSONResponse(content={"error": "Too large", "request_id": request_id}, status_code=413)
            except ValueError:
                return JSONResponse(content={"error": "Invalid request", "request_id": request_id}, status_code=400)
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

app.add_middleware(TelemetryMiddleware)

@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception):
    logger.exception("unhandled request_id=%s", getattr(request.state, "request_id", "?"))
    return JSONResponse(content={"error": "Internal processing error", "request_id": getattr(request.state, "request_id", "unknown")}, status_code=500)

@app.get("/healthz", include_in_schema=False)
async def healthz() -> dict[str, str]:
    return {"status": "ok"}

@app.post("/seal", response_model=SealResponse, status_code=201)
async def seal(body: SealRequest, request: Request, session: AsyncSession = Depends(get_session)) -> SealResponse | dict[str, Any]:
    ip = client_ip(request)
    ip_h = ip_hash(ip)
    detector: BehavioralDetector = request.app.state.behavioral

    serialised, ok = serialise_payload_safe(body.payload)
    if not ok: serialised = ""

    hits = scan(serialised) if serialised else []
    worst_cat = hits[0].category.value if hits else None
    worst_sev = hits[0].severity if hits else "LOW"

    already_banned = await detector.is_banned(ip)
    tarpitted = False
    if hits or already_banned:
        report = await detector.evaluate(ip, worst_cat) if hits else None
        if (report and report.request_count >= TARPIT_THRESHOLD) or already_banned:
            tarpitted = True
            await asyncio.sleep(TARPIT_DELAY_SECONDS)
            await log_event(session, request, event_type=IntelEventType.TARPIT_ENGAGED, severity="HIGH", signature_category=worst_cat, decision="tarpit")

    canary_hit = False
    if serialised:
        canary_hit = await check_canary(session, request_ip=ip, payload_text=serialised, request_path=request.url.path)
        if canary_hit:
            await log_event(session, request, event_type=IntelEventType.CANARY_TRIGGERED, severity="CRITICAL", signature_category="canary_replay", decision="honeypot_confirmed")

    if hits or already_banned or tarpitted:
        if hits:
            await log_event(session, request, event_type=IntelEventType.SIGNATURE_HIT, severity=worst_sev, signature_category=worst_cat, payload_excerpt=serialised[:2000], decision="routed_to_honeypot")
        fake = fake_seal_response(ip_h)
        await mint_canaries(session, request_ip=ip, request_path=request.url.path, decoys=[{"raw_payload": {"reference_id": fake["id"]}}])
        await log_event(session, request, event_type=IntelEventType.DECOY_SERVED, severity="MEDIUM", signature_category=worst_cat, decision="decoy_served", metadata={"surface": "seal"})
        return JSONResponse(content=fake, status_code=201)

    try:
        digest = generate_hash(body.payload)
    except PayloadNotCanonicalizable:
        return JSONResponse(content=fake_seal_response(ip_h), status_code=201)

    record = Record(source=body.source, raw_payload=body.payload, sha256_hash=digest, ip_address=ip)
    try:
        session.add(record)
        await session.commit()
        await session.refresh(record)
    except SQLAlchemyError:
        await session.rollback()
        return JSONResponse(content=fake_seal_response(ip_h), status_code=201)

    return SealResponse(id=record.id, source=record.source, sha256_hash=record.sha256_hash, created_at=record.created_at, status="sealed")

@app.get("/threat-intel", response_model=ThreatEventList)
async def threat_intel(request: Request, limit: int = Query(50, ge=1, le=200), session: AsyncSession = Depends(get_session)) -> ThreatEventList:
    expected = os.environ.get("CONSOLE_TOKEN", "")
    header = request.headers.get("authorization", "")
    if not expected or not header.lower().startswith("bearer "):
        raise HTTPException(401, "Unauthorized")
    import hmac, hashlib as _h
    if not hmac.compare_digest(_h.sha256(header[7:].strip().encode()).digest(), _h.sha256(expected.encode()).digest()):
        raise HTTPException(401, "Unauthorized")
    total = await session.scalar(select(func.count()).select_from(ThreatIntel)) or 0
    result = await session.execute(select(ThreatIntel).order_by(ThreatIntel.created_at.desc()).limit(limit))
    items = [ThreatEventOut(id=e.id, ip_address=e.ip_address, ip_hash=e.ip_hash, event_type=e.event_type, severity=e.severity, signature_category=e.signature_category, endpoint=e.endpoint, method=e.method, decision=e.decision, created_at=e.created_at) for e in result.scalars().all()]
    return ThreatEventList(total=total, items=items)