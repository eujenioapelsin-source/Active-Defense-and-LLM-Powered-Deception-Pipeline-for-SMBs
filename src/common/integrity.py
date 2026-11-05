"""Cryptographic integrity primitives."""
from __future__ import annotations
import hashlib
import hmac
import json
from typing import Any, Mapping

class PayloadNotCanonicalizable(TypeError):
    pass

def _reject(obj: Any) -> None:
    raise PayloadNotCanonicalizable(f"non-canonicalizable type: {type(obj).__name__}")

def canonical_payload(payload: Mapping[str, Any]) -> bytes:
    if not isinstance(payload, Mapping):
        raise PayloadNotCanonicalizable("payload must be a mapping")
    try:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False, default=_reject)
    except (TypeError, ValueError) as exc:
        raise PayloadNotCanonicalizable(str(exc)) from exc
    return encoded.encode("utf-8")

def generate_hash(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_payload(payload)).hexdigest()

def verify_integrity(record: Any) -> bool:
    try:
        payload = record.raw_payload
        if isinstance(payload, (str, bytes)):
            payload = json.loads(payload)
        stored = record.sha256_hash
        if not isinstance(stored, str) or len(stored) != 64:
            return False
        expected = generate_hash(payload)
    except Exception:
        return False
    return hmac.compare_digest(expected, stored.lower())