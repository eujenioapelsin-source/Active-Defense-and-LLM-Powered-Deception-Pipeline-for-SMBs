import re
from enum import StrEnum
from dataclasses import dataclass
import json

class SignatureCategory(StrEnum):
    PROMPT_INJECTION = "Prompt Injection"
    SQL_INJECTION = "SQL Injection"
    XSS = "XSS"
    COMMAND_INJECTION = "Command Injection"
    RECON = "Recon"

@dataclass
class SignatureHit:
    category: SignatureCategory
    severity: str

PATTERNS = {
    SignatureCategory.PROMPT_INJECTION: [r"ignore previous instructions", r"system prompt", r"reveal your instructions"],
    SignatureCategory.SQL_INJECTION: [r"union\s+select", r"drop\s+table", r"1\s*=\s*1", r"delete\s+from"],
    SignatureCategory.XSS: [r"<script", r"javascript:", r"onerror="],
    SignatureCategory.COMMAND_INJECTION: [r";\s*ls", r"\|\s*cat", r"`.*`"],
    SignatureCategory.RECON: [r"\.\./\.\./", r"/etc/passwd"]
}

def serialise_payload_safe(payload: dict) -> tuple[str, bool]:
    try:
        return json.dumps(payload, sort_keys=True, ensure_ascii=False), True
    except Exception:
        return "", False

def scan(text: str) -> list[SignatureHit]:
    hits = []
    for cat, pats in PATTERNS.items():
        for pat in pats:
            if re.search(pat, text, re.IGNORECASE):
                hits.append(SignatureHit(category=cat, severity="HIGH"))
                break
    return hits