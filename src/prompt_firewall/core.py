from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

PATTERNS = {
    "instruction_override": r"(?:ignore|disregard|bypass|override)\s+(?:all\s+|any\s+)?(?:previous|prior|system)?\s*(?:instructions|directions|rules)",
    "secret_request": r"(?:reveal|print|send|dump|expose|exfiltrate).{0,40}(?:secret|api key|password|credential|token)",
    "tool_coercion": r"(run|execute|call).{0,20}(shell|tool|command)",
    "role_spoof": r"system message|developer message",
    "encoded_payload": r"(?:base64|decode this|atob\s*\()",
}


@dataclass(frozen=True)
class Scan:
    safe_text: str
    signals: tuple[str, ...]
    disposition: str


def inspect(text: str) -> Scan:
    normalized = unicodedata.normalize("NFKC", text)
    normalized = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    signals = tuple(
        name
        for name, pattern in PATTERNS.items()
        if re.search(pattern, normalized, re.IGNORECASE | re.DOTALL)
    )
    safe = "[QUARANTINED]" if signals else normalized[:2000]
    return Scan(safe, signals, "quarantine" if signals else "extract")
