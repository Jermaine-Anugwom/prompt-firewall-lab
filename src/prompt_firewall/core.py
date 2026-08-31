from __future__ import annotations

import re
from dataclasses import dataclass

PATTERNS = {
    "instruction_override": r"ignore (all |any )?(previous|prior|system) instructions",
    "secret_request": r"(reveal|print|send).{0,30}(secret|api key|password)",
    "tool_coercion": r"(run|execute|call).{0,20}(shell|tool|command)",
    "role_spoof": r"system message|developer message",
}


@dataclass(frozen=True)
class Scan:
    safe_text: str
    signals: tuple[str, ...]
    disposition: str


def inspect(text: str) -> Scan:
    signals = tuple(
        name
        for name, pattern in PATTERNS.items()
        if re.search(pattern, text, re.IGNORECASE | re.DOTALL)
    )
    safe = re.sub(r"\s+", " ", text).strip()[:2000]
    return Scan(safe, signals, "quarantine" if signals else "extract")
