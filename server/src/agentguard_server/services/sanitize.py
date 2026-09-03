from __future__ import annotations

import re
from typing import Any


SENSITIVE_KEY = re.compile(r"(authorization|api[_-]?key|password|secret|pepper|token|credential|private[_-]?key)", re.I)
CONTENT_KEY = re.compile(r"(prompt|input|output|response|content|instruction|tool|error|exception)", re.I)
SAFE_STRUCTURED_CONTENT_KEYS = {"error_type"}
BEARER = re.compile(r"Bearer\s+[A-Za-z0-9._~+/-]+", re.I)
OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")
AGENTGUARD_KEY = re.compile(r"\bagk_[A-Za-z0-9_-]{40,}\b")


def sanitize(value: Any, *, capture_content: bool) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if SENSITIVE_KEY.search(key_text):
                result[key_text] = "[REDACTED]"
            elif not capture_content and CONTENT_KEY.search(key_text) and key_text.lower() not in SAFE_STRUCTURED_CONTENT_KEYS:
                result[key_text] = "[CONTENT_CAPTURE_DISABLED]"
            else:
                result[key_text] = sanitize(item, capture_content=capture_content)
        return result
    if isinstance(value, list):
        return [sanitize(item, capture_content=capture_content) for item in value]
    if isinstance(value, str):
        value = BEARER.sub("Bearer [REDACTED]", value)
        value = OPENAI_KEY.sub("[REDACTED]", value)
        return AGENTGUARD_KEY.sub("[REDACTED]", value)
    return value
