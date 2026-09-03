import re
from typing import Any


_SENSITIVE_KEY = re.compile(r"(authorization|api[_-]?key|password|secret|token|pepper|credential|private[_-]?key|integrity[_-]?key)", re.I)
_CONTENT_KEY = re.compile(r"(prompt|completion|input|output|response|content|instruction|message|tool[._-]?(argument|output|result|input)|gen_ai\.(input|output)\.)", re.I)
_BEARER = re.compile(r"Bearer\s+[A-Za-z0-9._~+/-]+", re.I)
_OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")
_AGENTGUARD_KEY = re.compile(r"\bagk_[A-Za-z0-9_-]{40,}\b")
_DATABASE_URL = re.compile(r"(postgres(?:ql)?://[^:/\s]+:)[^@\s]+(@)", re.I)


def redact(value: Any, *, capture_content: bool = False) -> Any:
    """Return a JSON-safe copy with credentials and content fields removed."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            key_text = str(key)
            if _SENSITIVE_KEY.search(key_text):
                result[key_text] = "[REDACTED]"
            elif not capture_content and _CONTENT_KEY.search(key_text):
                result[key_text] = "[CONTENT_CAPTURE_DISABLED]"
            else:
                result[key_text] = redact(item, capture_content=capture_content)
        return result
    if isinstance(value, list):
        return [redact(item, capture_content=capture_content) for item in value]
    if isinstance(value, str):
        value = _BEARER.sub("Bearer [REDACTED]", value)
        value = _OPENAI_KEY.sub("[REDACTED]", value)
        value = _AGENTGUARD_KEY.sub("[REDACTED]", value)
        return _DATABASE_URL.sub(r"\1[REDACTED]\2", value)
    return value
