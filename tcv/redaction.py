import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SENSITIVE_KEYS = {"token", "auth", "authorization", "key", "apikey", "jwt", "session"}


def redact_token(value: str) -> str:
    if not value:
        return value
    return "[REDACTED]"


def redact_url(url: str) -> str:
    split = urlsplit(url)
    pairs = []
    for key, value in parse_qsl(split.query, keep_blank_values=True):
        pairs.append((key, "[REDACTED]" if key.lower() in SENSITIVE_KEYS else value))
    return urlunsplit((split.scheme, split.netloc, split.path, urlencode(pairs), ""))


def redact_text(text: str) -> str:
    return re.sub(r"(?i)(token|apikey|authorization)=([^&\s]+)", r"\1=[REDACTED]", text)
