import re

PATTERNS = {
    "onion": re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.IGNORECASE),
    "tox_id": re.compile(r"\b[0-9A-Fa-f]{76}\b"),
    "pgp_public_key": re.compile(r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----", re.DOTALL),
    "btc": re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b", re.IGNORECASE),
    "xmr": re.compile(r"\b[48][1-9A-HJ-NP-Za-km-z]{94}(?:[1-9A-HJ-NP-Za-km-z]{11})?\b"),
    "email": re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    "url": re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
    "hash": re.compile(r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b"),
}
