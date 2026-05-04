#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from urllib.parse import urlparse

import requests

from tcv.common import sha256_bytes, utc_timestamp
from tcv.redaction import redact_url


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", default="candidates.json")
    p.add_argument("--out-dir", default="downloads")
    p.add_argument("--proxy", default="")
    p.add_argument("--allowed-host", action="append", default=[])
    p.add_argument("--max-files", type=int, default=20)
    p.add_argument("--max-mb", type=float, default=100)
    p.add_argument("--blocked-ext", default=".exe,.dll,.js")
    args = p.parse_args()

    blocked = {e.strip().lower() for e in args.blocked_ext.split(",") if e.strip()}
    budget = int(args.max_mb * 1024 * 1024)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    meta = out / "metadata.jsonl"
    session = requests.Session()
    if args.proxy:
        session.proxies.update({"http": args.proxy, "https": args.proxy})

    candidates = json.loads(Path(args.input).read_text(encoding="utf-8"))
    total = 0
    count = 0
    with meta.open("w", encoding="utf-8") as fh:
        for url in candidates:
            if count >= args.max_files:
                break
            parsed = urlparse(url)
            host = parsed.hostname or ""
            ext = Path(parsed.path).suffix.lower()
            status = "skipped"
            sha = ""
            size = 0
            if args.allowed_host and host not in args.allowed_host:
                status = "blocked_host"
            elif ext in blocked:
                status = "blocked_ext"
            else:
                try:
                    r = session.get(url, timeout=60)
                    r.raise_for_status()
                    data = r.content
                    size = len(data)
                    if total + size > budget:
                        status = "max_mb_exceeded"
                    else:
                        sha = sha256_bytes(data)
                        (out / sha).write_bytes(data)
                        total += size
                        count += 1
                        status = "downloaded"
                except Exception:
                    status = "error"
            fh.write(json.dumps({"ts": utc_timestamp(), "url": redact_url(url), "size": size, "sha256": sha, "status": status}) + "\n")


if __name__ == "__main__":
    main()
