#!/usr/bin/env python3
"""Download an explicit, host-scoped candidate list with hard byte limits."""

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
from urllib.parse import unquote, urljoin, urlparse

import requests

from tcv.common import utc_timestamp
from tcv.network import add_network_arguments, session_from_args
from tcv.redaction import redact_text, redact_url


CHUNK_SIZE = 64 * 1024
REQUEST_TIMEOUT = (15, 60)
MAX_REDIRECTS = 5


def normalized_hosts(values):
    return {value.strip().lower().rstrip(".") for value in values if value.strip()}


def candidate_status(url, allowed_hosts, blocked_extensions, allow_any_host=False):
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    extension = Path(parsed.path).suffix.lower()
    if parsed.scheme not in ("http", "https") or not host:
        return "blocked_scheme"
    if not allow_any_host and host not in allowed_hosts:
        return "blocked_host"
    if extension in blocked_extensions:
        return "blocked_ext"
    return "eligible"


def download_candidate(
    session,
    url,
    output_dir,
    remaining_bytes,
    allowed_hosts=None,
    blocked_extensions=None,
    allow_any_host=True,
):
    if remaining_bytes <= 0:
        return {"status": "max_mb_exceeded", "size": 0, "sha256": "", "final_url": url}

    current_url = url
    response = None
    for _redirect in range(MAX_REDIRECTS + 1):
        response = session.get(
            current_url,
            timeout=REQUEST_TIMEOUT,
            stream=True,
            allow_redirects=False,
        )
        if not getattr(response, "is_redirect", False):
            break
        location = response.headers.get("Location", "")
        next_url = urlparse(current_url)._replace(fragment="").geturl()
        if location:
            next_url = urljoin(current_url, location)
        response.close()
        redirect_status = candidate_status(
            next_url,
            allowed_hosts or set(),
            blocked_extensions or set(),
            allow_any_host,
        )
        if redirect_status != "eligible":
            return {
                "status": "redirect_" + redirect_status,
                "size": 0,
                "sha256": "",
                "final_url": next_url,
            }
        current_url = next_url
    else:
        return {"status": "too_many_redirects", "size": 0, "sha256": "", "final_url": current_url}

    try:
        response.raise_for_status()
        final_url = response.url or url
        redirect_status = candidate_status(
            final_url,
            allowed_hosts or set(),
            blocked_extensions or set(),
            allow_any_host,
        )
        if redirect_status != "eligible":
            return {
                "status": "redirect_" + redirect_status,
                "size": 0,
                "sha256": "",
                "final_url": final_url,
            }
        content_length = response.headers.get("Content-Length")
        if content_length:
            try:
                declared_length = int(content_length)
            except ValueError:
                declared_length = 0
            if declared_length > remaining_bytes:
                return {"status": "max_mb_exceeded", "size": 0, "sha256": "", "final_url": final_url}

        digest = hashlib.sha256()
        size = 0
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(dir=output_dir, delete=False) as handle:
                temp_path = Path(handle.name)
                for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                    if not chunk:
                        continue
                    if size + len(chunk) > remaining_bytes:
                        handle.close()
                        temp_path.unlink(missing_ok=True)
                        return {
                            "status": "max_mb_exceeded",
                            "size": size,
                            "sha256": "",
                            "final_url": final_url,
                        }
                    handle.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
        except Exception:
            if temp_path:
                temp_path.unlink(missing_ok=True)
            raise

        sha256 = digest.hexdigest()
        destination = output_dir / sha256
        os.replace(temp_path, destination)
        return {
            "status": "downloaded",
            "size": size,
            "sha256": sha256,
            "final_url": final_url,
            "content_type": response.headers.get("Content-Type", ""),
        }
    finally:
        response.close()


def load_candidates(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list) or not all(isinstance(value, str) for value in data):
        raise ValueError("candidate input must be a JSON array of URL strings")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="candidates.json")
    parser.add_argument("--out-dir", default="downloads")
    parser.add_argument("--allowed-host", action="append", default=[])
    parser.add_argument(
        "--allow-any-host",
        action="store_true",
        help="Explicitly disable the host allow-list requirement.",
    )
    parser.add_argument("--max-files", type=int, default=20)
    parser.add_argument("--max-mb", type=float, default=100)
    parser.add_argument("--blocked-ext", default=".exe,.dll,.js")
    add_network_arguments(parser)
    args = parser.parse_args()

    allowed_hosts = normalized_hosts(args.allowed_host)
    if not allowed_hosts and not args.allow_any_host:
        parser.error("provide --allowed-host at least once, or explicitly use --allow-any-host")
    if args.max_files < 1 or args.max_mb <= 0:
        parser.error("--max-files and --max-mb must be positive")
    # Settle how requests leave this machine before anything touches the disk.
    session = session_from_args(parser, args)

    blocked = {extension.strip().lower() for extension in args.blocked_ext.split(",") if extension.strip()}
    budget = int(args.max_mb * 1024 * 1024)
    output_dir = Path(args.out_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    metadata_path = output_dir / "metadata.jsonl"

    try:
        candidates = load_candidates(args.input)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))

    total = 0
    downloaded = 0
    with metadata_path.open("w", encoding="utf-8") as metadata:
        for url in candidates:
            if downloaded >= args.max_files:
                break
            record = {
                "ts": utc_timestamp(),
                "url": redact_url(url),
                "filename": unquote(Path(urlparse(url).path).name),
                "size": 0,
                "sha256": "",
                "status": candidate_status(url, allowed_hosts, blocked, args.allow_any_host),
            }
            if record["status"] == "eligible":
                try:
                    result = download_candidate(
                        session,
                        url,
                        output_dir,
                        budget - total,
                        allowed_hosts,
                        blocked,
                        args.allow_any_host,
                    )
                    record.update(result)
                    record["final_url"] = redact_url(record.get("final_url", url))
                    if record["status"] == "downloaded":
                        total += record["size"]
                        downloaded += 1
                except requests.RequestException as exc:
                    record["status"] = "error"
                    record["error"] = redact_text(str(exc))
            metadata.write(json.dumps(record, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
