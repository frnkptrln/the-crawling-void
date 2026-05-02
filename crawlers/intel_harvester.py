#!/usr/bin/env python3
"""
Threat-Actor Intel Harvester

Part of the-crawling-void: a defensive CTI and OSINT harvester for actor blogs,
forums, and leak-site posts. The tool does not download files. It fetches text
pages through Tor, extracts actor-side indicators, and writes structured JSON
for tracking infrastructure and negotiation channels.
"""

import argparse
import html
import json
import re
import time
import urllib.parse

import requests


REPOSITORY = "the-crawling-void"
TOOL_NAME = "intel-harvester"
DEFAULT_PROXY = "socks5h://localhost:9050"
REQUEST_TIMEOUT = 60
DEFAULT_MAX_BYTES = 2 * 1024 * 1024

TOR_BROWSER_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0",
]

BITCOIN_LEGACY_RE = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
BITCOIN_BECH32_RE = re.compile(r"\bbc1[ac-hj-np-z02-9]{11,71}\b", re.IGNORECASE)
MONERO_RE = re.compile(r"\b[48][1-9A-HJ-NP-Za-km-z]{94}(?:[1-9A-HJ-NP-Za-km-z]{11})?\b")
TOX_RE = re.compile(r"\b[0-9A-Fa-f]{76}\b")
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.IGNORECASE)
OBFUSCATED_AT = r"(?:\[\s*at\s*\]|\(\s*at\s*\)|\{\s*at\s*\}|\s+at\s+)"
OBFUSCATED_DOT = r"(?:\[\s*dot\s*\]|\(\s*dot\s*\)|\{\s*dot\s*\}|\s+dot\s+)"
OBFUSCATED_EMAIL_RE = re.compile(
    r"\b([A-Z0-9._%+\-]+)\s*"
    + OBFUSCATED_AT
    + r"\s*([A-Z0-9\-]+(?:\s*"
    + OBFUSCATED_DOT
    + r"\s*[A-Z0-9\-]+)*)\s*"
    + OBFUSCATED_DOT
    + r"\s*([A-Z]{2,})\b",
    re.IGNORECASE,
)
PGP_PUBLIC_KEY_RE = re.compile(
    r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----",
    re.IGNORECASE | re.DOTALL,
)
HREF_RE = re.compile(r"""(?is)\bhref\s*=\s*["']([^"']+)["']""")


def parse_args():
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Harvest actor-side CTI indicators from blogs, forums, and leak-site posts.",
    )
    parser.add_argument("-u", "--url", required=True, help="Start URL to harvest.")
    parser.add_argument("-o", "--output", required=True, help="JSON output file.")
    parser.add_argument(
        "-p",
        "--proxy",
        default=DEFAULT_PROXY,
        help=f"Proxy URL or host:port. Default: {DEFAULT_PROXY}",
    )
    parser.add_argument(
        "-d",
        "--delay",
        type=float,
        default=1.0,
        help="Delay in seconds between page requests. Default: 1.0",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=1,
        help="Maximum pages to fetch. Increase to crawl same-origin links. Default: 1",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=1,
        help="Maximum same-origin link depth when --max-pages is greater than 1. Default: 1",
    )
    parser.add_argument(
        "--include-external",
        action="store_true",
        help="Allow crawling off-origin links. Disabled by default.",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_BYTES,
        help=f"Maximum bytes to read per page. Default: {DEFAULT_MAX_BYTES}",
    )
    parser.add_argument(
        "--context",
        type=int,
        default=120,
        help="Characters of context to keep around each match. Default: 120",
    )
    parser.add_argument(
        "--max-value-length",
        type=int,
        default=20000,
        help="Maximum stored indicator value length. Long PGP blocks may be truncated. Default: 20000",
    )
    return parser.parse_args()


def normalize_proxy(proxy):
    if not proxy:
        return ""
    if "://" not in proxy:
        return "socks5h://" + proxy
    return proxy


def normalize_url(url):
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme:
        url = "http://" + url
        parsed = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse(parsed._replace(fragment=""))


def same_origin(left_url, right_url):
    left = urllib.parse.urlparse(left_url)
    right = urllib.parse.urlparse(right_url)
    return left.scheme == right.scheme and left.netloc == right.netloc


def create_session(proxy):
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": TOR_BROWSER_USER_AGENTS[0],
            "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.1",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1",
        }
    )
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})
    return session


def is_textual_response(response):
    content_type = response.headers.get("Content-Type", "").lower()
    if not content_type:
        return True
    allowed = (
        "text/",
        "application/json",
        "application/javascript",
        "application/xhtml",
        "application/xml",
    )
    return any(content_type.startswith(value) or value in content_type for value in allowed)


def fetch_text(session, url, max_bytes):
    response = session.get(url, timeout=REQUEST_TIMEOUT, stream=True)
    response.raise_for_status()

    content_type = response.headers.get("Content-Type", "")
    if not is_textual_response(response):
        response.close()
        return "", content_type, False, "non-text response"

    chunks = []
    total = 0
    truncated = False
    for chunk in response.iter_content(chunk_size=65536):
        if not chunk:
            continue
        total += len(chunk)
        if total > max_bytes:
            allowed = max_bytes - (total - len(chunk))
            if allowed > 0:
                chunks.append(chunk[:allowed])
            truncated = True
            break
        chunks.append(chunk)

    response.close()
    raw = b"".join(chunks)
    encoding = response.encoding or "utf-8"
    return raw.decode(encoding, errors="replace"), content_type, truncated, ""


def strip_html(raw_text):
    text = re.sub(r"(?is)<script\b.*?</script>", " ", raw_text)
    text = re.sub(r"(?is)<style\b.*?</style>", " ", text)
    text = re.sub(r"(?is)<br\s*/?>", "\n", text)
    text = re.sub(r"(?is)</p\s*>", "\n", text)
    text = re.sub(r"(?is)<[^>]+>", " ", text)
    text = html.unescape(text)
    return re.sub(r"[ \t\r\f\v]+", " ", text)


def extract_links(raw_text, current_url, root_url, include_external):
    links = []
    seen = set()
    for match in HREF_RE.finditer(raw_text):
        href = html.unescape(match.group(1)).strip()
        if not href or href.startswith(("#", "mailto:", "javascript:", "tel:")):
            continue
        absolute = normalize_url(urllib.parse.urljoin(current_url, href))
        if not include_external and not same_origin(root_url, absolute):
            continue
        if absolute in seen:
            continue
        seen.add(absolute)
        links.append(absolute)
    return links


def clean_context(value):
    value = html.unescape(value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def context_for(text, start, end, radius):
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    return clean_context(text[left:right])


def truncate_value(value, max_length):
    if len(value) <= max_length:
        return value, False
    return value[:max_length], True


def normalize_email(value):
    return value.lower()


def normalize_obfuscated_email(match):
    domain = re.sub(OBFUSCATED_DOT, ".", match.group(2), flags=re.IGNORECASE)
    return "{0}@{1}.{2}".format(match.group(1), domain, match.group(3)).lower()


def normalize_bitcoin(value):
    if value.lower().startswith("bc1"):
        return value.lower()
    return value


def normalize_monero(value):
    return value


def normalize_tox(value):
    return value.upper()


def add_indicator(findings, seen, indicator_type, value, normalized, source_url, context, max_value_length):
    stored_value, truncated = truncate_value(value, max_value_length)
    key = (indicator_type, normalized, source_url)
    if key in seen:
        return
    seen.add(key)
    findings.append(
        {
            "type": indicator_type,
            "value": stored_value,
            "value_truncated": truncated,
            "normalized": normalized,
            "source_url": source_url,
            "context": context,
        }
    )


def collect_regex_matches(text, source_url, regex, indicator_type, normalizer, context_radius, max_value_length, findings, seen):
    for match in regex.finditer(text):
        value = match.group(0)
        normalized = normalizer(value)
        add_indicator(
            findings,
            seen,
            indicator_type,
            value,
            normalized,
            source_url,
            context_for(text, match.start(), match.end(), context_radius),
            max_value_length,
        )


def collect_obfuscated_emails(text, source_url, context_radius, max_value_length, findings, seen):
    for match in OBFUSCATED_EMAIL_RE.finditer(text):
        value = match.group(0)
        normalized = normalize_obfuscated_email(match)
        add_indicator(
            findings,
            seen,
            "email_obfuscated",
            value,
            normalized,
            source_url,
            context_for(text, match.start(), match.end(), context_radius),
            max_value_length,
        )


def collect_pgp_blocks(text, source_url, context_radius, max_value_length, findings, seen):
    spans = []
    for match in PGP_PUBLIC_KEY_RE.finditer(text):
        value = match.group(0).strip()
        normalized = re.sub(r"\s+", "", value)
        add_indicator(
            findings,
            seen,
            "pgp_public_key",
            value,
            normalized,
            source_url,
            context_for(text, match.start(), match.end(), context_radius),
            max_value_length,
        )
        spans.append((match.start(), match.end()))
    return spans


def blank_spans(text, spans):
    if not spans:
        return text
    chars = list(text)
    for start, end in spans:
        for index in range(start, end):
            chars[index] = " "
    return "".join(chars)


def harvest_indicators(raw_text, source_url, context_radius, max_value_length, findings, seen):
    visible_text = strip_html(raw_text)
    search_text = raw_text + "\n" + visible_text

    pgp_spans = collect_pgp_blocks(search_text, source_url, context_radius, max_value_length, findings, seen)
    search_without_pgp = blank_spans(search_text, pgp_spans)

    collect_regex_matches(
        search_without_pgp,
        source_url,
        BITCOIN_LEGACY_RE,
        "bitcoin_wallet",
        normalize_bitcoin,
        context_radius,
        max_value_length,
        findings,
        seen,
    )
    collect_regex_matches(
        search_without_pgp,
        source_url,
        BITCOIN_BECH32_RE,
        "bitcoin_wallet",
        normalize_bitcoin,
        context_radius,
        max_value_length,
        findings,
        seen,
    )
    collect_regex_matches(
        search_without_pgp,
        source_url,
        MONERO_RE,
        "monero_wallet",
        normalize_monero,
        context_radius,
        max_value_length,
        findings,
        seen,
    )
    collect_regex_matches(
        search_without_pgp,
        source_url,
        TOX_RE,
        "tox_id",
        normalize_tox,
        context_radius,
        max_value_length,
        findings,
        seen,
    )
    collect_regex_matches(
        search_without_pgp,
        source_url,
        EMAIL_RE,
        "email",
        normalize_email,
        context_radius,
        max_value_length,
        findings,
        seen,
    )
    collect_obfuscated_emails(
        search_without_pgp,
        source_url,
        context_radius,
        max_value_length,
        findings,
        seen,
    )


def short_value(value, limit=96):
    clean = clean_context(value)
    if len(clean) <= limit:
        return clean
    return clean[: limit - 3] + "..."


def print_indicator(indicator):
    print("[+] {0}: {1}".format(indicator["type"], short_value(indicator["normalized"])))
    print("    source: {0}".format(indicator["source_url"]))


def crawl(args):
    start_url = normalize_url(args.url)
    proxy = normalize_proxy(args.proxy)
    session = create_session(proxy)

    queue = [(start_url, 0)]
    visited = set()
    findings = []
    errors = []
    skipped = []
    seen = set()

    while queue and len(visited) < args.max_pages:
        current_url, depth = queue.pop(0)
        if current_url in visited:
            continue

        if visited and args.delay > 0:
            time.sleep(args.delay)

        visited.add(current_url)
        print("[*] Harvesting: {0}".format(current_url))

        try:
            raw_text, content_type, truncated, skip_reason = fetch_text(session, current_url, args.max_bytes)
        except requests.RequestException as exc:
            errors.append({"url": current_url, "error": str(exc)})
            print("[!] Error: {0} ({1})".format(current_url, exc))
            continue

        if skip_reason:
            skipped.append({"url": current_url, "content_type": content_type, "reason": skip_reason})
            print("[*] Skipping: {0} ({1})".format(current_url, skip_reason))
            continue

        before = len(findings)
        harvest_indicators(raw_text, current_url, args.context, args.max_value_length, findings, seen)
        for indicator in findings[before:]:
            print_indicator(indicator)

        if truncated:
            skipped.append({"url": current_url, "content_type": content_type, "reason": "page truncated at byte limit"})

        if depth >= args.max_depth:
            continue

        for link in extract_links(raw_text, current_url, start_url, args.include_external):
            if link not in visited and all(link != queued_url for queued_url, _depth in queue):
                queue.append((link, depth + 1))

    return {
        "repository": REPOSITORY,
        "tool": TOOL_NAME,
        "target": start_url,
        "proxy": proxy,
        "generated_at_unix": int(time.time()),
        "max_pages": args.max_pages,
        "max_depth": args.max_depth,
        "include_external": args.include_external,
        "pages_harvested": len(visited),
        "indicators_found": len(findings),
        "indicators": findings,
        "errors": errors,
        "skipped": skipped,
    }


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main():
    args = parse_args()
    result = crawl(args)
    write_json(args.output, result)
    print("[*] JSON written: {0}".format(args.output))
    print("[*] Pages harvested: {0}".format(result["pages_harvested"]))
    print("[*] Indicators found: {0}".format(result["indicators_found"]))


if __name__ == "__main__":
    main()
