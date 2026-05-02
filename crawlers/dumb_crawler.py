#!/usr/bin/env python3
"""
Open-Directory Indexer

Part of the-crawling-void: a lightweight crawler for plain Apache and Nginx
directory listings. The tool does not download files. It indexes directory
entries, records file URLs, and emits reviewable curl commands for authorized
follow-up.
"""

import argparse
import html
import json
import re
import time
import urllib.parse

import requests


REPOSITORY = "the-crawling-void"
TOOL_NAME = "dumb-crawler"
DEFAULT_PROXY = "socks5h://localhost:9050"
REQUEST_TIMEOUT = 60
DEFAULT_MAX_BYTES = 2 * 1024 * 1024

TOR_BROWSER_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0",
]

ANCHOR_RE = re.compile(r"""(?is)<a\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>""")
INDEX_HINT_RE = re.compile(r"(?is)\bIndex of\b|Parent Directory|Directory Listing")
TAG_RE = re.compile(r"(?is)<[^>]+>")
WHITESPACE_RE = re.compile(r"\s+")
DATE_RE = re.compile(r"\b\d{2,4}[-/][A-Za-z0-9]{2,3}[-/]\d{2,4}(?:\s+\d{2}:\d{2})?\b")
SIZE_RE = re.compile(r"\b(?:\d+(?:\.\d+)?\s?(?:B|K|M|G|T|P)?|[-])\b", re.IGNORECASE)


def parse_args():
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Fast indexer for plain Apache and Nginx open directories.",
    )
    parser.add_argument("-u", "--url", required=True, help="Open directory URL to index.")
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
        default=0.2,
        help="Delay in seconds between directory requests. Default: 0.2",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=1000,
        help="Maximum directory pages to index. Default: 1000",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=20,
        help="Maximum directory depth below the start URL. Default: 20",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_BYTES,
        help=f"Maximum bytes to read per index page. Default: {DEFAULT_MAX_BYTES}",
    )
    parser.add_argument(
        "--include-regex",
        default="",
        help="Optional regex. Only matching file URLs or names are included in the file list.",
    )
    parser.add_argument(
        "--exclude-regex",
        default="",
        help="Optional regex. Matching file URLs or names are excluded.",
    )
    parser.add_argument(
        "--strict-index",
        action="store_true",
        help="Only parse pages that look like Apache/Nginx index listings.",
    )
    parser.add_argument(
        "--no-curl",
        action="store_true",
        help="Do not generate curl commands for file entries.",
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


def ensure_directory_url(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.path.endswith("/"):
        return url
    return urllib.parse.urlunparse(parsed._replace(path=parsed.path + "/"))


def create_session(proxy):
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": TOR_BROWSER_USER_AGENTS[0],
            "Accept": "text/html,application/xhtml+xml,text/plain;q=0.8,*/*;q=0.1",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "DNT": "1",
        }
    )
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})
    return session


def is_textual_response(response):
    content_type = response.headers.get("Content-Type", "").lower()
    if not content_type:
        return True
    return "text/html" in content_type or "text/plain" in content_type or "application/xhtml" in content_type


def fetch_index(session, url, max_bytes):
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
    encoding = response.encoding or "utf-8"
    return b"".join(chunks).decode(encoding, errors="replace"), content_type, truncated, ""


def clean_text(value):
    value = TAG_RE.sub(" ", value)
    value = html.unescape(value)
    return WHITESPACE_RE.sub(" ", value).strip()


def anchor_context(raw_html, match_start, match_end):
    line_start = raw_html.rfind("\n", 0, match_start)
    line_end = raw_html.find("\n", match_end)
    if line_start == -1:
        line_start = max(0, match_start - 160)
    else:
        line_start += 1
    if line_end == -1:
        line_end = min(len(raw_html), match_end + 160)
    return clean_text(raw_html[line_start:line_end])


def looks_like_index(raw_html):
    return bool(INDEX_HINT_RE.search(raw_html)) and bool(ANCHOR_RE.search(raw_html))


def is_sort_or_self_link(href):
    if not href:
        return True
    lowered = href.strip().lower()
    if lowered in ("#", ".", "./"):
        return True
    if lowered.startswith(("?c=", "?n=", "?m=", "?s=", "?d=")):
        return True
    if lowered.startswith(("mailto:", "javascript:", "tel:", "data:")):
        return True
    return False


def is_parent_link(href, label):
    value = urllib.parse.unquote(href).strip()
    label = clean_text(label).lower()
    return value in ("..", "../") or "parent directory" in label


def canonicalize_link(current_url, href):
    href = html.unescape(href).strip()
    absolute = urllib.parse.urljoin(current_url, href)
    parsed = urllib.parse.urlparse(absolute)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, parsed.query, ""))


def basename_from_url(url):
    parsed = urllib.parse.urlparse(url)
    path = urllib.parse.unquote_plus(parsed.path.rstrip("/"))
    name = path.rsplit("/", 1)[-1].strip()
    return name or "index"


def safe_output_name(filename):
    name = basename_from_url(filename)
    name = re.sub(r"[^A-Za-z0-9._ -]+", "_", name).strip(" .")
    return name or "download.bin"


def path_depth_from_root(root_url, candidate_url):
    root_path = urllib.parse.urlparse(root_url).path.rstrip("/")
    candidate_path = urllib.parse.urlparse(candidate_url).path.rstrip("/")
    if root_path and candidate_path.startswith(root_path):
        relative = candidate_path[len(root_path) :].strip("/")
    else:
        relative = candidate_path.strip("/")
    if not relative:
        return 0
    return len([part for part in relative.split("/") if part])


def parse_metadata(context, label):
    text = context.replace(clean_text(label), " ", 1)
    date_match = DATE_RE.search(text)
    size_match = None
    for match in SIZE_RE.finditer(text):
        value = match.group(0)
        if date_match and date_match.start() <= match.start() <= date_match.end():
            continue
        if value == "-" or re.search(r"[KMGTBP]$", value, re.IGNORECASE):
            size_match = match
            break
    return {
        "modified": date_match.group(0) if date_match else "",
        "size": size_match.group(0) if size_match else "",
    }


def parse_index_links(raw_html, current_url, root_url, strict_index):
    if strict_index and not looks_like_index(raw_html):
        return [], [], "not an index listing"

    directories = []
    files = []
    seen = set()

    for match in ANCHOR_RE.finditer(raw_html):
        href = match.group(1)
        label = clean_text(match.group(2))

        if is_sort_or_self_link(href) or is_parent_link(href, label):
            continue

        target_url = canonicalize_link(current_url, href)
        if not same_origin(root_url, target_url):
            continue
        if target_url in seen:
            continue
        seen.add(target_url)

        context = anchor_context(raw_html, match.start(), match.end())
        metadata = parse_metadata(context, label)
        entry = {
            "name": label or basename_from_url(target_url),
            "url": target_url,
            "directory_url": current_url,
            "modified": metadata["modified"],
            "size": metadata["size"],
        }

        href_path = urllib.parse.urlparse(href).path
        target_path = urllib.parse.urlparse(target_url).path
        if href.endswith("/") or href_path.endswith("/") or target_path.endswith("/"):
            directories.append(entry)
        else:
            files.append(entry)

    return directories, files, ""


def shell_quote(value):
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


def curl_proxy_argument(proxy):
    if not proxy:
        return ""

    parsed = urllib.parse.urlparse(proxy)
    if parsed.scheme in ("socks5h", "socks5"):
        host_port = parsed.netloc or parsed.path
        flag = "--socks5-hostname" if parsed.scheme == "socks5h" else "--socks5"
        return flag + " " + shell_quote(host_port)

    return "--proxy " + shell_quote(proxy)


def build_curl_command(file_url, filename, proxy):
    parts = ["curl", "-L", "--fail", "--silent", "--show-error", "--compressed"]
    proxy_arg = curl_proxy_argument(proxy)
    if proxy_arg:
        parts.append(proxy_arg)
    parts.append("-A " + shell_quote(TOR_BROWSER_USER_AGENTS[0]))
    parts.append("-o " + shell_quote(safe_output_name(filename)))
    parts.append(shell_quote(file_url))
    return " ".join(parts)


def compile_optional_regex(pattern, label):
    if not pattern:
        return None
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise ValueError("invalid {0}: {1}".format(label, exc))


def file_allowed(entry, include_regex, exclude_regex):
    text = entry["name"] + " " + entry["url"]
    if include_regex and not include_regex.search(text):
        return False
    if exclude_regex and exclude_regex.search(text):
        return False
    return True


def print_file(entry):
    detail = entry["url"]
    if entry.get("size"):
        detail += " ({0})".format(entry["size"])
    print("[+] File: {0}".format(detail))


def crawl(args):
    start_url = ensure_directory_url(normalize_url(args.url))
    proxy = normalize_proxy(args.proxy)
    session = create_session(proxy)
    include_regex = compile_optional_regex(args.include_regex, "--include-regex")
    exclude_regex = compile_optional_regex(args.exclude_regex, "--exclude-regex")

    queue = [start_url]
    visited = set()
    directories = []
    files = []
    errors = []
    skipped = []
    seen_files = set()
    seen_directories = set()

    while queue and len(visited) < args.max_pages:
        current_url = queue.pop(0)
        if current_url in visited:
            continue

        depth = path_depth_from_root(start_url, current_url)
        if depth > args.max_depth:
            skipped.append({"url": current_url, "reason": "max depth exceeded"})
            continue

        if visited and args.delay > 0:
            time.sleep(args.delay)

        visited.add(current_url)
        print("[*] Indexing: {0}".format(current_url))

        try:
            raw_html, content_type, truncated, skip_reason = fetch_index(session, current_url, args.max_bytes)
        except requests.RequestException as exc:
            errors.append({"url": current_url, "error": str(exc)})
            print("[!] Error: {0} ({1})".format(current_url, exc))
            continue

        if skip_reason:
            skipped.append({"url": current_url, "content_type": content_type, "reason": skip_reason})
            print("[*] Skipping: {0} ({1})".format(current_url, skip_reason))
            continue

        page_directories, page_files, parse_reason = parse_index_links(
            raw_html,
            current_url,
            start_url,
            args.strict_index,
        )
        if parse_reason:
            skipped.append({"url": current_url, "content_type": content_type, "reason": parse_reason})
            print("[*] Skipping: {0} ({1})".format(current_url, parse_reason))
            continue

        if truncated:
            skipped.append({"url": current_url, "content_type": content_type, "reason": "page truncated at byte limit"})

        for directory in page_directories:
            directory_url = ensure_directory_url(directory["url"])
            directory["url"] = directory_url
            if directory_url not in seen_directories:
                seen_directories.add(directory_url)
                directories.append(directory)
            if directory_url not in visited and directory_url not in queue:
                queue.append(directory_url)

        for file_entry in page_files:
            if not file_allowed(file_entry, include_regex, exclude_regex):
                continue
            if file_entry["url"] in seen_files:
                continue
            seen_files.add(file_entry["url"])
            if not args.no_curl:
                file_entry["curl"] = build_curl_command(file_entry["url"], file_entry["name"], proxy)
            files.append(file_entry)
            print_file(file_entry)

    return {
        "repository": REPOSITORY,
        "tool": TOOL_NAME,
        "target": start_url,
        "proxy": proxy,
        "generated_at_unix": int(time.time()),
        "max_pages": args.max_pages,
        "max_depth": args.max_depth,
        "pages_indexed": len(visited),
        "directories_found": len(directories),
        "files_found": len(files),
        "directories": directories,
        "files": files,
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
    print("[*] Pages indexed: {0}".format(result["pages_indexed"]))
    print("[*] Files found: {0}".format(result["files_found"]))


if __name__ == "__main__":
    main()
