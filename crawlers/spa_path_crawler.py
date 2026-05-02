#!/usr/bin/env python3
"""
SPA Path Crawler

Part of the-crawling-void: a defensive Threat Intelligence and OSINT crawler
for dynamic leak-site directory listings. The tool does not download files.
It walks HTML route views, searches for analyst-defined patterns, and emits
reviewable curl commands for authorized follow-up.
"""

import argparse
import json
import re
import time
import urllib.parse

import requests


REPOSITORY = "the-crawling-void"
TOOL_NAME = "spa-path-crawler"
DEFAULT_PROXY = "socks5h://localhost:9050"
REQUEST_TIMEOUT = 60

TOR_BROWSER_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0",
]

FILENAME_CHARS = r"A-Za-z0-9._%+\-@()\[\]{}=,$!~ "
TOKEN_ENV_VAR = "TCV_JWT_TOKEN"
COMMON_FILE_EXTENSIONS = {
    "7z",
    "avi",
    "bak",
    "bz2",
    "csv",
    "doc",
    "docx",
    "gz",
    "iso",
    "jpg",
    "jpeg",
    "json",
    "mdb",
    "mov",
    "mp4",
    "msg",
    "pdf",
    "png",
    "ppt",
    "pptx",
    "pst",
    "rar",
    "rtf",
    "sql",
    "tar",
    "tgz",
    "txt",
    "xls",
    "xlsx",
    "xml",
    "xz",
    "zip",
}


def parse_args():
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="JWT-aware crawler for SPA-style ?path= leak-site listings.",
    )
    parser.add_argument(
        "-u",
        "--url",
        required=True,
        help="Base URL to crawl, for example http://example.onion/?path=/",
    )
    parser.add_argument(
        "-t",
        "--token",
        default="",
        help="JWT session token. Omit for unauthenticated listings.",
    )
    parser.add_argument(
        "-w",
        "--wordlist",
        required=True,
        help="Pattern file. One term, glob, or regex per line.",
    )
    parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="JSON output file for structured findings.",
    )
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
        help="Delay in seconds between HTTP requests. Default: 1.0",
    )
    parser.add_argument(
        "--auth-mode",
        choices=("header", "query", "both"),
        default="header",
        help="Where to place the JWT. Use query for sites that require ?token=. Default: header",
    )
    parser.add_argument(
        "--token-param",
        default="token",
        help="Query parameter name for --auth-mode query or both. Default: token",
    )
    parser.add_argument(
        "--pattern-mode",
        choices=("glob", "literal", "regex"),
        default="glob",
        help="How unprefixed wordlist lines are interpreted. Default: glob",
    )
    return parser.parse_args()


def normalize_proxy(proxy):
    if not proxy:
        return ""
    if "://" not in proxy:
        return "socks5h://" + proxy
    return proxy


def parse_query(url):
    parsed = urllib.parse.urlparse(url)
    return parsed, urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)


def remove_query_param(url, param_name):
    parsed, pairs = parse_query(url)
    clean_pairs = [(key, value) for key, value in pairs if key != param_name]
    return urllib.parse.urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            parsed.params,
            urllib.parse.urlencode(clean_pairs),
            "",
        )
    )


def normalize_start_url(url, token_param):
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme:
        url = "http://" + url
        parsed = urllib.parse.urlparse(url)

    pairs = [(key, value) for key, value in urllib.parse.parse_qsl(parsed.query) if key != token_param]
    if not any(key == "path" for key, _value in pairs):
        pairs.append(("path", "/"))

    return urllib.parse.urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            parsed.params,
            urllib.parse.urlencode(pairs),
            "",
        )
    )


def add_query_token(url, token, token_param):
    if not token:
        return remove_query_param(url, token_param)

    parsed, pairs = parse_query(url)
    clean_pairs = [(key, value) for key, value in pairs if key != token_param]
    clean_pairs.append((token_param, token))
    return urllib.parse.urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            parsed.params,
            urllib.parse.urlencode(clean_pairs),
            "",
        )
    )


def add_query_token_placeholder(url, token_param):
    parsed, pairs = parse_query(url)
    clean_pairs = [(key, value) for key, value in pairs if key != token_param]
    query = urllib.parse.urlencode(clean_pairs)
    separator = "&" if query else ""
    placeholder = token_param + "=${" + TOKEN_ENV_VAR + "}"
    return urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, query + separator + placeholder, "")
    )


def request_url_for(crawl_url, token, auth_mode, token_param):
    if token and auth_mode in ("query", "both"):
        return add_query_token(crawl_url, token, token_param)
    return remove_query_param(crawl_url, token_param)


def create_session(token, proxy, auth_mode):
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": TOR_BROWSER_USER_AGENTS[0],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1",
        }
    )

    if token and auth_mode in ("header", "both"):
        session.headers["Authorization"] = "Bearer " + token
        session.headers["Cookie"] = "token={0}; jwt={0}; session={0}".format(token)

    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})

    return session


def load_pattern_lines(wordlist_path):
    lines = []
    with open(wordlist_path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            pattern = line.strip()
            if not pattern or pattern.startswith("#"):
                continue
            lines.append((line_number, pattern))

    if not lines:
        raise ValueError("pattern file contains no usable entries")

    return lines


def split_pattern_mode(raw_pattern, default_mode):
    lowered = raw_pattern.lower()
    prefixes = {
        "re:": "regex",
        "regex:": "regex",
        "glob:": "glob",
        "literal:": "literal",
    }

    for prefix, mode in prefixes.items():
        if lowered.startswith(prefix):
            return mode, raw_pattern[len(prefix) :].strip()

    return default_mode, raw_pattern


def glob_to_regex(value):
    escaped = re.escape(value)
    return escaped.replace(r"\*", r".*").replace(r"\?", r".")


def compile_single_pattern(line_number, raw_pattern, default_mode):
    mode, value = split_pattern_mode(raw_pattern, default_mode)
    if not value:
        raise ValueError("empty pattern at line {0}".format(line_number))

    if mode == "regex":
        expression = value
    else:
        variants = [value, urllib.parse.quote(value), urllib.parse.quote_plus(value)]
        variants = sorted(set(variants))
        transformer = glob_to_regex if mode == "glob" else re.escape
        needle = "|".join(transformer(variant) for variant in variants)
        expression = r"([{chars}]{{0,120}}(?:{needle})[{chars}]{{0,120}})".format(
            chars=FILENAME_CHARS,
            needle=needle,
        )

    try:
        compiled = re.compile(expression, re.IGNORECASE)
    except re.error as exc:
        raise ValueError("invalid regex at line {0}: {1}".format(line_number, exc))

    return {
        "line": line_number,
        "pattern": raw_pattern,
        "mode": mode,
        "regex": expression,
        "compiled": compiled,
    }


def compile_patterns(pattern_lines, default_mode):
    return [
        compile_single_pattern(line_number, raw_pattern, default_mode)
        for line_number, raw_pattern in pattern_lines
    ]


def same_origin(left_url, right_url):
    left = urllib.parse.urlparse(left_url)
    right = urllib.parse.urlparse(right_url)
    return left.scheme == right.scheme and left.netloc == right.netloc


def get_path_value(url):
    parsed = urllib.parse.urlparse(url)
    for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
        if key == "path":
            return value
    return None


def canonicalize_url(url, token_param):
    parsed = urllib.parse.urlparse(url.replace("&amp;", "&"))
    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    clean_pairs = [(key, value) for key, value in query_pairs if key != token_param]
    clean_query = urllib.parse.urlencode(clean_pairs)
    return urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, clean_query, "")
    )


def extract_path_links(html, current_url, root_url, token_param):
    links = []
    seen = set()
    expressions = [
        re.compile(r"""(?is)(?:href|src)\s*=\s*["']([^"']*\?path=[^"']*)["']"""),
        re.compile(r"""(?is)["']([^"']*\?path=[^"']+)["']"""),
        re.compile(r"""(?is)(\?path=[^"' <>\r\n]+)"""),
    ]

    for expression in expressions:
        for match in expression.finditer(html):
            raw_link = match.group(1).replace("&amp;", "&")
            absolute = urllib.parse.urljoin(current_url, raw_link)
            absolute = canonicalize_url(absolute, token_param)
            if get_path_value(absolute) is None:
                continue
            if not same_origin(root_url, absolute):
                continue
            if absolute in seen:
                continue
            seen.add(absolute)
            links.append(absolute)

    return links


def clean_candidate(value):
    cleaned = urllib.parse.unquote_plus(value)
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip(" \t\r\n\"'<>")


def looks_like_noise(value):
    if not value or len(value) > 220:
        return True
    if "<" in value or ">" in value:
        return True
    if value.count(" ") > 16:
        return True
    return False


def basename_from_path(path_value):
    if not path_value:
        return "download.bin"
    decoded = urllib.parse.unquote_plus(path_value.rstrip("/"))
    name = decoded.rsplit("/", 1)[-1].strip()
    return name or "download.bin"


def looks_like_file_path(path_value):
    if not path_value or path_value.endswith("/"):
        return False

    name = basename_from_path(path_value).lower()
    if "." not in name:
        return False

    extension = name.rsplit(".", 1)[-1]
    return extension in COMMON_FILE_EXTENSIONS


def is_html_response(response):
    content_type = response.headers.get("Content-Type", "").lower()
    if not content_type:
        return True
    return "text/html" in content_type or "application/xhtml" in content_type


def safe_output_name(filename):
    name = basename_from_path(filename)
    name = re.sub(r"[^A-Za-z0-9._ -]+", "_", name).strip(" .")
    return name or "download.bin"


def build_path_url(current_url, path_value):
    parsed = urllib.parse.urlparse(current_url)
    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    rewritten = []
    path_seen = False

    for key, value in query_pairs:
        if key == "path":
            rewritten.append((key, path_value))
            path_seen = True
        else:
            rewritten.append((key, value))

    if not path_seen:
        rewritten.append(("path", path_value))

    return urllib.parse.urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            parsed.params,
            urllib.parse.urlencode(rewritten),
            "",
        )
    )


def build_download_url(current_url, candidate, token_param):
    candidate = clean_candidate(candidate)
    if "?path=" in candidate:
        return canonicalize_url(urllib.parse.urljoin(current_url, candidate), token_param)
    if candidate.startswith("http://") or candidate.startswith("https://"):
        return canonicalize_url(candidate, token_param)

    current_path = get_path_value(current_url) or "/"
    if candidate.startswith("/"):
        target_path = candidate
    else:
        directory = current_path
        if not directory.endswith("/"):
            directory = directory + "/"
        target_path = directory + candidate

    return build_path_url(current_url, target_path)


def shell_quote(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def shell_double_quote(value):
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("`", "\\`")
    return '"' + escaped + '"'


def curl_proxy_argument(proxy):
    if not proxy:
        return ""

    parsed = urllib.parse.urlparse(proxy)
    if parsed.scheme in ("socks5h", "socks5"):
        host_port = parsed.netloc or parsed.path
        flag = "--socks5-hostname" if parsed.scheme == "socks5h" else "--socks5"
        return flag + " " + shell_quote(host_port)

    return "--proxy " + shell_quote(proxy)


def header_auth_parts():
    return [
        '-H "Authorization: Bearer ${' + TOKEN_ENV_VAR + '}"',
        '-H "Cookie: token=${' + TOKEN_ENV_VAR + "}; jwt=${" + TOKEN_ENV_VAR + "}; session=${" + TOKEN_ENV_VAR + '}"',
    ]


def build_curl_command(download_url, filename, token_present, auth_mode, proxy, token_param):
    parts = ["curl", "-L", "--fail", "--silent", "--show-error", "--compressed"]
    proxy_arg = curl_proxy_argument(proxy)
    if proxy_arg:
        parts.append(proxy_arg)

    parts.append("-A " + shell_quote(TOR_BROWSER_USER_AGENTS[0]))

    if token_present and auth_mode in ("header", "both"):
        parts.extend(header_auth_parts())

    final_url = download_url
    quote_url = shell_quote
    if token_present and auth_mode in ("query", "both"):
        final_url = add_query_token_placeholder(download_url, token_param)
        quote_url = shell_double_quote

    parts.append("-o " + shell_quote(safe_output_name(filename)))
    parts.append(quote_url(final_url))
    return " ".join(parts)


def match_value(match):
    if match.groups():
        return match.group(1)
    return match.group(0)


def make_record(pattern_match, filename, source_url, download_url, token_present, auth_mode, proxy, token_param):
    return {
        "pattern": pattern_match["pattern"],
        "pattern_line": pattern_match["line"],
        "pattern_mode": pattern_match["mode"],
        "regex": pattern_match["regex"],
        "filename": clean_candidate(filename),
        "source_url": source_url,
        "download_url": download_url,
        "curl": build_curl_command(download_url, filename, token_present, auth_mode, proxy, token_param),
    }


def find_matches(
    html,
    current_url,
    path_links,
    patterns,
    token_present,
    auth_mode,
    proxy,
    token_param,
    global_seen,
):
    findings = []
    linked_urls = set(path_links)
    linked_basenames = set()
    decoded_html = urllib.parse.unquote_plus(html)
    search_space = html if decoded_html == html else html + "\n" + decoded_html

    for link in path_links:
        path_value = get_path_value(link) or ""
        linked_basenames.add(basename_from_path(path_value).lower())
        searchable = link + " " + urllib.parse.unquote_plus(path_value)
        for pattern in patterns:
            if not pattern["compiled"].search(searchable):
                continue
            filename = basename_from_path(path_value)
            key = (pattern["pattern"], current_url, link, filename)
            if key in global_seen:
                continue
            global_seen.add(key)
            findings.append(
                make_record(pattern, filename, current_url, link, token_present, auth_mode, proxy, token_param)
            )

    for pattern in patterns:
        for match in pattern["compiled"].finditer(search_space):
            candidate = clean_candidate(match_value(match))
            if looks_like_noise(candidate):
                continue
            if basename_from_path(candidate).lower() in linked_basenames:
                continue
            download_url = build_download_url(current_url, candidate, token_param)
            if download_url in linked_urls:
                continue
            filename = basename_from_path(candidate)
            key = (pattern["pattern"], current_url, download_url, filename)
            if key in global_seen:
                continue
            global_seen.add(key)
            findings.append(
                make_record(pattern, filename, current_url, download_url, token_present, auth_mode, proxy, token_param)
            )

    return findings


def print_finding(finding):
    print("[+] Match: {0}".format(finding["filename"]))
    print("    pattern: {0}".format(finding["pattern"]))
    print("    source: {0}".format(finding["source_url"]))
    print("    download: {0}".format(finding["download_url"]))
    print("    curl: {0}".format(finding["curl"]))


def crawl(args):
    proxy = normalize_proxy(args.proxy)
    start_url = normalize_start_url(args.url, args.token_param)
    pattern_lines = load_pattern_lines(args.wordlist)
    patterns = compile_patterns(pattern_lines, args.pattern_mode)
    session = create_session(args.token, proxy, args.auth_mode)

    queue = [start_url]
    visited = set()
    findings = []
    errors = []
    skipped_non_html = []
    seen_findings = set()

    while queue:
        current_url = queue.pop(0)
        if current_url in visited:
            continue

        if visited and args.delay > 0:
            time.sleep(args.delay)

        visited.add(current_url)
        print("[*] Crawling: {0}".format(current_url))

        try:
            request_url = request_url_for(current_url, args.token, args.auth_mode, args.token_param)
            response = session.get(request_url, timeout=REQUEST_TIMEOUT, stream=True)
            response.raise_for_status()
        except requests.RequestException as exc:
            error = {"url": current_url, "error": str(exc)}
            errors.append(error)
            print("[!] Error: {0} ({1})".format(current_url, exc))
            continue

        if not is_html_response(response):
            content_type = response.headers.get("Content-Type", "")
            skipped_non_html.append({"url": current_url, "content_type": content_type})
            response.close()
            print("[*] Skipping non-HTML route: {0} ({1})".format(current_url, content_type))
            continue

        html = response.text
        path_links = extract_path_links(html, current_url, start_url, args.token_param)

        for link in path_links:
            if looks_like_file_path(get_path_value(link) or ""):
                continue
            if link not in visited and link not in queue:
                queue.append(link)

        page_findings = find_matches(
            html,
            current_url,
            path_links,
            patterns,
            bool(args.token),
            args.auth_mode,
            proxy,
            args.token_param,
            seen_findings,
        )
        for finding in page_findings:
            print_finding(finding)
        findings.extend(page_findings)

    return {
        "repository": REPOSITORY,
        "tool": TOOL_NAME,
        "target": start_url,
        "proxy": proxy,
        "auth_mode": args.auth_mode,
        "token_param": args.token_param,
        "generated_at_unix": int(time.time()),
        "token_supplied": bool(args.token),
        "pages_crawled": len(visited),
        "patterns_loaded": len(patterns),
        "matches_found": len(findings),
        "matches": findings,
        "errors": errors,
        "skipped_non_html": skipped_non_html,
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
    print("[*] Pages crawled: {0}".format(result["pages_crawled"]))
    print("[*] Matches found: {0}".format(result["matches_found"]))


if __name__ == "__main__":
    main()
