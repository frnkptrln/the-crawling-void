#!/usr/bin/env python3
"""
API and GraphQL Crawler

Part of the-crawling-void: a defensive Threat Intelligence and OSINT crawler
for JSON-backed leak-site panels. The tool does not download files. It queries
authorized REST or GraphQL endpoints, extracts directory and file records from
JSON responses, and emits reviewable curl commands for authorized follow-up.
"""

import argparse
import json
import re
import time
import urllib.parse

import requests


REPOSITORY = "the-crawling-void"
TOOL_NAME = "api-crawler"
DEFAULT_PROXY = "socks5h://localhost:9050"
REQUEST_TIMEOUT = 60
TOKEN_ENV_VAR = "TCV_JWT_TOKEN"

TOR_BROWSER_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0",
]

FILENAME_CHARS = r"A-Za-z0-9._%+\-@()\[\]{}=,$!~ "
DEFAULT_DIR_KEYS = "directories,dirs,folders,children"
DEFAULT_FILE_KEYS = "files,items,documents,entries,children"
DEFAULT_NAME_KEYS = "name,filename,file_name,fileName,title,label"
DEFAULT_PATH_KEYS = "path,full_path,fullPath,file_path,filePath,href,url,download_url,downloadUrl"
DEFAULT_DIRECTORY_TYPES = "directory,dir,folder"
DEFAULT_FILE_TYPES = "file,document,blob"
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


class SafeFormatDict(dict):
    def __missing__(self, key):
        return "{" + key + "}"


def parse_args():
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="JWT-aware REST and GraphQL crawler for JSON leak-site listings.",
    )
    parser.add_argument("-u", "--url", required=True, help="REST or GraphQL endpoint URL.")
    parser.add_argument("-t", "--token", default="", help="JWT session token.")
    parser.add_argument(
        "-w",
        "--wordlist",
        required=True,
        help="Pattern file. One term, glob, or regex per line.",
    )
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
        help="Delay in seconds between API requests. Default: 1.0",
    )
    parser.add_argument(
        "--api-mode",
        choices=("rest", "graphql"),
        default="rest",
        help="API style to query. Default: rest",
    )
    parser.add_argument(
        "--method",
        choices=("GET", "POST"),
        default="GET",
        help="REST request method. GraphQL always uses POST. Default: GET",
    )
    parser.add_argument(
        "--auth-mode",
        choices=("header", "query", "both"),
        default="header",
        help="Where to place the JWT. Default: header",
    )
    parser.add_argument(
        "--token-param",
        default="token",
        help="Query parameter name for --auth-mode query or both. Default: token",
    )
    parser.add_argument(
        "--path-param",
        default="path",
        help="REST path parameter or POST JSON field. Default: path",
    )
    parser.add_argument(
        "--root-path",
        default="/",
        help="Initial directory path to query. Default: /",
    )
    parser.add_argument(
        "--graphql-query",
        default="",
        help="GraphQL query string, or @path/to/query.graphql.",
    )
    parser.add_argument(
        "--graphql-variables",
        default="{}",
        help="GraphQL variables as JSON, or @path/to/variables.json. Default: {}",
    )
    parser.add_argument(
        "--graphql-path-variable",
        default="path",
        help="GraphQL variable name that receives the current path. Default: path",
    )
    parser.add_argument(
        "--download-template",
        default="",
        help=(
            "Optional URL template for downloads. Supports {base_url}, {api_url}, "
            "{path}, {path_encoded}, {name}, {name_encoded}, {url}, and {token}."
        ),
    )
    parser.add_argument(
        "--dir-keys",
        default=DEFAULT_DIR_KEYS,
        help=f"Comma-separated JSON keys containing directories. Default: {DEFAULT_DIR_KEYS}",
    )
    parser.add_argument(
        "--file-keys",
        default=DEFAULT_FILE_KEYS,
        help=f"Comma-separated JSON keys containing files. Default: {DEFAULT_FILE_KEYS}",
    )
    parser.add_argument(
        "--name-keys",
        default=DEFAULT_NAME_KEYS,
        help=f"Comma-separated JSON keys for names. Default: {DEFAULT_NAME_KEYS}",
    )
    parser.add_argument(
        "--path-keys",
        default=DEFAULT_PATH_KEYS,
        help=f"Comma-separated JSON keys for paths or URLs. Default: {DEFAULT_PATH_KEYS}",
    )
    parser.add_argument(
        "--type-key",
        default="type",
        help="JSON key that marks object type. Default: type",
    )
    parser.add_argument(
        "--directory-types",
        default=DEFAULT_DIRECTORY_TYPES,
        help=f"Comma-separated type values treated as directories. Default: {DEFAULT_DIRECTORY_TYPES}",
    )
    parser.add_argument(
        "--file-types",
        default=DEFAULT_FILE_TYPES,
        help=f"Comma-separated type values treated as files. Default: {DEFAULT_FILE_TYPES}",
    )
    parser.add_argument(
        "--pattern-mode",
        choices=("glob", "literal", "regex"),
        default="glob",
        help="How unprefixed wordlist lines are interpreted. Default: glob",
    )
    parser.add_argument(
        "--max-requests",
        type=int,
        default=0,
        help="Maximum API requests. 0 means unlimited. Default: 0",
    )
    return parser.parse_args()


def normalize_proxy(proxy):
    if not proxy:
        return ""
    if "://" not in proxy:
        return "socks5h://" + proxy
    return proxy


def parse_csv(value):
    return [item.strip() for item in value.split(",") if item.strip()]


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


def add_query_param(url, key, value):
    parsed, pairs = parse_query(url)
    clean_pairs = [(pair_key, pair_value) for pair_key, pair_value in pairs if pair_key != key]
    clean_pairs.append((key, value))
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


def add_query_token(url, token, token_param):
    if not token:
        return remove_query_param(url, token_param)
    return add_query_param(url, token_param, token)


def add_query_token_placeholder(url, token_param):
    parsed, pairs = parse_query(url)
    clean_pairs = [(key, value) for key, value in pairs if key != token_param]
    query = urllib.parse.urlencode(clean_pairs)
    separator = "&" if query else ""
    placeholder = token_param + "=${" + TOKEN_ENV_VAR + "}"
    return urllib.parse.urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            parsed.params,
            query + separator + placeholder,
            "",
        )
    )


def request_url_for(endpoint_url, token, auth_mode, token_param):
    if token and auth_mode in ("query", "both"):
        return add_query_token(endpoint_url, token, token_param)
    return remove_query_param(endpoint_url, token_param)


def normalized_endpoint(url, token_param):
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme:
        url = "http://" + url
    return remove_query_param(url, token_param)


def base_url_for(url):
    parsed = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "/", "", "", "")).rstrip("/")


def create_session(token, proxy, auth_mode):
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": TOR_BROWSER_USER_AGENTS[0],
            "Accept": "application/json,text/plain,*/*",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "application/json",
            "Connection": "keep-alive",
            "DNT": "1",
        }
    )

    if token and auth_mode in ("header", "both"):
        session.headers["Authorization"] = "Bearer " + token
        session.headers["Cookie"] = "token={0}; jwt={0}; session={0}".format(token)

    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})

    return session


def load_text_or_inline(value):
    if value.startswith("@"):
        with open(value[1:], "r", encoding="utf-8") as handle:
            return handle.read()
    return value


def load_json_or_inline(value):
    text = load_text_or_inline(value)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid JSON value: {0}".format(exc))


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


def is_scalar(value):
    return isinstance(value, (str, int, float, bool)) or value is None


def scalar_to_text(value):
    if value is None:
        return ""
    return str(value)


def first_string_value(obj, keys):
    if not isinstance(obj, dict):
        return ""
    for key in keys:
        value = obj.get(key)
        if is_scalar(value) and scalar_to_text(value):
            return scalar_to_text(value)
    return ""


def object_type(obj, type_key):
    if not isinstance(obj, dict):
        return ""
    return scalar_to_text(obj.get(type_key)).strip().lower()


def iter_json_objects(value, pointer="$"):
    if isinstance(value, dict):
        yield pointer, value
        for key, child in value.items():
            child_pointer = pointer + "." + str(key)
            yield from iter_json_objects(child, child_pointer)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_pointer = pointer + "[" + str(index) + "]"
            yield from iter_json_objects(child, child_pointer)


def join_path(parent_path, child_value):
    if not child_value:
        return parent_path or "/"

    child = urllib.parse.unquote(str(child_value)).strip()
    if child.startswith("http://") or child.startswith("https://"):
        return child
    if child.startswith("/"):
        return child

    parent = parent_path or "/"
    if not parent.endswith("/"):
        parent += "/"
    return parent + child


def basename_from_path(path_value):
    if not path_value:
        return "download.bin"
    parsed = urllib.parse.urlparse(str(path_value))
    raw_path = parsed.path if parsed.scheme else str(path_value)
    decoded = urllib.parse.unquote_plus(raw_path.rstrip("/"))
    name = decoded.rsplit("/", 1)[-1].strip()
    return name or "download.bin"


def looks_like_file_path(path_value):
    if not path_value or str(path_value).endswith("/"):
        return False

    name = basename_from_path(path_value).lower()
    if "." not in name:
        return False

    extension = name.rsplit(".", 1)[-1]
    return extension in COMMON_FILE_EXTENSIONS


def clean_candidate(value):
    cleaned = urllib.parse.unquote_plus(str(value))
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip(" \t\r\n\"'<>")


def safe_output_name(filename):
    name = basename_from_path(filename)
    name = re.sub(r"[^A-Za-z0-9._ -]+", "_", name).strip(" .")
    return name or "download.bin"


def record_from_value(value, parent_path, name_keys, path_keys, pointer):
    if isinstance(value, str):
        path_value = join_path(parent_path, value)
        return {
            "name": basename_from_path(path_value),
            "path": path_value,
            "url": path_value if path_value.startswith(("http://", "https://")) else "",
            "pointer": pointer,
            "raw": value,
        }

    if not isinstance(value, dict):
        return {}

    explicit_url = first_string_value(value, ["download_url", "downloadUrl", "url", "href"])
    path_value = first_string_value(value, path_keys)
    name_value = first_string_value(value, name_keys)
    if not path_value and name_value:
        path_value = join_path(parent_path, name_value)
    elif path_value and not path_value.startswith(("http://", "https://")):
        path_value = join_path(parent_path, path_value)

    name = name_value or basename_from_path(path_value or explicit_url)
    return {
        "name": clean_candidate(name),
        "path": path_value or explicit_url,
        "url": explicit_url if explicit_url.startswith(("http://", "https://")) else "",
        "pointer": pointer,
        "raw": value,
    }


def child_pointer(parent_pointer, key, index):
    return parent_pointer + "." + str(key) + "[" + str(index) + "]"


def records_from_array(obj, parent_pointer, key, parent_path, name_keys, path_keys, type_key="", skip_types=None):
    records = []
    value = obj.get(key)
    if not isinstance(value, list):
        return records
    skip_types = skip_types or set()
    for index, item in enumerate(value):
        if skip_types and object_type(item, type_key) in skip_types:
            continue
        record = record_from_value(item, parent_path, name_keys, path_keys, child_pointer(parent_pointer, key, index))
        if record:
            records.append(record)
    return records


def searchable_record_text(record):
    raw = record.get("raw")
    try:
        raw_text = json.dumps(raw, ensure_ascii=False, sort_keys=True)
    except TypeError:
        raw_text = str(raw)
    return " ".join(
        [
            scalar_to_text(record.get("name")),
            scalar_to_text(record.get("path")),
            scalar_to_text(record.get("url")),
            raw_text,
        ]
    )


def object_has_matching_text(obj, patterns):
    try:
        text = json.dumps(obj, ensure_ascii=False, sort_keys=True)
    except TypeError:
        text = str(obj)
    decoded_text = urllib.parse.unquote_plus(text)
    search_space = text if decoded_text == text else text + "\n" + decoded_text
    return any(pattern["compiled"].search(search_space) for pattern in patterns)


def extract_api_records(data, current_path, patterns, options):
    directories = []
    files = []
    seen_directories = set()
    seen_files = set()

    for pointer, obj in iter_json_objects(data):
        for key in options["dir_keys"]:
            for record in records_from_array(
                obj,
                pointer,
                key,
                current_path,
                options["name_keys"],
                options["path_keys"],
                options["type_key"],
                options["file_types"],
            ):
                candidate_path = record.get("path")
                if not candidate_path or looks_like_file_path(candidate_path):
                    continue
                if candidate_path in seen_directories:
                    continue
                seen_directories.add(candidate_path)
                directories.append(record)

        for key in options["file_keys"]:
            for record in records_from_array(
                obj,
                pointer,
                key,
                current_path,
                options["name_keys"],
                options["path_keys"],
                options["type_key"],
                options["directory_types"],
            ):
                candidate_path = record.get("path")
                if not candidate_path:
                    continue
                if candidate_path in seen_files:
                    continue
                seen_files.add(candidate_path)
                files.append(record)

        obj_type = object_type(obj, options["type_key"])
        if obj_type in options["directory_types"]:
            record = record_from_value(obj, current_path, options["name_keys"], options["path_keys"], pointer)
            candidate_path = record.get("path")
            if candidate_path and candidate_path not in seen_directories:
                seen_directories.add(candidate_path)
                directories.append(record)
        elif obj_type in options["file_types"]:
            record = record_from_value(obj, current_path, options["name_keys"], options["path_keys"], pointer)
            candidate_path = record.get("path")
            if candidate_path and candidate_path not in seen_files:
                seen_files.add(candidate_path)
                files.append(record)
        elif object_has_matching_text(obj, patterns):
            record = record_from_value(obj, current_path, options["name_keys"], options["path_keys"], pointer)
            candidate_path = record.get("path")
            if candidate_path and (looks_like_file_path(candidate_path) or record.get("url")):
                if candidate_path not in seen_files:
                    seen_files.add(candidate_path)
                    files.append(record)

    return directories, files


def shell_quote(value):
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


def shell_double_quote(value):
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"').replace("`", "\\`")
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


def render_download_template(template, endpoint_url, record):
    path_value = scalar_to_text(record.get("path"))
    name_value = scalar_to_text(record.get("name")) or basename_from_path(path_value)
    url_value = scalar_to_text(record.get("url"))
    values = SafeFormatDict(
        {
            "api_url": endpoint_url,
            "base_url": base_url_for(endpoint_url),
            "path": path_value,
            "path_encoded": urllib.parse.quote(path_value),
            "path_query": urllib.parse.quote_plus(path_value),
            "name": name_value,
            "name_encoded": urllib.parse.quote(name_value),
            "url": url_value,
            "token": "${" + TOKEN_ENV_VAR + "}",
        }
    )
    return template.format_map(values)


def default_download_url(endpoint_url, path_param, record):
    record_url = scalar_to_text(record.get("url"))
    if record_url.startswith(("http://", "https://")):
        return record_url

    path_value = scalar_to_text(record.get("path"))
    if path_value.startswith(("http://", "https://")):
        return path_value

    return add_query_param(endpoint_url, path_param, path_value)


def build_download_url(endpoint_url, path_param, download_template, record):
    if download_template:
        return render_download_template(download_template, endpoint_url, record)
    return default_download_url(endpoint_url, path_param, record)


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


def matching_patterns(record, patterns):
    text = searchable_record_text(record)
    decoded_text = urllib.parse.unquote_plus(text)
    search_space = text if decoded_text == text else text + "\n" + decoded_text
    return [pattern for pattern in patterns if pattern["compiled"].search(search_space)]


def make_finding(pattern, record, current_path, endpoint_url, args, proxy):
    filename = record.get("name") or basename_from_path(record.get("path"))
    download_url = build_download_url(endpoint_url, args.path_param, args.download_template, record)
    return {
        "pattern": pattern["pattern"],
        "pattern_line": pattern["line"],
        "pattern_mode": pattern["mode"],
        "regex": pattern["regex"],
        "filename": clean_candidate(filename),
        "api_path": current_path,
        "record_path": scalar_to_text(record.get("path")),
        "record_url": scalar_to_text(record.get("url")),
        "source_pointer": record.get("pointer", ""),
        "download_url": remove_query_param(download_url, args.token_param),
        "curl": build_curl_command(
            download_url,
            filename,
            bool(args.token),
            args.auth_mode,
            proxy,
            args.token_param,
        ),
    }


def print_finding(finding):
    print("[+] Match: {0}".format(finding["filename"]))
    print("    pattern: {0}".format(finding["pattern"]))
    print("    api_path: {0}".format(finding["api_path"]))
    print("    record: {0}".format(finding["record_path"] or finding["record_url"]))
    print("    curl: {0}".format(finding["curl"]))


def request_rest(session, endpoint_url, current_path, args):
    request_url = request_url_for(endpoint_url, args.token, args.auth_mode, args.token_param)
    if args.method == "GET":
        request_url = add_query_param(request_url, args.path_param, current_path)
        response = session.get(request_url, timeout=REQUEST_TIMEOUT)
    else:
        response = session.post(request_url, json={args.path_param: current_path}, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    return response.json()


def request_graphql(session, endpoint_url, current_path, query, variables, args):
    request_url = request_url_for(endpoint_url, args.token, args.auth_mode, args.token_param)
    request_variables = dict(variables)
    request_variables[args.graphql_path_variable] = current_path
    response = session.post(
        request_url,
        json={"query": query, "variables": request_variables},
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    data = response.json()
    if isinstance(data, dict) and data.get("errors"):
        raise RuntimeError("GraphQL returned errors: {0}".format(data["errors"]))
    return data


def build_options(args):
    return {
        "dir_keys": parse_csv(args.dir_keys),
        "file_keys": parse_csv(args.file_keys),
        "name_keys": parse_csv(args.name_keys),
        "path_keys": parse_csv(args.path_keys),
        "type_key": args.type_key,
        "directory_types": {value.lower() for value in parse_csv(args.directory_types)},
        "file_types": {value.lower() for value in parse_csv(args.file_types)},
    }


def prepare_graphql(args):
    if args.api_mode != "graphql":
        return "", {}
    if not args.graphql_query:
        raise ValueError("--graphql-query is required when --api-mode graphql is used")
    query = load_text_or_inline(args.graphql_query)
    variables = load_json_or_inline(args.graphql_variables)
    if not isinstance(variables, dict):
        raise ValueError("--graphql-variables must decode to a JSON object")
    return query, variables


def crawl(args):
    endpoint_url = normalized_endpoint(args.url, args.token_param)
    proxy = normalize_proxy(args.proxy)
    pattern_lines = load_pattern_lines(args.wordlist)
    patterns = compile_patterns(pattern_lines, args.pattern_mode)
    session = create_session(args.token, proxy, args.auth_mode)
    options = build_options(args)
    graphql_query, graphql_variables = prepare_graphql(args)

    queue = [args.root_path]
    visited = set()
    findings = []
    errors = []
    seen_findings = set()
    request_count = 0

    while queue:
        current_path = queue.pop(0)
        if current_path in visited:
            continue
        if args.max_requests and request_count >= args.max_requests:
            break

        if visited and args.delay > 0:
            time.sleep(args.delay)

        visited.add(current_path)
        request_count += 1
        print("[*] Querying {0}: {1}".format(args.api_mode, current_path))

        try:
            if args.api_mode == "graphql":
                data = request_graphql(session, endpoint_url, current_path, graphql_query, graphql_variables, args)
            else:
                data = request_rest(session, endpoint_url, current_path, args)
        except (requests.RequestException, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            error = {"api_path": current_path, "error": str(exc)}
            errors.append(error)
            print("[!] Error: {0} ({1})".format(current_path, exc))
            continue

        directories, files = extract_api_records(data, current_path, patterns, options)

        for directory in directories:
            directory_path = directory.get("path")
            if directory_path and directory_path not in visited and directory_path not in queue:
                queue.append(directory_path)

        for record in files:
            for pattern in matching_patterns(record, patterns):
                record_identity = record.get("path") or record.get("url") or record.get("name")
                key = (pattern["pattern"], current_path, record_identity)
                if key in seen_findings:
                    continue
                seen_findings.add(key)
                finding = make_finding(pattern, record, current_path, endpoint_url, args, proxy)
                print_finding(finding)
                findings.append(finding)

    return {
        "repository": REPOSITORY,
        "tool": TOOL_NAME,
        "target_api": endpoint_url,
        "api_mode": args.api_mode,
        "method": "POST" if args.api_mode == "graphql" else args.method,
        "auth_mode": args.auth_mode,
        "token_param": args.token_param,
        "path_param": args.path_param,
        "root_path": args.root_path,
        "proxy": proxy,
        "generated_at_unix": int(time.time()),
        "token_supplied": bool(args.token),
        "patterns_loaded": len(patterns),
        "requests_made": request_count,
        "paths_visited": len(visited),
        "matches_found": len(findings),
        "matches": findings,
        "errors": errors,
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
    print("[*] Requests made: {0}".format(result["requests_made"]))
    print("[*] Matches found: {0}".format(result["matches_found"]))


if __name__ == "__main__":
    main()
