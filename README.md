# the-crawling-void

> A small collection of disciplined crawlers for the places where ordinary mirrors lose the trail.

`the-crawling-void` is an open-source Threat Intelligence and OSINT toolkit for defensive analysis of modern leak-site surfaces, especially Tor hidden services that expose directory listings through single-page application routes such as `?path=/Downloads`.

The repository is intentionally structured for multiple crawlers. The first tool is `spa-path-crawler`, a JWT-aware crawler for dynamic `?path=` listings. It does not download files. It walks HTML views, searches locally for analyst-defined indicators or regular expressions, and emits reviewable `curl` commands for authorized follow-up.

The second tool is `api-crawler`, built for panels that render little or no HTML and instead expose JSON through REST or GraphQL APIs. It walks directory records from JSON arrays, extracts file records directly from data structures, and builds the same kind of token-redacted `curl` commands.

The third tool is `intel-harvester`, which extracts actor-side CTI indicators from ransomware blogs, forum posts, and negotiation pages: cryptocurrency wallets, TOX IDs, PGP public keys, and contact email addresses.

The fourth tool is `dumb-crawler`, a fast Open-Directory indexer for plain Apache and Nginx listings. It follows simple `<a href="...">` directory links, inventories file URLs, and avoids the heavier SPA/API logic when the server is just a bare directory listing.

## Description

Many current leak-site panels are not simple static indexes. Directory navigation may be represented entirely through URL parameters, while access control is carried in JWTs placed in headers, cookies, or even a `token` query parameter. This is where generic tooling such as `wget` tends to lose authenticated state or miss SPA routes.

`spa-path-crawler` performs breadth-first traversal of same-origin `?path=` routes. It records file-looking routes as candidate downloads but avoids fetching them as pages. Tokens are never written into JSON output; generated commands reference `${TCV_JWT_TOKEN}` instead.

## Repository Layout

```text
.
├── crawlers/
│   ├── api_crawler.py
│   ├── dumb_crawler.py
│   ├── intel_harvester.py
│   └── spa_path_crawler.py
├── README.md
├── requirements.txt
├── .gitignore
└── LICENSE
```

## Key Features

- Tor SOCKS5 proxy support with a `socks5h://localhost:9050` default.
- JWT handling through headers/cookies, query parameters, or both.
- SPA route crawling for `?path=` navigation.
- Same-origin breadth-first traversal to avoid unexpected off-target requests.
- File-looking `?path=` routes are reported but not crawled as HTML pages.
- Tor Browser style User-Agent headers.
- Local HTML scanning only; no automatic downloads.
- Pattern files with glob, literal, or raw-regex modes.
- JSON API crawling for REST and GraphQL-backed panels.
- Flexible JSON key mapping for `directories`, `files`, `children`, paths, names, and type fields.
- Optional download URL templates for panels whose API listing endpoint differs from the file endpoint.
- Actor-side CTI harvesting for Bitcoin, Monero, TOX, PGP public keys, and negotiation emails.
- Fast Apache/Nginx open-directory indexing for simple exposed file trees.
- Structured JSON findings with source route, inferred download URL, and generated `curl`.
- Token redaction by design: output uses `${TCV_JWT_TOKEN}` placeholders.

## Platform Support

The crawlers are pure Python and are intended to run on Linux, macOS, and Windows. The examples use `python`; on systems where Python 3 is exposed as `python3` or through the Windows launcher, replace `python` with `python3` or `py -3`.

Path examples use forward slashes such as `crawlers/spa_path_crawler.py`. Python accepts these paths on Windows as well.

## Prerequisites

- Python 3.9 or newer.
- Tor Browser or a Tor service exposing a local SOCKS proxy.
- Authorization to access the target service and analyze the listed material.

Common Tor SOCKS endpoints:

```text
socks5h://localhost:9050    Tor daemon or service
socks5h://localhost:9150    Tor Browser
```

The tools default to `socks5h://localhost:9050`. If you use Tor Browser, pass `--proxy socks5h://localhost:9150`.

Tor setup is platform-specific:

Linux:

```bash
sudo systemctl start tor
```

macOS with Homebrew:

```bash
brew services start tor
```

Windows:

- Start Tor Browser and keep it open.
- Use `--proxy socks5h://localhost:9150`.

Optional proxy checks:

```bash
curl --socks5-hostname localhost:9050 https://check.torproject.org/api/ip
curl --socks5-hostname localhost:9150 https://check.torproject.org/api/ip
```

## Installation

Linux/macOS:

```bash
git clone https://github.com/frnkptrln/the-crawling-void.git
cd the-crawling-void
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Windows PowerShell:

```powershell
git clone https://github.com/frnkptrln/the-crawling-void.git
cd the-crawling-void
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Usage

Keep all case material local. The repository ignores `*.txt`, `*.json`, token files, and logs by default.

Set JWT tokens without writing them to disk:

Linux/macOS:

```bash
export TCV_JWT_TOKEN="eyJ..."
```

Windows PowerShell:

```powershell
$env:TCV_JWT_TOKEN = "eyJ..."
```

The multi-line examples below use POSIX shell syntax with `\` line continuations and `$TCV_JWT_TOKEN`. On Windows PowerShell, either run the command on one line or replace `\` with PowerShell backticks, and use `$env:TCV_JWT_TOKEN` for token arguments.

Generated `curl` commands are POSIX-shell oriented. On Windows, run them from Git Bash or WSL, or translate them for PowerShell by using `curl.exe` and replacing `${TCV_JWT_TOKEN}` with `$env:TCV_JWT_TOKEN`.

Simple glob-style indicators:

```text
finance
payroll
acquisition
*.pst
```

Run with JWTs in headers and cookies:

```bash
python crawlers/spa_path_crawler.py \
  --url "http://example.onion/?path=/" \
  --token "$TCV_JWT_TOKEN" \
  --wordlist indicators.txt \
  --output findings.json
```

Run against panels that require `?token=<JWT>` in the URL:

```bash
python crawlers/spa_path_crawler.py \
  --url "http://example.onion/?path=/" \
  --token "$TCV_JWT_TOKEN" \
  --auth-mode query \
  --token-param token \
  --wordlist indicators.txt \
  --output findings.json
```

Use precise regex patterns for a real investigation workflow:

```text
25\d{4}_CASE_[^"'<]+
[^"'<]*invoice[^"'<]*
[^"'<]*contract[^"'<]*
[^"'<]*backup[^"'<]*
```

Then run:

```bash
python crawlers/spa_path_crawler.py \
  -u "http://example.onion/?path=/" \
  -t "$TCV_JWT_TOKEN" \
  -w case-patterns.txt \
  -o findings.json \
  --auth-mode query \
  --pattern-mode regex \
  -d 1
```

Generated commands are intentionally explicit. Execute them only after validating legal authority, collection scope, and operational risk:

```bash
curl -L --fail --silent --show-error --compressed --socks5-hostname 'localhost:9050' -A 'Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0' -o 'sample.zip' "http://example.onion/?path=%2FDownloads%2Fsample.zip&token=${TCV_JWT_TOKEN}"
```

## CLI Reference

```text
-u, --url             Base URL, for example http://example.onion/?path=/
-t, --token           JWT session token
-w, --wordlist        Local indicator or regex file
-o, --output          JSON output path
-p, --proxy           Proxy URL or host:port
-d, --delay           Delay between requests
--auth-mode           header, query, or both
--token-param         Query parameter name, default token
--pattern-mode        glob, literal, or regex
```

Pattern lines may also be prefixed individually:

```text
glob:*.xlsx
literal:Project Orion
regex:[^"'<]*payroll[^"'<]*\.zip
```

## API & GraphQL Crawler

Use `api-crawler` when the target panel returns JSON rather than HTML. The crawler requests one directory path at a time, parses arrays such as `directories`, `files`, `folders`, `items`, or `children`, and queues discovered directory paths.

REST example:

```bash
python crawlers/api_crawler.py \
  --url "http://example.onion/api/list" \
  --token "$TCV_JWT_TOKEN" \
  --auth-mode header \
  --path-param path \
  --root-path "/" \
  --wordlist indicators.txt \
  --output api-findings.json
```

REST panel with query-token auth and a separate download route:

```bash
python crawlers/api_crawler.py \
  -u "http://example.onion/api/list" \
  -t "$TCV_JWT_TOKEN" \
  -w case-patterns.txt \
  -o api-findings.json \
  --auth-mode query \
  --pattern-mode regex \
  --download-template "{base_url}/download?path={path_query}"
```

GraphQL example:

```bash
python crawlers/api_crawler.py \
  --api-mode graphql \
  --url "http://example.onion/graphql" \
  --graphql-query @queries/listFiles.graphql \
  --graphql-variables '{"limit": 500}' \
  --graphql-path-variable path \
  --token "$TCV_JWT_TOKEN" \
  --wordlist indicators.txt \
  --output graphql-findings.json
```

The GraphQL query should return directory and file arrays in any nested shape. For example:

```graphql
query ListFiles($path: String!, $limit: Int) {
  list(path: $path, limit: $limit) {
    directories {
      name
      path
    }
    files {
      filename
      path
      downloadUrl
    }
  }
}
```

Useful `api-crawler` options:

```text
--api-mode             rest or graphql
--method               GET or POST for REST
--path-param           REST path query/body field
--root-path            Initial path
--graphql-query        Inline query or @file
--graphql-variables    Inline JSON or @file
--download-template    Download URL template
--dir-keys             Directory array keys
--file-keys            File array keys
--name-keys            Filename field keys
--path-keys            Path or URL field keys
```

## Output Format

```json
{
  "repository": "the-crawling-void",
  "tool": "spa-path-crawler",
  "target": "http://example.onion/?path=%2F",
  "proxy": "socks5h://localhost:9050",
  "auth_mode": "query",
  "token_param": "token",
  "generated_at_unix": 1777286400,
  "token_supplied": true,
  "pages_crawled": 12,
  "patterns_loaded": 4,
  "matches_found": 2,
  "matches": [
    {
      "pattern": "[^\"'<]*payroll[^\"'<]*\\.zip",
      "pattern_line": 1,
      "pattern_mode": "regex",
      "regex": "[^\"'<]*payroll[^\"'<]*\\.zip",
      "filename": "payroll-archive.zip",
      "source_url": "http://example.onion/?path=%2FDownloads",
      "download_url": "http://example.onion/?path=%2FDownloads%2Fpayroll-archive.zip",
      "curl": "curl -L --fail --silent --show-error --compressed --socks5-hostname 'localhost:9050' -A 'Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0' -o 'payroll-archive.zip' \"http://example.onion/?path=%2FDownloads%2Fpayroll-archive.zip&token=${TCV_JWT_TOKEN}\""
    }
  ],
  "errors": [],
  "skipped_non_html": []
}
```

`api-crawler` produces the same high-level structure, with API-specific fields such as `target_api`, `api_mode`, `requests_made`, `api_path`, `record_path`, and `source_pointer`.

## Open-Directory Indexer

Use `dumb-crawler` when the target is a plain Apache or Nginx directory listing rather than an SPA or JSON API. It is intentionally simple: parse `<a href="...">`, ignore parent/sort links, queue same-origin directories, and record files. It does not download files.

Basic crawl:

```bash
python crawlers/dumb_crawler.py \
  --url "http://example.onion/files/" \
  --output open-directory.json
```

Fast but bounded crawl with filters:

```bash
python crawlers/dumb_crawler.py \
  -u "http://example.onion/files/" \
  -o open-directory.json \
  --max-pages 500 \
  --max-depth 10 \
  --delay 0.1 \
  --include-regex "\\.(zip|7z|rar|sql|xlsx)$"
```

Strict mode only parses pages that look like index listings:

```bash
python crawlers/dumb_crawler.py \
  -u "http://example.onion/" \
  -o open-directory.json \
  --strict-index
```

Output entries include file URL, parent directory URL, best-effort size and modified timestamp, and a generated `curl` command unless `--no-curl` is set.

## Threat-Actor Intel Harvester

Use `intel-harvester` when the objective is to track actor infrastructure and contact channels rather than victim files. It fetches text pages through Tor, strips basic HTML, and extracts CTI-relevant indicators:

- Bitcoin wallets
- Monero wallets
- TOX IDs
- PGP public key blocks
- standard and lightly obfuscated email addresses

Single-page harvest:

```bash
python crawlers/intel_harvester.py \
  --url "http://example.onion/blog/post" \
  --output actor-intel.json
```

Same-origin crawl with rate limiting:

```bash
python crawlers/intel_harvester.py \
  -u "http://example.onion/" \
  -o actor-intel.json \
  --max-pages 25 \
  --max-depth 2 \
  --delay 2
```

The output stores normalized indicator values, source URLs, and short context snippets:

```json
{
  "tool": "intel-harvester",
  "target": "http://example.onion/",
  "pages_harvested": 3,
  "indicators_found": 2,
  "indicators": [
    {
      "type": "tox_id",
      "value": "AABB...",
      "value_truncated": false,
      "normalized": "AABB...",
      "source_url": "http://example.onion/contact",
      "context": "contact us via TOX AABB..."
    }
  ]
}
```

## Legal Disclaimer

For educational and defensive Threat Intelligence purposes only. Use this tool only on systems, services, and data for which you have explicit authorization. The author and contributors are not responsible for misuse, unauthorized access, privacy violations, or unlawful handling of third-party data.
