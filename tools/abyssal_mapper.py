#!/usr/bin/env python3
"""Build a bounded URL graph from local evidence or an explicitly scoped seed."""

import argparse
import html
import json
import re
import urllib.parse
import xml.etree.ElementTree as ET
from collections import deque
from pathlib import Path

import requests

from tcv.common import write_json
from tcv.redaction import redact_text, redact_url


URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
ONION_RE = re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.IGNORECASE)
HREF_RE = re.compile(r"(?is)\bhref\s*=\s*[\"']([^\"']+)")
GRAPHML_NS = "http://graphml.graphdrawing.org/xmlns"
DEFAULT_MAX_BYTES = 2 * 1024 * 1024


def normalized_host(url):
    return (urllib.parse.urlparse(url).hostname or "").lower().rstrip(".")


def host_allowed(url, allowed_hosts):
    if not allowed_hosts:
        return True
    return normalized_host(url) in allowed_hosts


def extract_urls(text, base_url=""):
    found = set(URL_RE.findall(text))
    for match in HREF_RE.finditer(text):
        link = html.unescape(match.group(1).strip())
        if link.startswith(("mailto:", "javascript:", "#", "tel:", "data:")):
            continue
        absolute = urllib.parse.urljoin(base_url, link)
        if absolute.startswith(("http://", "https://")):
            found.add(absolute)
    return sorted(found), sorted(set(ONION_RE.findall(text)))


def export_graphml(path, nodes, edges):
    ET.register_namespace("", GRAPHML_NS)
    graphml = ET.Element(f"{{{GRAPHML_NS}}}graphml")
    ET.SubElement(
        graphml,
        f"{{{GRAPHML_NS}}}key",
        {"id": "url", "for": "node", "attr.name": "url", "attr.type": "string"},
    )
    graph = ET.SubElement(graphml, f"{{{GRAPHML_NS}}}graph", {"edgedefault": "directed"})
    node_ids = {value: f"n{index}" for index, value in enumerate(sorted(nodes))}
    for value, node_id in node_ids.items():
        node = ET.SubElement(graph, f"{{{GRAPHML_NS}}}node", {"id": node_id})
        ET.SubElement(node, f"{{{GRAPHML_NS}}}data", {"key": "url"}).text = value
    for index, (source, target) in enumerate(sorted(edges)):
        ET.SubElement(
            graph,
            f"{{{GRAPHML_NS}}}edge",
            {"id": f"e{index}", "source": node_ids[source], "target": node_ids[target]},
        )
    ET.ElementTree(graphml).write(path, encoding="utf-8", xml_declaration=True)


def fetch_text(session, url, max_bytes):
    response = session.get(url, timeout=(15, 30), stream=True)
    response.raise_for_status()
    try:
        content_type = response.headers.get("Content-Type", "").lower()
        if content_type and "text" not in content_type and "html" not in content_type:
            return "", "non-text response"
        chunks = []
        total = 0
        for chunk in response.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            if total + len(chunk) > max_bytes:
                chunks.append(chunk[: max_bytes - total])
                return b"".join(chunks).decode(response.encoding or "utf-8", errors="replace"), "truncated"
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks).decode(response.encoding or "utf-8", errors="replace"), ""
    finally:
        response.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--html", action="append", default=[])
    parser.add_argument("--crawler-json")
    parser.add_argument("--url")
    parser.add_argument("--output", default="abyssal_graph.json")
    parser.add_argument("--graphml", default="abyssal_graph.graphml")
    parser.add_argument("--max-depth", type=int, default=1)
    parser.add_argument("--max-pages", type=int, default=25)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--same-origin", action="store_true", help="Retained for compatibility; now the default.")
    parser.add_argument("--include-external", action="store_true", help="Allow off-origin crawl requests.")
    parser.add_argument("--allowed-host", action="append", default=[])
    args = parser.parse_args()

    nodes, edges, queue, seen = set(), set(), deque(), set()
    errors, skipped = [], []

    for filename in args.html:
        text = Path(filename).read_text(encoding="utf-8", errors="replace")
        urls, onions = extract_urls(text)
        nodes.update(urls + onions)

    if args.crawler_json:
        data = json.loads(Path(args.crawler_json).read_text(encoding="utf-8"))
        urls, onions = extract_urls(json.dumps(data))
        nodes.update(urls + onions)

    if args.url:
        queue.append((args.url, 0, args.url))

    root_host = normalized_host(args.url) if args.url else ""
    allowed_hosts = {value.lower().rstrip(".") for value in args.allowed_host}
    session = requests.Session()
    pages = 0
    while queue and pages < args.max_pages:
        url, depth, parent = queue.popleft()
        if url in seen or depth > args.max_depth:
            continue
        seen.add(url)
        if not args.include_external and root_host and normalized_host(url) != root_host:
            skipped.append({"url": redact_url(url), "reason": "off-origin"})
            continue
        if not host_allowed(url, allowed_hosts):
            skipped.append({"url": redact_url(url), "reason": "host not allowed"})
            continue
        try:
            text, reason = fetch_text(session, url, args.max_bytes)
        except requests.RequestException as exc:
            errors.append({"url": redact_url(url), "error": redact_text(str(exc))})
            continue
        if reason == "non-text response":
            skipped.append({"url": redact_url(url), "reason": reason})
            continue
        if reason:
            skipped.append({"url": redact_url(url), "reason": reason})
        pages += 1
        nodes.add(url)
        if parent != url:
            edges.add((parent, url))
        urls, onions = extract_urls(text, url)
        nodes.update(onions)
        for candidate in urls:
            nodes.add(candidate)
            edges.add((url, candidate))
            queue.append((candidate, depth + 1, url))

    graph = {
        "nodes": sorted(nodes),
        "edges": [{"source": source, "target": target} for source, target in sorted(edges)],
        "pages_crawled": pages,
        "errors": errors,
        "skipped": skipped,
    }
    write_json(args.output, graph)
    export_graphml(args.graphml, sorted(nodes), sorted(edges))


if __name__ == "__main__":
    main()
