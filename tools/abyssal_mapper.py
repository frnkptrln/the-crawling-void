#!/usr/bin/env python3
import argparse
import html
import json
import re
import urllib.parse
from collections import deque
from pathlib import Path

import requests

from tcv.common import write_json

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
ONION_RE = re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.IGNORECASE)
HREF_RE = re.compile(r"(?is)\bhref\s*=\s*[\"']([^\"']+)")


def host_allowed(url, allowed_hosts):
    if not allowed_hosts:
        return True
    host = urllib.parse.urlparse(url).hostname or ""
    return host in allowed_hosts


def extract_urls(text, base_url=""):
    found = set(URL_RE.findall(text))
    for m in HREF_RE.finditer(text):
        link = html.unescape(m.group(1).strip())
        if link.startswith(("mailto:", "javascript:", "#", "tel:")):
            continue
        absolute = urllib.parse.urljoin(base_url, link)
        if absolute.startswith(("http://", "https://")):
            found.add(absolute)
    return sorted(found), sorted(set(ONION_RE.findall(text)))


def export_graphml(path, nodes, edges):
    lines = ['<?xml version="1.0" encoding="UTF-8"?>', '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">', '<graph edgedefault="directed">']
    for n in nodes:
        lines.append(f'<node id="{n}"/>')
    for i, (s, t) in enumerate(edges):
        lines.append(f'<edge id="e{i}" source="{s}" target="{t}"/>')
    lines += ["</graph>", "</graphml>"]
    Path(path).write_text("\n".join(lines), encoding="utf-8")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--html", action="append", default=[])
    p.add_argument("--crawler-json")
    p.add_argument("--url")
    p.add_argument("--output", default="abyssal_graph.json")
    p.add_argument("--graphml", default="abyssal_graph.graphml")
    p.add_argument("--max-depth", type=int, default=1)
    p.add_argument("--max-pages", type=int, default=25)
    p.add_argument("--same-origin", action="store_true")
    p.add_argument("--allowed-host", action="append", default=[])
    args = p.parse_args()

    nodes, edges, queue, seen = set(), set(), deque(), set()

    for file in args.html:
        txt = Path(file).read_text(encoding="utf-8", errors="replace")
        urls, onions = extract_urls(txt)
        nodes.update(urls + onions)

    if args.crawler_json:
        data = json.loads(Path(args.crawler_json).read_text(encoding="utf-8"))
        dumped = json.dumps(data)
        urls, onions = extract_urls(dumped)
        nodes.update(urls + onions)

    if args.url:
        queue.append((args.url, 0, args.url))

    root_host = urllib.parse.urlparse(args.url).hostname if args.url else None
    session = requests.Session()
    pages = 0
    while queue and pages < args.max_pages:
        url, depth, parent = queue.popleft()
        if url in seen or depth > args.max_depth:
            continue
        seen.add(url)
        if args.same_origin and root_host and urllib.parse.urlparse(url).hostname != root_host:
            continue
        if not host_allowed(url, args.allowed_host):
            continue
        try:
            resp = session.get(url, timeout=20)
            ctype = resp.headers.get("Content-Type", "")
            if "text" not in ctype and "html" not in ctype:
                continue
            text = resp.text
        except Exception:
            continue
        pages += 1
        nodes.add(url)
        if parent != url:
            edges.add((parent, url))
        urls, onions = extract_urls(text, url)
        nodes.update(onions)
        for u in urls:
            nodes.add(u)
            edges.add((url, u))
            queue.append((u, depth + 1, url))

    graph = {"nodes": sorted(nodes), "edges": [{"source": s, "target": t} for s, t in sorted(edges)]}
    write_json(args.output, graph)
    export_graphml(args.graphml, sorted(nodes), sorted(edges))


if __name__ == "__main__":
    main()
