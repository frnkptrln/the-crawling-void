#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

from tcv.indicators import PATTERNS
from tcv.common import write_json


def collect_text(paths):
    parts = []
    for p in paths:
        raw = Path(p).read_text(encoding="utf-8", errors="replace")
        parts.append(raw)
    return "\n".join(parts)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("inputs", nargs="+")
    p.add_argument("--output", default="tox_hunter.json")
    p.add_argument("--markdown", default="tox_hunter.md")
    args = p.parse_args()

    text = collect_text(args.inputs)
    results = {k: sorted(set(m.group(0) for m in rx.finditer(text))) for k, rx in PATTERNS.items()}
    write_json(args.output, results)

    md = ["# tox-hunter summary", ""]
    for k, vals in results.items():
        md.append(f"## {k} ({len(vals)})")
        md.extend([f"- `{v}`" for v in vals[:50]])
        md.append("")
    Path(args.markdown).write_text("\n".join(md), encoding="utf-8")


if __name__ == "__main__":
    main()
