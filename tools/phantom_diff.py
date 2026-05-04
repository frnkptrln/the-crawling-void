#!/usr/bin/env python3
import argparse
from pathlib import Path

from tcv.common import read_json, write_json


def keyset(data):
    out = set()
    if isinstance(data, dict):
        for k, v in data.items():
            out.add(str(k))
            if isinstance(v, list):
                out.update(str(x) for x in v)
            elif isinstance(v, dict):
                out.update(str(x) for x in v.keys())
    elif isinstance(data, list):
        out.update(str(x) for x in data)
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("old_json")
    p.add_argument("new_json")
    p.add_argument("--output", default="phantom_diff.json")
    p.add_argument("--markdown", default="phantom_diff.md")
    args = p.parse_args()

    old = read_json(args.old_json)
    new = read_json(args.new_json)
    old_s, new_s = keyset(old), keyset(new)
    diff = {
        "added": sorted(new_s - old_s),
        "removed": sorted(old_s - new_s),
        "reappeared": sorted((new_s & old_s)),
        "changed": sorted(x for x in (new_s & old_s) if str(old) != str(new)),
    }
    write_json(args.output, diff)
    md = ["# phantom-diff", "", f"- added: {len(diff['added'])}", f"- removed: {len(diff['removed'])}", f"- changed: {len(diff['changed'])}", f"- reappeared: {len(diff['reappeared'])}"]
    Path(args.markdown).write_text("\n".join(md), encoding="utf-8")


if __name__ == "__main__":
    main()
