#!/usr/bin/env python3
"""Compare two crawler snapshots without inventing lifecycle semantics."""

import argparse
import json
from pathlib import Path

from tcv.common import read_json, write_json


COLLECTION_KEYS = (
    "matches",
    "files",
    "indicators",
    "directories",
    "nodes",
    "urls",
)
IDENTITY_KEYS = (
    "id",
    "url",
    "download_url",
    "record_url",
    "record_path",
    "path",
    "normalized",
    "value",
    "filename",
    "name",
)


def records_from_snapshot(data):
    if isinstance(data, list):
        return data, "$"
    if isinstance(data, dict):
        for key in COLLECTION_KEYS:
            if isinstance(data.get(key), list):
                return data[key], "$." + key
        list_keys = [key for key, value in data.items() if isinstance(value, list)]
        if len(list_keys) == 1:
            key = list_keys[0]
            return data[key], "$." + key
    raise ValueError(
        "snapshot must be a list or contain one supported record collection: "
        + ", ".join(COLLECTION_KEYS)
    )


def record_identity(record):
    if not isinstance(record, dict):
        return "scalar:" + json.dumps(record, ensure_ascii=False, sort_keys=True)

    for key in IDENTITY_KEYS:
        value = record.get(key)
        if value not in (None, "", [], {}):
            return "record:" + json.dumps([key, value], ensure_ascii=False, sort_keys=True)
    return "record:" + json.dumps(record, ensure_ascii=False, sort_keys=True)


def index_records(records):
    indexed = {}
    for record in records:
        identity = record_identity(record)
        if identity in indexed:
            raise ValueError("duplicate record identity: " + identity)
        indexed[identity] = record
    return indexed


def compare_snapshots(old, new):
    old_records, old_collection = records_from_snapshot(old)
    new_records, new_collection = records_from_snapshot(new)
    old_index = index_records(old_records)
    new_index = index_records(new_records)

    old_ids = set(old_index)
    new_ids = set(new_index)
    shared_ids = old_ids & new_ids
    changed_ids = sorted(
        identity
        for identity in shared_ids
        if old_index[identity] != new_index[identity]
    )
    unchanged_ids = sorted(shared_ids - set(changed_ids))

    return {
        "old_collection": old_collection,
        "new_collection": new_collection,
        "added": [new_index[identity] for identity in sorted(new_ids - old_ids)],
        "removed": [old_index[identity] for identity in sorted(old_ids - new_ids)],
        "changed": [
            {
                "identity": identity,
                "before": old_index[identity],
                "after": new_index[identity],
            }
            for identity in changed_ids
        ],
        "unchanged": [new_index[identity] for identity in unchanged_ids],
    }


def markdown_summary(diff):
    return "\n".join(
        [
            "# phantom-diff",
            "",
            f"- added: {len(diff['added'])}",
            f"- removed: {len(diff['removed'])}",
            f"- changed: {len(diff['changed'])}",
            f"- unchanged: {len(diff['unchanged'])}",
            "",
            "> Reappearance requires at least three lifecycle-aware snapshots and is not inferred here.",
            "",
        ]
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("old_json")
    parser.add_argument("new_json")
    parser.add_argument("--output", default="phantom_diff.json")
    parser.add_argument("--markdown", default="phantom_diff.md")
    args = parser.parse_args()

    try:
        diff = compare_snapshots(read_json(args.old_json), read_json(args.new_json))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))

    write_json(args.output, diff)
    Path(args.markdown).write_text(markdown_summary(diff), encoding="utf-8")


if __name__ == "__main__":
    main()
