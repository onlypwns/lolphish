#!/usr/bin/env python3
"""
LOLPHISH build script.

Reads entries/*.yml, validates each against schema/entry.schema.json,
and regenerates:
  - data.js            (consumed by the site)
  - api/entries.json   (machine-readable feed for downstream tooling)

Usage:
  python3 build.py            # validate + build
  python3 build.py --check    # validate only (CI mode)

Requires: pyyaml, jsonschema  (pip install pyyaml jsonschema)
"""

import argparse
import glob
import json
import os
import sys

import yaml

try:
    import jsonschema
except ImportError:
    jsonschema = None

ROOT = os.path.dirname(os.path.abspath(__file__))
ENTRIES_DIR = os.path.join(ROOT, "entries")
SCHEMA_PATH = os.path.join(ROOT, "schema", "entry.schema.json")
DATA_JS_PATH = os.path.join(ROOT, "data.js")
API_PATH = os.path.join(ROOT, "api", "entries.json")

CATEGORY_META = {
    "Identity Flow Abuse":     {"color": "#6fd3d3", "blurb": "Abused auth mechanisms — the phish happens on the real login page"},
    "User-Assisted Execution": {"color": "#d3b46f", "blurb": "The victim is the dropper — clipboard, QR, paste-to-run tricks"},
    "Trusted Delivery":        {"color": "#b48fd3", "blurb": "The lure arrives from infrastructure your filters were told to trust"},
    "Reputation Laundering":   {"color": "#8fd3a0", "blurb": "Hosting and redirect chains that inherit someone else's good name"},
}

FIELD_ORDER = ["id", "name", "category", "vendors", "summary", "abuse", "variants",
               "kits", "surfaces", "attack", "detections", "detection_code",
               "mitigations", "refs", "since"]


def fail(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def load_entries():
    schema = json.load(open(SCHEMA_PATH, encoding="utf-8"))
    entries = []
    paths = sorted(glob.glob(os.path.join(ENTRIES_DIR, "*.yml")))
    if not paths:
        fail(f"no entry files found in {ENTRIES_DIR}")

    for path in paths:
        slug = os.path.splitext(os.path.basename(path))[0]
        if slug.startswith("_"):
            continue  # skip _template.yml and friends
        try:
            data = yaml.safe_load(open(path, encoding="utf-8"))
        except yaml.YAMLError as e:
            fail(f"{slug}: YAML parse error: {e}")
        if not isinstance(data, dict):
            fail(f"{slug}: entry is not a mapping")

        if jsonschema:
            try:
                jsonschema.validate(data, schema)
            except jsonschema.ValidationError as e:
                fail(f"{slug}: schema violation — {e.message} "
                     f"(field: {'/'.join(str(p) for p in e.absolute_path) or 'root'})")
        else:
            missing = [k for k in schema["required"] if k not in data]
            if missing:
                fail(f"{slug}: missing required fields {missing} "
                     "(install jsonschema for full validation)")

        if data["id"] != slug:
            fail(f"{slug}: 'id' field ({data['id']}) must match filename")
        if data["category"] not in CATEGORY_META:
            fail(f"{slug}: unknown category '{data['category']}'")

        entries.append({k: data[k] for k in FIELD_ORDER if k in data})

    ids = [e["id"] for e in entries]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        fail(f"duplicate entry ids: {', '.join(sorted(dupes))}")

    return entries


def build(entries):
    stats = {
        "entries": len(entries),
        "variants": sum(len(e["variants"]) for e in entries),
        "kits": sum(len(e["kits"]) for e in entries),
        "vendors": sorted({v for e in entries for v in e["vendors"]}),
        "categories": sorted({e["category"] for e in entries}),
    }

    header = "/* GENERATED FILE — do not edit. Source of truth: entries/*.yml (run build.py) */\n\n"
    js = header
    js += "const ENTRIES = " + json.dumps(entries, indent=2, ensure_ascii=False) + ";\n\n"
    js += "const STATS = " + json.dumps(stats, indent=2, ensure_ascii=False) + ";\n\n"
    js += "const CATEGORY_META = " + json.dumps(
        {k: {"color": v["color"], "blurb": v["blurb"]} for k, v in CATEGORY_META.items()},
        indent=2, ensure_ascii=False) + ";\n"

    with open(DATA_JS_PATH, "w", encoding="utf-8") as f:
        f.write(js)

    os.makedirs(os.path.dirname(API_PATH), exist_ok=True)
    with open(API_PATH, "w", encoding="utf-8") as f:
        json.dump({"version": "0.4", "generated_by": "lolphish build.py",
                   "stats": stats, "entries": entries}, f, indent=2, ensure_ascii=False)

    print(f"OK - {stats['entries']} entries, {stats['variants']} variants, "
          f"{stats['kits']} kits/actors -> data.js + api/entries.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="validate only, no output")
    args = ap.parse_args()

    entries = load_entries()
    if args.check:
        print(f"OK — {len(entries)} entries valid")
    else:
        build(entries)


if __name__ == "__main__":
    main()
