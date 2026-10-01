#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""YAML-parse every file under scenarios/ (the `scenarios-yaml` CI job).

Parse-only by design: structural validation against spec 0001 arrives with
`lab validate` at plan step S3. Exits non-zero on any unparseable file.
"""

import glob
import sys

import yaml


def main() -> int:
    files = sorted(glob.glob("scenarios/**/*.y*ml", recursive=True))
    if not files:
        print("no YAML found under scenarios/", file=sys.stderr)
        return 1
    failed = False
    for path in files:
        try:
            with open(path, encoding="utf-8") as fh:
                docs = list(yaml.safe_load_all(fh))
        except (OSError, yaml.YAMLError) as exc:
            print(f"FAIL {path}: {exc}", file=sys.stderr)
            failed = True
            continue
        plural = "s" if len(docs) != 1 else ""
        print(f"ok   {path} ({len(docs)} document{plural})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
