#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Self-validate schemas/*.json against their declared JSON-Schema dialect.

Runs as the `schemas` CI job (docs/DEVELOPMENT_PLAN.md S0). Exits non-zero
if any schema fails to parse or violates its meta-schema.
"""

import glob
import json
import sys

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

# Both schema versions declare draft 2020-12 (spec 0001): v1alpha2, the
# current contract, and v1alpha1, frozen history the engine still reads
# (docs/DEVELOPMENT_PLAN_RECONCILIATION.md D-R2). Required
# explicitly — validator_for() would silently fall back to "latest" on a
# missing or misspelled $schema, letting an unchecked dialect pass this
# gate. Admitting another dialect is a deliberate change to this list.
REQUIRED_DIALECT = "https://json-schema.org/draft/2020-12/schema"

# The eight files the engine embeds and compiles (internal/lab/schema.go):
# four kinds in two versions. A missing one fails here, not at runtime.
EXPECTED = sorted(
    f"schemas/{kind}.{version}.json"
    for kind in ("checkpoint", "module", "playbook", "template")
    for version in ("v1alpha1", "v1alpha2")
)


def main() -> int:
    files = sorted(glob.glob("schemas/*.json"))
    if not files:
        print("no schemas found under schemas/", file=sys.stderr)
        return 1
    failed = False
    for path in sorted(set(EXPECTED) - set(files)):
        print(f"FAIL {path}: missing", file=sys.stderr)
        failed = True
    for path in files:
        try:
            with open(path, encoding="utf-8") as fh:
                schema = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"FAIL {path}: {exc}", file=sys.stderr)
            failed = True
            continue
        declared = schema.get("$schema")
        if declared != REQUIRED_DIALECT:
            print(
                f"FAIL {path}: $schema is {declared!r}, expected"
                f" {REQUIRED_DIALECT!r}",
                file=sys.stderr,
            )
            failed = True
            continue
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError as exc:
            print(f"FAIL {path}: {exc.message}", file=sys.stderr)
            failed = True
            continue
        print(f"ok   {path} (valid against {declared})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
