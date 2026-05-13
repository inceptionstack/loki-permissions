#!/usr/bin/env python3
"""Parity check between policies/*.json and Terraform-rendered statement lists.

The Terraform module's deny_guardrails / iam_scoped / permissions_boundary
policies and policies/*.json must encode identical Sid → (Action|NotAction)
sets. Drift would leave one deployment path under-protected.

Usage:

    # Default: assumes you're in terraform/ with rendered tf-*.json there.
    python3 ../scripts/check_parity.py

    # Or pass a render directory explicitly:
    python3 scripts/check_parity.py --render-dir terraform

Exits 0 on parity, 1 on drift.

Note on scope: this verifies Action/NotAction parity per Sid.
Resource/NotResource/Condition are NOT checked because `terraform console`
can't resolve resource refs like `aws_iam_role.agent.arn` without an apply
(returns "known after apply"). Scope correctness is enforced by review +
the JSON template's literal placeholders being humanly auditable.
"""

import argparse
import json
import sys
import pathlib

# Repo-relative paths resolved against this script's location, not CWD.
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# (logical name, JSON source path relative to REPO_ROOT, TF render filename)
POLICIES = [
    ("deny-guardrails",      "policies/deny-guardrails.json",      "tf-deny.json"),
    ("iam-scoped",           "policies/iam-scoped.json",           "tf-iam-scoped.json"),
    ("permissions-boundary", "policies/permissions-boundary.json", "tf-boundary.json"),
]


def actions_of(stmt):
    """Return (action_set, notaction_set) tuple. Either may be empty.
    Handles Action/NotAction being either a list or a string."""
    def to_set(key):
        if key not in stmt or stmt[key] is None:
            return frozenset()
        v = stmt[key]
        return frozenset(v) if isinstance(v, list) else frozenset([v])
    return to_set("Action"), to_set("NotAction")


def by_sid(stmts):
    return {s["Sid"]: actions_of(s) for s in stmts}


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--render-dir",
        default="terraform",
        help="Directory containing the Terraform-rendered tf-*.json files "
             "(default: terraform, resolved relative to repo root).",
    )
    args = parser.parse_args()

    render_dir = (REPO_ROOT / args.render_dir).resolve()

    any_drift = False
    for name, json_rel, tf_filename in POLICIES:
        json_path = REPO_ROOT / json_rel
        tf_path = render_dir / tf_filename

        if not tf_path.exists():
            print(f"[{name}] MISSING render file: {tf_path}", file=sys.stderr)
            print(f"  Run `terraform console` to produce it before this check.", file=sys.stderr)
            sys.exit(2)

        j  = json.loads(json_path.read_text())
        tf = json.loads(tf_path.read_text())
        js = by_sid(j["Statement"])
        ts = by_sid(tf)

        miss_tf  = set(js) - set(ts)
        miss_json = set(ts) - set(js)
        if miss_tf or miss_json:
            any_drift = True
            print(f"[{name}] STATEMENT DRIFT:")
            if miss_tf:   print(f"  Sids in JSON only: {sorted(miss_tf)}")
            if miss_json: print(f"  Sids in TF only:   {sorted(miss_json)}")

        for sid in sorted(set(js) & set(ts)):
            ja, jna = js[sid]
            ta, tna = ts[sid]
            if ja != ta:
                any_drift = True
                print(f"[{name}] ACTION DRIFT in Sid='{sid}':")
                if ja - ta: print(f"    JSON only: {sorted(ja - ta)}")
                if ta - ja: print(f"    TF only:   {sorted(ta - ja)}")
            if jna != tna:
                any_drift = True
                print(f"[{name}] NOTACTION DRIFT in Sid='{sid}':")
                if jna - tna: print(f"    JSON only: {sorted(jna - tna)}")
                if tna - jna: print(f"    TF only:   {sorted(tna - jna)}")

        total_a  = sum(len(a) for a, _ in js.values())
        total_na = sum(len(na) for _, na in js.values())
        extras = f", {total_na} NotActions" if total_na else ""
        print(f"[{name}] {len(js)} statements, {total_a} actions{extras}")

    if any_drift:
        sys.exit(1)
    print("all policies parity OK")


if __name__ == "__main__":
    main()
