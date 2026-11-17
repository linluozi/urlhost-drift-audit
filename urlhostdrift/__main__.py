"""CLI: python -m urlhostdrift {run,show,selftest}"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import audit, save, verify_ipv4_oracle
from .corpus import build_corpus
from .parsers import parse_reference

DEFAULT_OUT = Path("evidence")


def _print_summary(summary: dict) -> None:
    m = summary["meta"]
    print(f"corpus: raw={m['corpus_raw']} unique={m['corpus_unique']} "
          f"duplicates={m['corpus_duplicates']} sha256={m['corpus_sha256'][:16]}")
    print(f"versions: {m['versions']}")
    print(f"report_sha256: {summary['report_sha256']}")
    for name, counts in summary["classes"].items():
        print(f"  {name:8s} {dict(counts)}")
    for name, counts in summary["families"].items():
        print(f"  families[{name}]: {dict(counts)}")
    for policy, per in summary["guard"].items():
        print(f"guard.{policy}: " + ", ".join(f"{k}={v['count']}" for k, v in per.items()))


def cmd_run(args) -> int:
    summary = audit()
    paths = save(summary, args.out)
    _print_summary(summary)
    corpus = build_corpus()
    refs = parse_reference(corpus["urls"])
    oracle = verify_ipv4_oracle(corpus["urls"], refs)
    print(f"ipv4 oracle: checked={oracle['checked']} mismatches={oracle['mismatch_count']}")
    print(f"wrote: {paths['summary']}, {paths['findings']}")
    return 0


def cmd_show(args) -> int:
    path = Path(args.out) / "summary.json"
    summary = json.loads(path.read_text())
    print(f"report_sha256: {summary['report_sha256']}")
    print(f"corpus_unique: {summary['meta']['corpus_unique']}")
    return 0


def cmd_selftest(args) -> int:
    first = audit()
    second = audit()
    ok = first["report_sha256"] == second["report_sha256"]
    print(f"determinism: {'PASS' if ok else 'FAIL'} "
          f"({first['report_sha256'][:16]} == {second['report_sha256'][:16]})")
    return 0 if ok else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="urlhostdrift")
    sub = parser.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="run the full audit")
    run.add_argument("--out", default=str(DEFAULT_OUT))
    run.set_defaults(func=cmd_run)
    show = sub.add_parser("show", help="print the committed report digest")
    show.add_argument("--out", default=str(DEFAULT_OUT))
    show.set_defaults(func=cmd_show)
    self_test = sub.add_parser("selftest", help="run the audit twice and compare digests")
    self_test.set_defaults(func=cmd_selftest)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())