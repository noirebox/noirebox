from __future__ import annotations

import argparse


def _version() -> str:
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("noirebox")
    except PackageNotFoundError:  # running from the repo without installation
        return "0.4.0+unknown"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="noirebox",
        description="NoireBox — the flight data recorder for AI agents.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {_version()}")
    sub = parser.add_subparsers(dest="command")
    serve = sub.add_parser("serve", help="run the HTTP API (uvicorn)")
    serve.add_argument("--host", default="127.0.0.1", help="bind address")
    serve.add_argument("--port", type=int, default=8768, help="listening port")
    rec = sub.add_parser("reconcile",
                         help="reconciliation plugin — invariants over the journal (issue #3)")
    rec.add_argument("--config", required=True, help="JSON file with the invariants")
    rec.add_argument("--db", default=None,
                     help="journal path (default: NOIREBOX_DB or data/noirebox.db)")
    rec.add_argument("--journal-report", action="store_true",
                     help="seal the report as a reconciliation event")
    rec.add_argument("--fail-on-findings", action="store_true",
                     help="exit 2 if any open_gap/orphan/late finding exists (CI-friendly)")
    pack = sub.add_parser("audit-pack",
                          help="auditor pack: export + verifier report + "
                               "Annexe IV §2(f) description (ADR 010)")
    pack.add_argument("outdir", help="directory to write the pack into")
    pack.add_argument("--db", default=None,
                      help="journal path (default: NOIREBOX_DB or data/noirebox.db)")
    args = parser.parse_args(argv)

    if args.command == "serve":
        import uvicorn

        uvicorn.run("noirebox.main:app", host=args.host, port=args.port, log_level="info")
        return 0

    if args.command == "reconcile":
        import os

        from noirebox.chain import KeyPair
        from noirebox.reconcile import journal_report, load_config, reconcile
        from noirebox.store import EventStore

        db = args.db or os.environ.get("NOIREBOX_DB", "data/noirebox.db")
        store = EventStore(db)
        key = KeyPair.load_or_create(db + ".key")
        invariants = load_config(args.config)
        findings = reconcile(store.all(), invariants)
        for f in findings:
            print(f"  [{f.status:<14}] {f.correlation_id}  (invariant: {f.invariant})")
        print(f"[✓] {len(findings)} finding(s) over {len(store.all())} events")
        if args.journal_report:
            journal_report(store, key, invariants, findings)
            print("[✓] report sealed as a `reconciliation` event")
        return 2 if args.fail_on_findings and findings else 0

    if args.command == "audit-pack":
        import os

        from noirebox.aiact import audit_pack
        from noirebox.chain import KeyPair
        from noirebox.store import EventStore

        db = args.db or os.environ.get("NOIREBOX_DB", "data/noirebox.db")
        store = EventStore(db)
        key = KeyPair.load_or_create(db + ".key")
        report = audit_pack(store, key, args.outdir)
        print(f"[{'✓' if report['valid'] else '✗'}] verifier report: "
              f"valid={report['valid']}, {report['nb_events_checked']} events, "
              f"{report['anchors_checked']} witness tokens checked "
              f"({report['anchors_pinned']} pinned)")
        print(f"[✓] pack written to {args.outdir}/ — export.json, "
              f"verifier_report.json, ANNEXE-IV-2f.md")
        return 0 if report["valid"] else 1

    parser.print_help()
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
