from __future__ import annotations

import argparse


def _version() -> str:
    from . import __version__

    return __version__


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
    traj = sub.add_parser("seal-trajectory",
                          help="seal a coding agent's model trajectory "
                               "(model-io JSONL, ADR 012) — digests only")
    traj.add_argument("file", nargs="?",
                      help="path to the model-io-*.jsonl file")
    traj.add_argument("--rollout", default=None,
                      help="scan a rollout DIR instead of one file: seals "
                           "every new-or-changed model-io file; sealed lines "
                           "are printed on stderr (plugin-hook facing)")
    traj.add_argument("--interval", type=int, default=10,
                      help="minutes between rollout scans (default 10)")
    traj.add_argument("--format", default="model-io",
                      choices=["model-io", "session-transcript", "generic-jsonl", "auto"],
                      help="log shape: model-io (per-call, default), "
                           "session-transcript / generic-jsonl (ADR 013), "
                           "auto = sniff by shape")
    traj.add_argument("--db", default=None,
                      help="journal path (default: NOIREBOX_DB or data/noirebox.db)")
    hook = sub.add_parser("hook",
                          help="integration hook: seal one agent event from "
                               "hook JSON on stdin (best-effort, ADR 013)")
    hooksub = hook.add_subparsers(dest="hook_event")
    hooksub.add_parser("tool-use", help="seal one agent tool action (PostToolUse)")
    hooksub.add_parser("session-end", help="seal the session transcript (SessionEnd)")
    seal = sub.add_parser("seal",
                          help="seal one free-form event into the journal "
                               "(digests and short facts, never raw content)")
    seal.add_argument("type", help="event type (e.g. note, decision)")
    seal.add_argument("payload", help="JSON payload")
    seal.add_argument("--db", default=None,
                      help="journal path (default: NOIREBOX_DB, then the "
                           "nearest .noirebox/ directory, then ./.noirebox/)")
    verify = sub.add_parser("verify",
                            help="verify the journal chain in place and "
                                 "print the verdict")
    verify.add_argument("--db", default=None,
                        help="journal path (default: NOIREBOX_DB, then the "
                             "nearest .noirebox/ directory, then ./.noirebox/)")
    sub.add_parser("locate", help="print the resolved journal path")
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

    if args.command == "seal-trajectory":
        import os
        import sys

        from noirebox.chain import KeyPair, verify_chain
        from noirebox.store import EventStore
        from noirebox.trajectory import read_model_io, trajectory_payload

        db = args.db or os.environ.get("NOIREBOX_DB", "data/noirebox.db")

        if args.rollout:
            from noirebox.trajseal import seal_rollout

            for line in seal_rollout(args.rollout, db, interval_min=args.interval):
                print(f"[noirebox] trajectory sealed: {line}", file=sys.stderr)
            return 0

        if not args.file:
            print("[✗] nothing to seal: give a file, or --rollout <dir>")
            return 1
        try:
            if args.format == "model-io":
                summary = read_model_io(args.file)
                payload = trajectory_payload(summary)
            else:
                from noirebox import transcripts

                if args.format == "auto":
                    summary = transcripts.read_summary(args.file)
                    if summary.origin == transcripts.MODEL_IO:
                        summary = read_model_io(args.file)  # strict reader, ADR 012
                        payload = trajectory_payload(summary)
                    else:
                        payload = transcripts.transcript_payload(summary)
                else:
                    summary = transcripts.read_summary(args.file, origin=args.format)
                    payload = transcripts.transcript_payload(summary)
        except ValueError as exc:
            print(f"[✗] {exc}")
            return 1
        store = EventStore(db)
        key = KeyPair.load_or_create(db + ".key")
        event = store.append("model_trajectory", payload, key)
        tail = " (truncated tail ignored)" if summary.truncated_tail else ""
        print(f"[✓] {summary.record_count} model call(s) sealed{tail} — "
              f"session {', '.join(summary.session_ids)}")
        print(f"    trajectory_digest {summary.trajectory_digest}")
        print(f"    event seq={event.seq} hash={event.event_hash}")
        check = verify_chain(key.public_hex(), store.all())
        print(f"[{'✓' if check['valid'] else '✗'}] chain valid over "
              f"{check['nb_events']} events")
        return 0 if check["valid"] else 1

    if args.command == "hook":
        import sys

        from noirebox.hookcli import run as hook_run

        return hook_run(args.hook_event, stdin=sys.stdin)

    if args.command == "seal":
        import json as _json

        from noirebox import locate
        from noirebox.chain import KeyPair, verify_chain
        from noirebox.store import EventStore

        try:
            payload = _json.loads(args.payload)
        except _json.JSONDecodeError as exc:
            print(f"[✗] payload is not valid JSON: {exc}")
            return 1
        if not isinstance(payload, dict):
            print("[✗] payload must be a JSON object")
            return 1
        db = args.db or locate.ensure_journal_dir()
        store = EventStore(db)
        key = KeyPair.load_or_create(db + ".key")
        event = store.append(args.type, payload, key)
        print(f"[✓] sealed {args.type}: seq={event.seq} hash={event.event_hash}")
        return 0

    if args.command == "verify":
        from noirebox import locate
        from noirebox.chain import KeyPair, verify_chain
        from noirebox.store import EventStore

        db = args.db or locate.resolve_journal()
        import os
        if not os.path.exists(db):
            print(f"[✗] no journal at {db}")
            return 1
        store = EventStore(db)
        key = KeyPair.load_or_create(db + ".key")
        check = verify_chain(key.public_hex(), store.all())
        verdict = "VALID" if check["valid"] else "TAMPERED"
        print(f"[{verdict}] {check['nb_events']} events — {db}")
        if not check["valid"]:
            err = check["first_error"]
            print(f"    first anomaly at seq={err['seq']}: {err['reason']}")
        return 0 if check["valid"] else 1

    if args.command == "locate":
        from noirebox import locate

        print(locate.resolve_journal())
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
