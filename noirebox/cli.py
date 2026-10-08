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
                     help="journal path (default: NOIREBOX_DB, nearest .noirebox/, data/noirebox.db)")
    rec.add_argument("--journal-report", action="store_true",
                     help="seal the report as a reconciliation event")
    rec.add_argument("--fail-on-findings", action="store_true",
                     help="exit 2 if any open_gap/orphan/late finding exists (CI-friendly)")
    pack = sub.add_parser("audit-pack",
                          help="auditor pack: export + verifier report + "
                               "Annexe IV §2(f) description (ADR 010)")
    pack.add_argument("outdir", help="directory to write the pack into")
    pack.add_argument("--db", default=None,
                      help="journal path (default: NOIREBOX_DB, nearest .noirebox/, data/noirebox.db)")
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
                      help="journal path (default: NOIREBOX_DB, nearest .noirebox/, data/noirebox.db)")
    hook = sub.add_parser("hook",
                          help="integration hook: seal one agent event from "
                               "hook JSON on stdin (best-effort, ADR 013)")
    hooksub = hook.add_subparsers(dest="hook_event")
    hooksub.add_parser("tool-use", help="seal one agent tool action (PostToolUse)")
    hooksub.add_parser("session-end", help="seal the session transcript (SessionEnd)")
    flt = sub.add_parser("fleet-anchor",
                         help="fleet hub v0 (ADR 017): one Merkle seal covers N "
                              "journals — root witnessed by the configured TSAs, "
                              "proofs printed for every member")
    flt.add_argument("journals", nargs="+", help="journal paths to include")
    flt.add_argument("--db", default=None,
                     help="the HUB journal that seals the fleet anchor "
                          "(default: NOIREBOX_DB, nearest .noirebox/, repo layout)")
    flt.add_argument("--allow-local", action="store_true",
                     help="seal without a configured TSA (witness: local — the "
                          "proofs verify, no external date attests them)")
    flv = sub.add_parser("fleet-verify",
                         help="is this journal covered by the hub's latest fleet seal? "
                              "(local recomputation, exit 0/1)")
    flv.add_argument("journal", help="the member journal to check")
    flv.add_argument("--db", default=None,
                     help="the HUB journal holding the fleet_anchor (same defaults)")
    fls = sub.add_parser("fleet-status",
                         help="fleet hub v0 (ADR 017): check every member "
                              "against the hub's latest fleet seal — cron/CI "
                              "friendly (exit 0 all covered, exit 1 alarm)")
    fls.add_argument("members", nargs="+", help="member journal paths to check")
    fls.add_argument("--db", default=None,
                     help="the HUB journal holding the fleet_anchor (same defaults)")
    fls.add_argument("--json", action="store_true",
                     help="machine-readable report on stdout (for alerting)")
    rep = sub.add_parser("replay",
                         help="rebuild the decision timeline for one "
                              "meeting/run from sealed evidence (the chain "
                              "must verify first — replay refuses theater)")
    rep.add_argument("subject", help="the meeting_id (or run_id) to replay")
    rep.add_argument("--db", default=None,
                     help="journal path (same defaults as verify)")
    siem = sub.add_parser("export-siem",
                          help="export journal events for a SIEM: CEF "
                               "(ArcSight) or OTLP/JSON (OpenTelemetry)")
    siem.add_argument("--format", choices=["cef", "otlp"], default="cef")
    siem.add_argument("--since", type=int, default=0,
                      help="only events with seq > SINCE (the tail since the last export)")
    siem.add_argument("--db", default=None,
                      help="journal path (same defaults as verify)")
    flw = sub.add_parser("fleet-watch",
                         help="fleet console, service form (ADR 022): check "
                              "members on a wall-clock cadence, alarm on drift, "
                              "optionally re-seal the fleet (Ctrl-C to stop)")
    flw.add_argument("members", nargs="+", help="member journal paths to watch")
    flw.add_argument("--db", default=None,
                     help="the HUB journal (same defaults as fleet-status)")
    flw.add_argument("--interval", type=int, default=300,
                     help="seconds between checks (default 300)")
    flw.add_argument("--reanchor", action="store_true",
                     help="re-seal the fleet when the check is healthy "
                          "(shrinks the falsifiable window to the interval)")
    flw.add_argument("--webhook", default=None,
                     help="POST the alarm JSON to this URL on drift")
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
        from noirebox import locate
        from noirebox.chain import KeyPair, load_instance_key
        from noirebox.reconcile import journal_report, load_config, reconcile, run_probes
        from noirebox.store import EventStore

        db = args.db or locate.resolve_existing_journal()
        store = EventStore(db)
        key = load_instance_key(db)
        invariants, probes = load_config(args.config)
        events = store.all()
        findings = reconcile(events, invariants)
        for f in findings:
            print(f"  [{f.status:<14}] {f.correlation_id}  (invariant: {f.invariant})")
        probe_findings = run_probes(events, invariants, probes) if probes else []
        for f in probe_findings:
            print(f"  [{'PROBE':<14}] {f.correlation_id}  (negative control)")
        print(f"[✓] {len(findings)} finding(s) over {len(events)} events, "
              f"{len(probe_findings)} negative-control result(s)")
        if args.journal_report:
            journal_report(store, key, invariants, findings,
                           probes=probe_findings, events=events)
            print("[✓] report sealed as a `reconciliation` event "
                  "(always sealed — clean pass included, ADR 019)")
        return 2 if args.fail_on_findings and findings else 0

    if args.command == "audit-pack":
        from noirebox import locate
        from noirebox.aiact import audit_pack
        from noirebox.chain import KeyPair, load_instance_key
        from noirebox.store import EventStore

        db = args.db or locate.resolve_existing_journal()
        store = EventStore(db)
        key = load_instance_key(db)
        report = audit_pack(store, key, args.outdir)
        print(f"[{'✓' if report['valid'] else '✗'}] verifier report: "
              f"valid={report['valid']}, {report['nb_events_checked']} events, "
              f"{report['anchors_checked']} witness tokens checked "
              f"({report['anchors_pinned']} pinned)")
        print(f"[✓] pack written to {args.outdir}/ — export.json, "
              f"verifier_report.json, ANNEXE-IV-2f.md")
        return 0 if report["valid"] else 1

    if args.command == "seal-trajectory":
        import sys

        from noirebox import locate, transcripts
        from noirebox.chain import KeyPair, load_instance_key, verify_chain
        from noirebox.store import EventStore

        db = args.db or locate.resolve_existing_journal()

        if args.rollout:
            from noirebox.trajseal import seal_rollout

            for line in seal_rollout(args.rollout, db, interval_min=args.interval):
                print(f"[noirebox] trajectory sealed: {line}", file=sys.stderr)
            return 0

        if not args.file:
            print("[✗] nothing to seal: give a file, or --rollout <dir>")
            return 1
        try:
            origin = None if args.format == "auto" else args.format
            summary = transcripts.read_summary(args.file, origin=origin)
            payload = transcripts.transcript_payload(summary)
        except ValueError as exc:
            print(f"[✗] {exc}")
            return 1
        store = EventStore(db)
        key = load_instance_key(db)
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

    if args.command == "fleet-anchor":
        from noirebox import locate
        from noirebox.chain import KeyPair, load_instance_key
        from noirebox.fleet import fleet_anchor
        from noirebox.store import EventStore

        hub = args.db or locate.resolve_existing_journal()
        store = EventStore(hub)
        key = KeyPair.load_or_create(hub + ".key")
        try:
            result = fleet_anchor(args.journals, store, key,
                                  require_witness=not args.allow_local)
        except (ValueError, RuntimeError) as exc:
            print(f"[✗] {exc}")
            return 1
        print(f"[✓] fleet_anchor sealed in {hub} (seq {result['event_seq']}) — "
              f"root {result['root'][:16]}… over {len(result['members'])} journal(s)")
        for w in result["warnings"]:
            print(f"    [!] {w}")
        for name in result["members"]:
            print(f"    member: {name}")
        return 0

    if args.command == "fleet-verify":
        from noirebox import locate
        from noirebox.fleet import fleet_verify
        from noirebox.store import EventStore

        hub = args.db or locate.resolve_existing_journal()
        result = fleet_verify(args.journal, EventStore(hub))
        if result["covered"] and result["inclusion_ok"]:
            print(f"[✓] COVERED — head {result['head'][:16]}… recomputes to the "
                  f"sealed root {result['root'][:16]}…")
            return 0
        print(f"[✗] NOT COVERED — {result.get('warning', 'inclusion failed')}")
        if result.get("head"):
            print(f"    head: {result['head'][:16]}…  sealed root: "
                  f"{(result.get('root') or '—')[:16]}…")
        return 1

    if args.command == "fleet-status":
        import json as _json

        from noirebox import locate
        from noirebox.fleet import fleet_status
        from noirebox.store import EventStore

        hub = args.db or locate.resolve_existing_journal()
        report = fleet_status(EventStore(hub), args.members)
        if args.json:
            print(_json.dumps(report, ensure_ascii=False, indent=2))
        else:
            for m in report["members"]:
                state = ("COVERED" if m["covered"] and m["inclusion_ok"]
                         else "NOT COVERED")
                extra = f" — {m['warning']}" if m.get("warning") else ""
                print(f"  [{state}] {m['journal']}{extra}")
            print(f"[{'✓' if report['ok'] else '✗'}] fleet status over "
                  f"{len(report['members'])} member(s) — hub {hub}")
        return 0 if report["ok"] else 1

    if args.command == "fleet-watch":
        import json as _json
        import threading

        from noirebox import locate
        from noirebox.chain import KeyPair
        from noirebox.fleet import fleet_watch
        from noirebox.store import EventStore

        hub = args.db or locate.resolve_existing_journal()
        key = KeyPair.load_or_create(hub + ".key") if args.reanchor else None

        def notify(alarm: dict) -> None:
            if args.webhook:
                import httpx

                from urllib.parse import urlparse

                parsed = urlparse(args.webhook)
                if parsed.scheme not in ("http", "https"):
                    raise ValueError(
                        f"webhook must be a plain http(s) URL: {args.webhook[:80]}")
                httpx.post(args.webhook, json=alarm, timeout=10,
                           follow_redirects=False)
            else:
                print(f"[noirebox] ALARM {alarm['at']}: "
                      f"{[m['journal'] for m in alarm['members'] if not (m['covered'] and m['inclusion_ok'])]}",
                      flush=True)

        stop = threading.Event()
        try:
            fleet_watch(EventStore(hub), args.members, stop=stop,
                        interval_seconds=args.interval,
                        reanchor=args.reanchor, key=key, notify=notify)
        except KeyboardInterrupt:
            stop.set()
            print("[noirebox] fleet-watch stopped")
        return 0

    if args.command == "replay":
        from noirebox import locate
        from noirebox.chain import KeyPair
        from noirebox.replay import replay, render
        from noirebox.store import EventStore

        db = args.db or locate.resolve_existing_journal()
        store = EventStore(db)
        key = KeyPair.load_or_create(db + ".key")
        print(render(replay(store.all(), key, args.subject)))
        return 0

    if args.command == "export-siem":
        from noirebox import locate
        from noirebox.siem import to_cef, to_otlp
        from noirebox.store import EventStore

        db = args.db or locate.resolve_existing_journal()
        events = [e for e in EventStore(db).all() if e["seq"] > args.since]
        if args.format == "cef":
            print(to_cef(events))
        else:
            import json as _json

            print(_json.dumps(to_otlp(events), ensure_ascii=False))
        return 0

    if args.command == "hook":
        import sys

        from noirebox.hookcli import run as hook_run

        return hook_run(args.hook_event, stdin=sys.stdin)

    if args.command == "seal":
        import json as _json

        from noirebox import locate
        from noirebox.chain import KeyPair, load_instance_key, load_instance_key, verify_chain
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
        key = load_instance_key(db)
        event = store.append(args.type, payload, key)
        print(f"[✓] sealed {args.type}: seq={event.seq} hash={event.event_hash}")
        return 0

    if args.command == "verify":
        from noirebox import locate
        from noirebox.chain import KeyPair, load_instance_key, load_instance_key, verify_chain
        from noirebox.store import EventStore

        db = args.db or locate.resolve_journal()
        import os
        if not os.path.exists(db):
            print(f"[✗] no journal at {db}")
            return 1
        store = EventStore(db)
        key = load_instance_key(db)
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
