#!/usr/bin/env python3
"""Reproducible benchmarks for the two numbers that matter in practice.

Run with `make bench`. Absolute values vary with hardware and load —
run it on your own machine and compare orders of magnitude, not decimals.
"""
from __future__ import annotations

import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "verifier"))

from noirebox.attestation import build_attestation
from noirebox.chain import KeyPair
from noirebox.store import EventStore

import verifier  # noqa: E402  (verifier/verifier.py, resolved via sys.path)


def bench_sealing() -> float:
    """Average ms to seal one event (hash + Ed25519 signature + SQLite commit)."""
    with tempfile.TemporaryDirectory() as tmp:
        store = EventStore(f"{tmp}/bench.db")
        key = KeyPair.load_or_create(f"{tmp}/bench.key")
        for i in range(50):  # warm-up: imports, sqlite pages, crypto init
            store.append("bench_warmup", {"i": i}, key)
        n = 2000
        t0 = time.perf_counter()
        for i in range(n):
            store.append("bench", {"i": i, "note": "benchmark payload"}, key)
        return (time.perf_counter() - t0) * 1000 / n


def bench_verification() -> float:
    """Median seconds for a full verify_export() of a fresh 100-event journal."""
    with tempfile.TemporaryDirectory() as tmp:
        store = EventStore(f"{tmp}/bench.db")
        key = KeyPair.load_or_create(f"{tmp}/bench.key")
        for i in range(100):
            store.append("bench", {"i": i}, key)
        export = {
            "format_version": 1,
            "service": "noirebox",
            "public_key": key.public_hex(),
            "events": store.all(),
            "attestation": build_attestation(store, key),
        }
        runs = []
        for _ in range(3):  # warm-up
            verifier.verify_export(json.loads(json.dumps(export)))
        for _ in range(7):
            t0 = time.perf_counter()
            report = verifier.verify_export(json.loads(json.dumps(export)))
            runs.append(time.perf_counter() - t0)
        assert report["valid"], "the benchmark journal must verify INTACT"
        return statistics.median(runs)


def main() -> None:
    ms_per_event = bench_sealing()
    print("[1] Sealing 2,000 events (hash + Ed25519 signature + SQLite commit)…")
    print(f"    {ms_per_event:.2f} ms/event")

    seconds = bench_verification()
    print("[2] Verifying a fresh 100-event export (median of 7 runs)…")
    print(f"    {seconds * 1000:.0f} ms per full verification")
    print("    (no TSA anchor in the benchmark journal — each real anchor")
    print("     adds one `openssl ts -verify` to the total)")
    print()
    print("    Absolute values vary with hardware and load — run it on")
    print("    your own machine and compare orders of magnitude.")


if __name__ == "__main__":
    main()
