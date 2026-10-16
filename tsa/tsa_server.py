#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MATERIAL = ROOT / "tsa" / "material"


class TSAHandler(BaseHTTPRequestHandler):
    material: Path

    def do_POST(self) -> None:
        if self.path != "/tsa":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", 0))
        query = self.rfile.read(length)
        with tempfile.TemporaryDirectory() as tmp:
            q = Path(tmp) / "req.tsq"
            r = Path(tmp) / "resp.tsr"
            q.write_bytes(query)
            proc = subprocess.run(
                ["openssl", "ts", "-reply", "-queryfile", str(q),
                 "-config", str(self.material / "tsa.conf"), "-out", str(r)],
                capture_output=True,
            )
            if proc.returncode != 0:
                self.send_error(400, "Invalid TimeStampReq")
                return
            body = r.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path != "/cert":
            self.send_error(404)
            return

        body = (self.material / "tsa_bundle.pem").read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/x-pem-file")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description="NoireBox local TSA (RFC 3161)")
    parser.add_argument("--material", default=str(DEFAULT_MATERIAL))
    parser.add_argument("--port", type=int, default=3318)
    args = parser.parse_args()
    material = Path(args.material).resolve()
    if not (material / "tsa.conf").exists():
        parser.error(f"no tsa.conf in {material} — run tsa/gen_tsa.sh first")

    handler = type("BoundTSAHandler", (TSAHandler,), {"material": material})
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler)
    print(f"[✓] Local TSA: http://127.0.0.1:{args.port}/tsa  (cert: /cert) — Ctrl-C to stop")
    server.serve_forever()


if __name__ == "__main__":
    main()
