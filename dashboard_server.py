"""Loopback-only dashboard for Wazuh and synthetic alert review."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import sqlite3
from threading import Lock
from urllib.parse import parse_qs, urlsplit

from cli import FIXTURE
from services import Reputation, ServiceError, ollama_draft, wazuh_docker_alerts
from triage import VERDICTS, baseline, evidence, load_cases, normalize

ROOT = Path(__file__).resolve().parent
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/dashboard.css": ("dashboard.css", "text/css; charset=utf-8"),
    "/dashboard.js": ("dashboard.js", "text/javascript; charset=utf-8"),
}
SOURCES = {"demo", "wazuh"}
MODEL = "qwen3:1.7b"


class ReviewStore:
    def __init__(self, directory):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = directory / "dashboard.sqlite3"
        # Create a private file before SQLite opens it.
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS reviews (
                source TEXT, alert_id TEXT, verdict TEXT NOT NULL, draft_verdict TEXT NOT NULL,
                engine TEXT NOT NULL, reviewed_at TEXT NOT NULL, PRIMARY KEY (source, alert_id))""")

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def for_source(self, source):
        with self.connect() as db:
            return {row["alert_id"]: dict(row) for row in db.execute(
                "SELECT alert_id, verdict, draft_verdict, engine, reviewed_at FROM reviews WHERE source = ?", (source,)
            )}

    def approve(self, source, alert_id, verdict, draft, engine):
        when = datetime.now(timezone.utc).isoformat()
        with self.connect() as db:
            db.execute("INSERT INTO reviews VALUES (?, ?, ?, ?, ?, ?)",
                       (source, alert_id, verdict, draft["verdict"], engine, when))


class Dashboard(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port, review_dir, docker_context, container):
        self.token = secrets.token_urlsafe(32)
        self.store = ReviewStore(review_dir)
        self.docker_context = docker_context
        self.container = container
        demo = [(normalize(case["alert"]), case.get("reputation", [])) for case in load_cases(FIXTURE)]
        self.records = {"demo": {alert.alert_id: (alert, rep) for alert, rep in demo}}
        self.drafts = {}
        self.reputation = None
        self.draft_lock = Lock()
        super().__init__(("127.0.0.1", port), Handler)
        self.origin = f"http://127.0.0.1:{self.server_port}"

    def load_wazuh(self):
        alerts = list(wazuh_docker_alerts(self.docker_context, self.container, 50))
        self.records["wazuh"] = {alert.alert_id: (alert, []) for alert in reversed(alerts)}

    def resolve(self, source, alert_id):
        try:
            return self.records[source][alert_id]
        except KeyError:
            raise ValueError("Alert not in the loaded queue. Refresh and try again.") from None

    def detail(self, source, alert_id):
        alert, recorded = self.resolve(source, alert_id)
        facts = evidence(alert, recorded)
        cached = self.drafts.get((source, alert_id))
        if cached:
            facts, draft, engine = cached
        else:
            draft, engine = baseline(facts), "baseline"
        return {"facts": facts, "draft": draft, "engine": engine,
                "ips": alert.ips, "hashes": alert.hashes}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        # Review identifiers and provider errors stay out of HTTP access logs.
        pass

    def reply(self, status, body, content_type="application/json; charset=utf-8"):
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(body)

    def allowed_host(self):
        return self.headers.get("Host") == urlsplit(self.server.origin).netloc

    def do_GET(self):
        if not self.allowed_host():
            return self.reply(403, {"error": "Use the printed loopback URL."})
        url = urlsplit(self.path)
        if url.path in ASSETS:
            name, content = ASSETS[url.path]
            return self.reply(200, (ROOT / "dashboard" / name).read_bytes(), content)
        if url.path == "/api/config":
            return self.reply(200, {"csrf": self.server.token, "model": MODEL})
        if url.path == "/api/benchmarks":
            results = [json.loads((ROOT / "results" / name).read_text()) for name in (
                "baseline-benchmark.json", "qwen3-1.7b-benchmark.json")]
            return self.reply(200, results)
        args = parse_qs(url.query)
        source = args.get("source", ["demo"])[0]
        if source not in SOURCES:
            return self.reply(400, {"error": "Unknown alert source."})
        try:
            if url.path == "/api/queue":
                if source == "wazuh" and (source not in self.server.records or args.get("refresh") == ["1"]):
                    self.server.load_wazuh()
                reviews = self.server.store.for_source(source)
                rows = [{"id": alert.alert_id, "category": alert.category, "severity": alert.severity,
                         "indicators": len(alert.ips) + len(alert.hashes), "review": reviews.get(alert.alert_id)}
                        for alert, _ in self.server.records[source].values()]
                return self.reply(200, rows)
            if url.path == "/api/alert":
                return self.reply(200, self.server.detail(source, args.get("id", [""])[0]))
        except ValueError as exc:
            return self.reply(422, {"error": str(exc)})
        return self.reply(404, {"error": "Unknown route."})

    def do_POST(self):
        if (not self.allowed_host() or self.headers.get("Origin") != self.server.origin
                or not secrets.compare_digest(self.headers.get("X-Triage-Token", ""), self.server.token)):
            return self.reply(403, {"error": "Invalid local review session. Reload the page."})
        if self.headers.get_content_type() != "application/json":
            return self.reply(415, {"error": "Expected JSON."})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 4096:
                raise ValueError("Invalid request size.")
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError("Invalid request.")
            source, alert_id = body.get("source"), body.get("id")
            if not isinstance(source, str) or source not in SOURCES or not isinstance(alert_id, str):
                raise ValueError("Invalid alert selection.")
            alert, recorded = self.server.resolve(source, alert_id)
            if self.path == "/api/draft":
                if type(body.get("enrich", False)) is not bool:
                    raise ValueError("Invalid enrichment selection.")
                if not self.server.draft_lock.acquire(blocking=False):
                    return self.reply(409, {"error": "A local draft is already running. Try again shortly."})
                try:
                    if source == "wazuh" and body.get("enrich"):
                        if self.server.reputation is None:
                            self.server.reputation = Reputation()
                        recorded = self.server.reputation.enrich(alert)
                    facts = evidence(alert, recorded)
                    draft = ollama_draft(facts, MODEL)
                    self.server.drafts[(source, alert_id)] = (facts, draft, MODEL)
                finally:
                    self.server.draft_lock.release()
                return self.reply(200, self.server.detail(source, alert_id))
            if self.path == "/api/review":
                verdict = body.get("verdict")
                if verdict not in VERDICTS or body.get("approve") is not True:
                    raise ValueError("Select a verdict and explicitly approve it.")
                current = self.server.detail(source, alert_id)
                self.server.store.approve(source, alert_id, verdict, current["draft"], current["engine"])
                return self.reply(201, self.server.store.for_source(source)[alert_id])
        except sqlite3.IntegrityError:
            return self.reply(409, {"error": "This alert already has an approved verdict. Refresh the queue."})
        except (ValueError, ServiceError) as exc:
            return self.reply(422, {"error": str(exc)})
        return self.reply(404, {"error": "Unknown route."})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--review-dir", type=Path, default=ROOT / "reviews")
    parser.add_argument("--docker-context", default="colima-wazuh")
    parser.add_argument("--wazuh-container", default="single-node-wazuh.manager-1")
    args = parser.parse_args()
    with Dashboard(args.port, args.review_dir, args.docker_context, args.wazuh_container) as server:
        print(f"Local: {server.origin}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
