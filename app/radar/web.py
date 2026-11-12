"""HTTP server: the static page plus /data/<name>.json served from PostgreSQL snapshots."""
import contextlib
import gzip
import logging
import threading
import time
from datetime import datetime
from email.utils import formatdate

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from psycopg_pool import ConnectionPool

from . import collect, config, db, rss, summary

log = logging.getLogger("radar.web")
ALLOWED = set(collect.SNAPSHOT_NAMES)
REFRESH_SEC = 10

pool = ConnectionPool(config.DATABASE_URL, min_size=1, max_size=4, open=False, kwargs={"autocommit": True})


class SnapshotCache:
    def __init__(self):
        self.lock = threading.Lock()
        self.entries = {}       # name -> (etag, raw, gz, updated_at)
        self.checked = 0.0

    def _refresh(self):
        with pool.connection() as c:
            rows = c.execute("SELECT name, etag FROM snapshots").fetchall()
            current = {n: e for n, e in rows}
            stale = [n for n, e in current.items() if n in ALLOWED and (n not in self.entries or self.entries[n][0] != e)]
            for n in stale:
                r = c.execute("SELECT body, etag, updated_at FROM snapshots WHERE name = %s", (n,)).fetchone()
                if r:
                    raw = r[0].encode("utf-8")
                    self.entries[n] = (r[1], raw, gzip.compress(raw, 6), r[2])
            for n in list(self.entries):
                if n not in current:
                    del self.entries[n]
        self.checked = time.monotonic()

    def get(self, name):
        with self.lock:
            if time.monotonic() - self.checked > REFRESH_SEC:
                self._refresh()
            return self.entries.get(name)


cache = SnapshotCache()


@contextlib.asynccontextmanager
async def lifespan(_app):
    db.init_schema()
    pool.open(wait=True, timeout=60)
    yield
    pool.close()


app = FastAPI(title="KCM", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)


@app.middleware("http")
async def headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    if request.url.path in ("/", "/index.html") or request.url.path.endswith((".js", ".css")):
        resp.headers.setdefault("Cache-Control", "no-cache")
    return resp


@app.get("/data/{name}.json")
def data(name: str, request: Request):
    if name not in ALLOWED:
        return JSONResponse({"error": "not found"}, status_code=404)
    e = cache.get(name)
    if not e:
        return JSONResponse({"error": "not ready", "hint": "첫 수집이 끝나면 데이터가 생깁니다"}, status_code=404)
    etag, raw, gz, updated = e
    tag = f'"{etag}"'
    base = {"ETag": tag, "Cache-Control": "no-cache", "Last-Modified": formatdate(updated.timestamp(), usegmt=True)}
    if request.headers.get("if-none-match") == tag:
        return Response(status_code=304, headers=base)
    if "gzip" in (request.headers.get("accept-encoding") or ""):
        return Response(gz, media_type="application/json; charset=utf-8", headers={**base, "Content-Encoding": "gzip", "Vary": "Accept-Encoding"})
    return Response(raw, media_type="application/json; charset=utf-8", headers={**base, "Vary": "Accept-Encoding"})


@app.get("/healthz")
def healthz():
    try:
        with pool.connection(timeout=5) as c:
            c.execute("SELECT 1")
        return {"ok": True}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)[:200]}, status_code=503)


@app.get("/api/status")
def status():
    with pool.connection() as c:
        runs = c.execute("""SELECT id, kind, status, started_at, finished_at, error, summary
                            FROM runs ORDER BY id DESC LIMIT 10""").fetchall()
        tr = dict(c.execute("SELECT status, count(*) FROM translations GROUP BY status").fetchall())
        eng = dict(c.execute("SELECT engine, count(*) FROM translations WHERE ko IS NOT NULL GROUP BY engine").fetchall())
        snaps = c.execute("SELECT name, length(body), updated_at FROM snapshots ORDER BY name").fetchall()
        feeds = c.execute("SELECT feed, count(*), max(published), max(first_seen) FROM rss_items GROUP BY feed ORDER BY feed").fetchall()
    return {
        "translations": {"byStatus": tr, "translatedByEngine": eng},
        "rss": [{"feed": f, "items": n, "latest": p.isoformat() if p else None, "lastNew": s.isoformat() if s else None} for f, n, p, s in feeds],
        "snapshots": [{"name": n, "bytes": b, "updatedAt": u.isoformat()} for n, b, u in snaps],
        "runs": [{"id": r[0], "kind": r[1], "status": r[2], "startedAt": r[3].isoformat() if r[3] else None,
                  "finishedAt": r[4].isoformat() if r[4] else None, "error": (r[5] or "")[:500] or None,
                  "summary": r[6]} for r in runs],
    }


@app.get("/api/rss")
def rss_history(feed: str | None = None, before: str | None = None, q: str | None = None, limit: int = 50):
    """Archive of every RSS entry ever seen, newest first. before = ISO timestamp (the 'at' of the last row you have)."""
    limit = max(1, min(limit, 200))
    q = (q or "").strip()[:100] or None
    b = None
    if before:
        try:
            b = datetime.fromisoformat(before.replace("Z", "+00:00"))
        except ValueError:
            return JSONResponse({"error": "before는 ISO 시각이어야 합니다"}, status_code=400)
    with pool.connection() as c:
        with c.cursor() as cur:
            items = rss.history(cur, feed=feed, before=b, q=q, limit=limit + 1)
    return {"items": items[:limit], "more": len(items) > limit}


@app.get("/api/summaries")
def summaries(before: str | None = None, limit: int = 20):
    """EXAONE briefing history, newest first. before = the 'at' of the last row you have."""
    limit = max(1, min(limit, 100))
    b = None
    if before:
        try:
            b = datetime.fromisoformat(before.replace("Z", "+00:00"))
        except ValueError:
            return JSONResponse({"error": "before는 ISO 시각이어야 합니다"}, status_code=400)
    with pool.connection() as c:
        with c.cursor() as cur:
            items = summary.history(cur, before=b, limit=limit + 1)
    return {"items": items[:limit], "more": len(items) > limit, "schedule": config.SUMMARY_CRON}


app.mount("/", StaticFiles(directory=config.STATIC_DIR, html=True), name="static")


def main():
    import uvicorn
    uvicorn.run(app, host=config.WEB_HOST, port=config.WEB_PORT, proxy_headers=True, forwarded_allow_ips="*",
                log_level="info", access_log=False)
