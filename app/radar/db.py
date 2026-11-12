"""PostgreSQL schema and small helpers (psycopg 3)."""
import contextlib
import hashlib
import json
import logging
import time

import psycopg
from psycopg.types.json import Jsonb

from . import config

log = logging.getLogger("radar.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS kv_state (
    key         text PRIMARY KEY,
    value       jsonb NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now()
);
-- KEV enrichment cache: one row per KEV CVE, positional array (see collect.KCACHE_LEN)
CREATE TABLE IF NOT EXISTS kev_cache (
    cve_id  text PRIMARY KEY,
    row     jsonb NOT NULL
);
-- stored CVE items (90 days, CVSS >= 9.0, or major vendor >= 7.0)
CREATE TABLE IF NOT EXISTS cve_store (
    cve_id     text PRIMARY KEY,
    published  date NOT NULL,
    score      real NOT NULL,
    vendor     text NOT NULL DEFAULT '',
    major      text NOT NULL DEFAULT '',
    item       jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS cve_store_published_idx ON cve_store (published DESC);
CREATE TABLE IF NOT EXISTS kisa_notices (
    ntt   text PRIMARY KEY,
    date  date NOT NULL,
    item  jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS change_days (
    day   date PRIMARY KEY,
    item  jsonb NOT NULL
);
-- Korean text per CVE / KEV / GHSA id. engine: libretranslate | manual | seed
CREATE TABLE IF NOT EXISTS translations (
    key         text PRIMARY KEY,
    src         text NOT NULL DEFAULT '',
    src_hash    text NOT NULL DEFAULT '',
    ko          text,
    engine      text NOT NULL DEFAULT 'libretranslate',
    status      text NOT NULL DEFAULT 'pending',   -- pending | done | failed
    priority    integer NOT NULL DEFAULT 9,
    attempts    integer NOT NULL DEFAULT 0,
    error       text,
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS translations_pending_idx ON translations (priority, key) WHERE status = 'pending';
-- JSON documents served to the browser at /data/<name>.json
CREATE TABLE IF NOT EXISTS snapshots (
    name        text PRIMARY KEY,
    body        text NOT NULL,
    etag        text NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS runs (
    id           bigserial PRIMARY KEY,
    kind         text NOT NULL,
    started_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz,
    status       text NOT NULL DEFAULT 'running',
    summary      jsonb,
    error        text
);
-- RSS/Atom entries (KNVD 등). Kept forever: feeds only show their latest ~10 entries.
CREATE TABLE IF NOT EXISTS rss_items (
    feed        text NOT NULL,
    guid        text NOT NULL,
    title       text NOT NULL,
    link        text NOT NULL DEFAULT '',
    body        text NOT NULL DEFAULT '',
    category    text NOT NULL DEFAULT '',
    published   timestamptz NOT NULL,
    cves        text[] NOT NULL DEFAULT '{}',
    lang        text NOT NULL DEFAULT 'ko',          -- ko | en
    extra       jsonb NOT NULL DEFAULT '{}',          -- cvss, severity ...
    first_seen  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (feed, guid)
);
CREATE INDEX IF NOT EXISTS rss_items_pub_idx ON rss_items (feed, published DESC);
CREATE INDEX IF NOT EXISTS rss_items_cves_idx ON rss_items USING gin (cves);
-- Every EXAONE briefing (the "summary" snapshot only holds the latest)
CREATE TABLE IF NOT EXISTS summary_history (
    id            bigserial PRIMARY KEY,
    generated_at  timestamptz NOT NULL DEFAULT now(),
    day           date NOT NULL,
    slot          text NOT NULL DEFAULT '',        -- "07:00" etc. (TZ), '' for manual runs
    doc           jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS summary_history_at_idx ON summary_history (generated_at DESC);
-- Everything the collector has ever stored. cve_store / kisa_notices keep 90 days; these are never pruned.
CREATE TABLE IF NOT EXISTS cve_history (
    cve_id      text PRIMARY KEY,
    published   date NOT NULL,
    score       real NOT NULL,
    vendor      text NOT NULL DEFAULT '',
    item        jsonb NOT NULL,
    first_seen  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS cve_history_published_idx ON cve_history (published DESC);
CREATE TABLE IF NOT EXISTS kisa_history (
    ntt         text PRIMARY KEY,
    date        date NOT NULL,
    item        jsonb NOT NULL,
    first_seen  timestamptz NOT NULL DEFAULT now()
);
"""

LOCK_COLLECT = 724_001
LOCK_TRANSLATE = 724_002
LOCK_RSS = 724_003


def connect(autocommit=False, retries=30):
    last = None
    for i in range(retries):
        try:
            return psycopg.connect(config.DATABASE_URL, autocommit=autocommit)
        except psycopg.OperationalError as e:
            last = e
            log.warning("DB 연결 대기 중 (%s/%s): %s", i + 1, retries, str(e).strip()[:120])
            time.sleep(2)
    raise last


def init_schema():
    with connect(autocommit=True) as c:
        c.execute(SCHEMA)


def dumps(body):
    return json.dumps(body, ensure_ascii=False, separators=(",", ":"))


def put_snapshot(cur, name, body):
    text = body if isinstance(body, str) else dumps(body)
    etag = hashlib.sha1(text.encode("utf-8")).hexdigest()[:20]
    cur.execute(
        """INSERT INTO snapshots (name, body, etag, updated_at) VALUES (%s, %s, %s, now())
           ON CONFLICT (name) DO UPDATE SET body = EXCLUDED.body, etag = EXCLUDED.etag, updated_at = now()
           WHERE snapshots.etag <> EXCLUDED.etag""",
        (name, text, etag),
    )
    return len(text.encode("utf-8"))


def get_snapshot(cur, name, default=None):
    cur.execute("SELECT body FROM snapshots WHERE name = %s", (name,))
    r = cur.fetchone()
    if not r:
        return default
    try:
        return json.loads(r[0])
    except Exception:
        return default


def kv_get(cur, key, default=None):
    cur.execute("SELECT value FROM kv_state WHERE key = %s", (key,))
    r = cur.fetchone()
    return r[0] if r else default


def kv_set(cur, key, value):
    cur.execute(
        """INSERT INTO kv_state (key, value, updated_at) VALUES (%s, %s, now())
           ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()""",
        (key, Jsonb(value)),
    )


@contextlib.contextmanager
def advisory_lock(conn, key):
    """Session-level try-lock. Yields True when acquired."""
    with conn.cursor() as cur:
        cur.execute("SELECT pg_try_advisory_lock(%s)", (key,))
        got = cur.fetchone()[0]
    if not conn.autocommit:
        conn.commit()
    try:
        yield got
    finally:
        if got:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_unlock(%s)", (key,))
            if not conn.autocommit:
                conn.commit()


def run_start(kind):
    with connect(autocommit=True) as c:
        return c.execute("INSERT INTO runs (kind) VALUES (%s) RETURNING id", (kind,)).fetchone()[0]


def run_finish(run_id, status, summary=None, error=None):
    with connect(autocommit=True) as c:
        c.execute(
            "UPDATE runs SET finished_at = now(), status = %s, summary = %s, error = %s WHERE id = %s",
            (status, Jsonb(summary) if summary is not None else None, error, run_id),
        )
        # keep the last 500 runs
        c.execute("DELETE FROM runs WHERE id < (SELECT COALESCE(MAX(id), 0) - 500 FROM runs)")
