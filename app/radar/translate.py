"""Korean text via LibreTranslate.

The collector queues (key, english text) pairs in the translations table; run_pending() works through the queue
in priority order and the result is published as the "ko" snapshot ({"items": {key: {"t": 한국어, "at": date}}}),
which the page already reads. Rows with engine 'manual' or 'seed' are never overwritten by machine translation.
"""
import concurrent.futures as cf
import datetime as dt
import hashlib
import json
import logging
import re
import urllib.error
import urllib.request

from . import config, db

log = logging.getLogger("radar.translate")

KERNEL_RE = re.compile(r"^\s*In the Linux kernel, the following vulnerability has been resolved:\s*", re.I)
HANGUL_RE = re.compile(r"[가-힣]")
PROTECTED_ENGINES = ("manual", "seed")
MAX_ATTEMPTS = 3


def prep(text):
    """English source text as the page would show it, trimmed for translation."""
    s = str(text or "")
    if KERNEL_RE.match(s):
        s = KERNEL_RE.sub("", s)
        lines = [l.strip() for l in s.split("\n") if l.strip()]
        s = lines[0] if lines else ""
    s = " ".join(s.split())
    lim = config.TRANSLATE_MAX_CHARS
    if len(s) > lim:
        cut = s[:lim]
        dot = max(cut.rfind(". "), cut.rfind("; "))
        s = cut[:dot + 1] if dot > lim * 0.5 else cut.rstrip() + "…"
    return s


def h(s):
    return hashlib.sha1(s.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- queue maintenance (called inside the collect transaction)
def sync_queue(cur, cands, keep_extra=()):
    """cands: iterable of (key, english, priority). Rows not in cands ∪ keep_extra are pruned."""
    want = {}
    for key, text, pr in cands:
        if not key:
            continue
        if key in want:
            if pr < want[key][1]:
                want[key] = (want[key][0], pr)
            continue
        want[key] = (prep(text), pr)
    cur.execute("SELECT key, src_hash, engine, status, priority FROM translations")
    have = {r[0]: r[1:] for r in cur.fetchall()}
    ins, upd_src, upd_pr, upd_keep = [], [], [], []
    for key, (src, pr) in want.items():
        if not src:
            continue
        sh = h(src)
        cur_row = have.get(key)
        if cur_row is None:
            ins.append((key, src, sh, pr))
        else:
            src_hash, engine, status, old_pr = cur_row
            if engine in PROTECTED_ENGINES:
                # keep the hand-written text; remember the source so it can be handed back to MT later
                if src_hash != sh:
                    upd_keep.append((src, sh, pr, key))
                elif old_pr != pr:
                    upd_pr.append((pr, key))
            elif src_hash != sh:
                upd_src.append((src, sh, pr, key))
            elif old_pr != pr:
                upd_pr.append((pr, key))
    if ins:
        cur.executemany("INSERT INTO translations (key, src, src_hash, priority) VALUES (%s, %s, %s, %s) ON CONFLICT (key) DO NOTHING", ins)
    if upd_src:
        cur.executemany("""UPDATE translations SET src = %s, src_hash = %s, priority = %s, status = 'pending',
                           attempts = 0, error = NULL, engine = 'libretranslate', updated_at = now() WHERE key = %s""", upd_src)
    if upd_keep:
        cur.executemany("UPDATE translations SET src = %s, src_hash = %s, priority = %s WHERE key = %s", upd_keep)
    if upd_pr:
        cur.executemany("UPDATE translations SET priority = %s WHERE key = %s", upd_pr)
    keep = set(want) | set(keep_extra)
    cur.execute("CREATE TEMP TABLE IF NOT EXISTS _keep_keys (key text PRIMARY KEY) ON COMMIT DROP")
    cur.execute("TRUNCATE _keep_keys")
    with cur.copy("COPY _keep_keys (key) FROM STDIN") as cp:
        for k in keep:
            cp.write_row((k,))
    # rss:* rows belong to rss.py and are kept as long as the entry (forever)
    cur.execute("""DELETE FROM translations t WHERE t.key NOT LIKE 'rss:%%'
                   AND NOT EXISTS (SELECT 1 FROM _keep_keys k WHERE k.key = t.key)""")
    pruned = cur.rowcount
    # give failed rows another chance once a day (LibreTranslate may have been restarting)
    cur.execute("""UPDATE translations SET status = 'pending', attempts = 0
                   WHERE status = 'failed' AND src <> '' AND updated_at < now() - interval '1 day'""")
    retried = cur.rowcount
    st = counts(cur)
    st.update({"queuedNew": len(ins), "sourceChanged": len(upd_src), "pruned": pruned, "retriedFailed": retried})
    return st


def counts(cur):
    cur.execute("SELECT status, count(*) FROM translations GROUP BY status")
    out = {"pending": 0, "done": 0, "failed": 0}
    for s, n in cur.fetchall():
        out[s] = n
    return out


def build_ko_snapshot(cur):
    cur.execute("SELECT key, ko, updated_at, engine FROM translations WHERE ko IS NOT NULL AND ko <> '' ORDER BY key")
    items = {}
    for key, ko, at, engine in cur.fetchall():
        items[key] = {"t": ko, "at": at.date().isoformat(), "e": engine}
    return db.put_snapshot(cur, "ko", {"items": items})


# ---------------------------------------------------------------- LibreTranslate client
def _post(path, payload, timeout):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(config.LT_URL + path, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def lt_ready():
    """True when LibreTranslate answers and offers source -> target."""
    try:
        with urllib.request.urlopen(config.LT_URL + "/languages", timeout=15) as r:
            langs = json.loads(r.read())
    except Exception as e:
        log.info("LibreTranslate 응답 없음 (%s) — 모델 다운로드 중이거나 아직 시작 전입니다", str(e)[:120])
        return False
    for l in langs or []:
        if l.get("code") == config.LT_SOURCE and config.LT_TARGET in (l.get("targets") or []):
            return True
    log.warning("LibreTranslate에 %s→%s 모델이 없습니다. LT_LOAD_ONLY에 %s,%s가 들어 있는지 확인하세요",
                config.LT_SOURCE, config.LT_TARGET, config.LT_SOURCE, config.LT_TARGET)
    return False


def lt_translate(texts):
    payload = {"q": texts, "source": config.LT_SOURCE, "target": config.LT_TARGET, "format": "text"}
    if config.LT_API_KEY:
        payload["api_key"] = config.LT_API_KEY
    res = _post("/translate", payload, config.LT_TIMEOUT)
    out = res.get("translatedText")
    if isinstance(out, str):
        out = [out]
    if not isinstance(out, list) or len(out) != len(texts):
        raise RuntimeError("unexpected LibreTranslate response: " + str(res)[:200])
    return out


def post(ko):
    t = " ".join(str(ko or "").split())
    return t[:600]


def _translate_batch(rows):
    """rows: [(key, src)] -> [(key, ko|None, error|None)]"""
    texts = [r[1] for r in rows]
    try:
        outs = lt_translate(texts)
        return [(k, post(o), None) for (k, _), o in zip(rows, outs)]
    except Exception as e:
        if len(rows) == 1:
            msg = str(e)
            if isinstance(e, urllib.error.HTTPError):
                try:
                    msg = f"HTTP {e.code}: {e.read()[:200]!r}"
                except Exception:
                    pass
            return [(rows[0][0], None, msg[:300])]
        # one bad item should not sink the batch
        out = []
        for r in rows:
            out.extend(_translate_batch([r]))
        return out


def run_pending(limit=None):
    """Translate up to `limit` pending rows. Returns stats dict."""
    limit = limit or config.TRANSLATE_CHUNK
    conn = db.connect()
    try:
        with db.advisory_lock(conn, db.LOCK_TRANSLATE) as got:
            if not got:
                return {"skipped": "busy"}
            with conn.cursor() as cur:
                pend = counts(cur)["pending"]
            conn.commit()
            if not pend:
                return {"done": 0, "failed": 0, "remaining": 0}
            if not lt_ready():
                return {"done": 0, "failed": 0, "remaining": pend, "skipped": "libretranslate not ready"}
            with conn.cursor() as cur:
                cur.execute("SELECT key, src FROM translations WHERE status = 'pending' ORDER BY priority, key LIMIT %s", (limit,))
                rows = cur.fetchall()
            conn.commit()
            batches = [rows[i:i + config.LT_BATCH] for i in range(0, len(rows), config.LT_BATCH)]
            ok = bad = 0
            today = dt.date.today()
            with cf.ThreadPoolExecutor(config.LT_CONCURRENCY) as ex:
                for res in ex.map(_translate_batch, batches):
                    with conn.cursor() as cur:
                        for key, ko, err in res:
                            if ko and HANGUL_RE.search(ko):
                                cur.execute("""UPDATE translations SET ko = %s, status = 'done', error = NULL, updated_at = now()
                                               WHERE key = %s AND engine NOT IN ('manual', 'seed')""", (ko, key))
                                ok += 1
                            else:
                                cur.execute("""UPDATE translations SET attempts = attempts + 1, error = %s,
                                               status = CASE WHEN attempts + 1 >= %s THEN 'failed' ELSE 'pending' END,
                                               updated_at = now() WHERE key = %s""",
                                            (err or ("no Korean in output: " + str(ko)[:120]), MAX_ATTEMPTS, key))
                                bad += 1
                    conn.commit()
            with conn.cursor() as cur:
                build_ko_snapshot(cur)
                remaining = counts(cur)["pending"]
            conn.commit()
            log.info("번역 %d건 완료, 실패 %d건, 남은 %d건 (%s)", ok, bad, remaining, today)
            return {"done": ok, "failed": bad, "remaining": remaining}
    finally:
        conn.close()


def retry_failed():
    with db.connect(autocommit=True) as c:
        n = c.execute("UPDATE translations SET status = 'pending', attempts = 0 WHERE status = 'failed'").rowcount
    return n


def set_manual(key, text):
    with db.connect() as c:
        with c.cursor() as cur:
            cur.execute("""INSERT INTO translations (key, ko, engine, status, priority) VALUES (%s, %s, 'manual', 'done', 0)
                           ON CONFLICT (key) DO UPDATE SET ko = EXCLUDED.ko, engine = 'manual', status = 'done', updated_at = now()""",
                        (key, text))
            build_ko_snapshot(cur)
        c.commit()


def clear_manual(key=None, engine=None):
    """Hand one key (or every row of an engine, e.g. 'seed') back to machine translation."""
    with db.connect() as c:
        with c.cursor() as cur:
            where, arg = ("key = %s", key) if key else ("engine = %s", engine)
            cur.execute(f"""UPDATE translations SET engine = 'libretranslate', attempts = 0, error = NULL,
                            status = CASE WHEN src <> '' THEN 'pending' ELSE status END WHERE {where}""", (arg,))
            n = cur.rowcount
            build_ko_snapshot(cur)
        c.commit()
    return n
