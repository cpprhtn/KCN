"""RSS/Atom feed poller (KNVD 보안공지·공개 취약점 + any feed listed in RSS_FEEDS).

Feeds only carry their latest ~10 entries, so the worker polls them every RSS_INTERVAL_MIN and keeps every
entry it has ever seen in the rss_items table (never pruned). The browser reads the "rss" snapshot
(recent RSS_SNAPSHOT_DAYS) and /api/rss for older history.

Entries that are mostly English are queued into the translations table under keys
  rss:<feed>:<guid>:t   (title)
  rss:<feed>:<guid>:d   (first part of the body)
and LibreTranslate fills them in; the page shows the Korean text from the "ko" snapshot.
"""
import datetime as dt
import email.utils
import hashlib
import html
import logging
import re
import urllib.request
import xml.etree.ElementTree as ET

from psycopg.types.json import Jsonb

from . import config, db, translate

log = logging.getLogger("radar.rss")


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
HANGUL_RE = re.compile(r"[가-힣]")
LATIN_RE = re.compile(r"[A-Za-z]")
URL_RE = re.compile(r"https?://\S+")
BR_RE = re.compile(r"<br\s*/?>", re.I)
BLOCK_RE = re.compile(r"</(p|div|li|tr|h\d)>", re.I)
TAG_RE = re.compile(r"<[^>]+>")
MD_ESC_RE = re.compile(r"\\([\[\]()*_~`#|\\-])")       # KNVD bodies carry markdown escapes like \[1\]
ATOM = "{http://www.w3.org/2005/Atom}"
CONTENT = "{http://purl.org/rss/1.0/modules/content/}encoded"


def feeds():
    """[(name, label, url)] from RSS_FEEDS: 'name|label|url' entries separated by ';' or newlines."""
    out = []
    for part in re.split(r"[;\n]", config.RSS_FEEDS):
        bits = [b.strip() for b in part.split("|")]
        if len(bits) == 3 and bits[0] and bits[2].startswith("http"):
            if re.fullmatch(r"[a-z0-9_-]{1,32}", bits[0]):
                out.append(tuple(bits))
            else:
                log.warning("RSS_FEEDS 이름은 영문 소문자·숫자·-_ 만 됩니다: %r", bits[0])
    return out


# ---------------------------------------------------------------- parsing
def clean_html(s):
    s = html.unescape(s or "")
    s = BR_RE.sub("\n", s)
    s = BLOCK_RE.sub("\n", s)
    s = html.unescape(TAG_RE.sub("", s))
    s = MD_ESC_RE.sub(r"\1", s)
    lines = [" ".join(l.split()) for l in s.replace("\r", "").split("\n")]
    out, blank = [], False
    for l in lines:
        if not l:
            if out and not blank:
                out.append("")
            blank = True
            continue
        out.append(l)
        blank = False
    return "\n".join(out).strip()


def lang_of(*texts):
    """'en' when the prose (URLs, CVE ids and table rows removed) is mostly Latin letters."""
    s = " ".join(t or "" for t in texts)
    s = URL_RE.sub(" ", s)
    s = CVE_RE.sub(" ", s)
    s = "\n".join(l for l in s.split("\n") if not l.lstrip().startswith("|"))
    hg, lt = len(HANGUL_RE.findall(s)), len(LATIN_RE.findall(s))
    if hg + lt == 0:
        return "ko"
    # one Hangul syllable carries roughly 2-3 Latin letters' worth of text
    return "en" if hg * 2.5 < lt * 0.15 else "ko"


def _date(s):
    if not s:
        return None
    s = s.strip()
    try:
        d = email.utils.parsedate_to_datetime(s)
    except Exception:
        try:
            d = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d


def _table_rows(body):
    """Markdown-ish tables ('| a | b |') -> list of tables, each a list of cell lists (separator rows dropped)."""
    tables, cur = [], []
    for line in body.split("\n"):
        l = line.strip()
        if l.startswith("|") and l.count("|") >= 2:
            cells = [c.strip() for c in l.strip("|").split("|")]
            if all(re.fullmatch(r":?-{2,}:?", c) for c in cells if c):
                continue
            cur.append(cells)
        elif cur:
            tables.append(cur)
            cur = []
    if cur:
        tables.append(cur)
    return tables


def extras(body):
    """Max CVSS and severity from tables with a CVSS / 심각도 column (KNVD 공개 취약점)."""
    best, sev = None, None
    for t in _table_rows(body):
        head = [h.upper() for h in t[0]]
        ci = next((i for i, h in enumerate(head) if "CVSS" in h), None)
        si = next((i for i, h in enumerate(t[0]) if "심각도" in h or h.upper() == "SEVERITY"), None)
        for row in t[1:]:
            if ci is not None and ci < len(row):
                m = re.search(r"\d{1,2}(?:\.\d)?", row[ci])
                if m:
                    v = float(m.group(0))
                    if 0 <= v <= 10 and (best is None or v > best):
                        best = v
                        sev = row[si] if si is not None and si < len(row) else sev
    out = {}
    if best is not None:
        out["cvss"] = best
    if sev:
        out["sev"] = sev
    return out


def parse(xml_text, feed):
    root = ET.fromstring(xml_text)
    out = []
    if root.tag == ATOM + "feed":
        entries = root.findall(ATOM + "entry")
        for e in entries:
            link = ""
            for l in e.findall(ATOM + "link"):
                if l.get("rel", "alternate") == "alternate":
                    link = l.get("href", "")
                    break
            body = e.findtext(ATOM + "content") or e.findtext(ATOM + "summary") or ""
            out.append({"title": e.findtext(ATOM + "title") or "", "link": link, "raw": body,
                        "guid": e.findtext(ATOM + "id") or link,
                        "date": _date(e.findtext(ATOM + "updated") or e.findtext(ATOM + "published")),
                        "category": ", ".join(c.get("term", "") for c in e.findall(ATOM + "category") if c.get("term"))})
    else:
        for it in root.iter("item"):
            link = (it.findtext("link") or "").strip()
            out.append({"title": it.findtext("title") or "", "link": link,
                        "raw": it.findtext(CONTENT) or it.findtext("description") or "",
                        "guid": (it.findtext("guid") or "").strip() or link,
                        "date": _date(it.findtext("pubDate") or it.findtext("{http://purl.org/dc/elements/1.1/}date")),
                        "category": ", ".join((c.text or "").strip() for c in it.findall("category") if (c.text or "").strip())})
    items = []
    for x in out:
        title = " ".join(html.unescape(TAG_RE.sub("", x["title"])).split())
        if not title:
            continue
        body = clean_html(x["raw"])[: config.RSS_BODY_MAX]
        guid = x["guid"]
        m = re.search(r"[?&]id=([A-Za-z0-9_-]+)", guid)        # KNVD: detail?id=<hex>
        guid = m.group(1) if m else hashlib.sha1(guid.encode("utf-8")).hexdigest()[:24]
        cves = sorted({c.upper() for c in CVE_RE.findall(title + "\n" + body)})
        items.append({"feed": feed, "guid": guid, "title": title, "link": x["link"], "body": body,
                      "category": x["category"][:200], "published": x["date"], "cves": cves,
                      "lang": lang_of(title, body), "extra": extras(body)})
    return items


def _get(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": config.USER_AGENT,
                                               "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


# ---------------------------------------------------------------- translation text
SECTION_SKIP = re.compile(r"^(□\s*)?(참고\s*사이트|문의\s*사항|작성)", re.I)


def lead_text(body):
    """Prose part of the body for translation: no tables, URLs or footer sections."""
    keep = []
    for l in body.split("\n"):
        s = l.strip()
        if not s or s.startswith("|") or s.startswith("※"):
            continue
        if SECTION_SKIP.match(s):
            break
        s = URL_RE.sub("", s).strip()
        s = re.sub(r"^(□|o|-|•)\s*", "", s)
        if len(s) > 2:
            keep.append(s)
    return " ".join(keep)


def tr_keys(it):
    base = f"rss:{it['feed']}:{it['guid']}"
    return base + ":t", base + ":d"


def queue_translation(cur, it):
    if it["lang"] != "en":
        return 0
    kt, kd = tr_keys(it)
    rows = [(kt, translate.prep(it["title"]), 1), (kd, translate.prep(lead_text(it["body"])), 2)]
    n = 0
    for key, src, pr in rows:
        if not src:
            continue
        cur.execute("""INSERT INTO translations (key, src, src_hash, priority) VALUES (%s, %s, %s, %s)
                       ON CONFLICT (key) DO UPDATE SET src = EXCLUDED.src, src_hash = EXCLUDED.src_hash,
                         status = 'pending', attempts = 0, error = NULL, updated_at = now()
                       WHERE translations.src_hash <> EXCLUDED.src_hash AND translations.engine NOT IN ('manual', 'seed')""",
                    (key, src, translate.h(src), pr))
        n += cur.rowcount
    return n


# ---------------------------------------------------------------- storage + snapshot
def upsert(cur, it):
    """Returns 'new', 'updated' or None."""
    cur.execute("""INSERT INTO rss_items (feed, guid, title, link, body, category, published, cves, lang, extra)
                   VALUES (%(feed)s, %(guid)s, %(title)s, %(link)s, %(body)s, %(category)s, %(published)s, %(cves)s, %(lang)s, %(extra)s)
                   ON CONFLICT (feed, guid) DO UPDATE SET title = EXCLUDED.title, link = EXCLUDED.link, body = EXCLUDED.body,
                     category = EXCLUDED.category, published = EXCLUDED.published, cves = EXCLUDED.cves, lang = EXCLUDED.lang,
                     extra = EXCLUDED.extra, updated_at = now()
                   WHERE (rss_items.title, rss_items.body, rss_items.link) IS DISTINCT FROM (EXCLUDED.title, EXCLUDED.body, EXCLUDED.link)
                   RETURNING (xmax = 0) AS inserted""",
                {**it, "extra": Jsonb(it["extra"])})
    r = cur.fetchone()
    if not r:
        return None
    return "new" if r[0] else "updated"


def row_json(r):
    feed, guid, title, link, body, category, published, cves, lang, extra, first_seen = r
    d = {"feed": feed, "id": guid, "title": title, "link": link, "body": body, "cat": category,
         "date": published.astimezone(dt.timezone(dt.timedelta(hours=9))).date().isoformat(),
         "at": published.isoformat(timespec="seconds"), "cves": list(cves or []), "lang": lang,
         "seen": first_seen.isoformat(timespec="seconds")}
    d.update(extra or {})
    return d


COLS = "feed, guid, title, link, body, category, published, cves, lang, extra, first_seen"


def build_snapshot(cur, status=None):
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=config.RSS_SNAPSHOT_DAYS)
    meta = []
    items = []
    for name, label, url in feeds():
        cur.execute(f"""SELECT {COLS} FROM rss_items WHERE feed = %s AND published >= %s
                        ORDER BY published DESC, guid LIMIT %s""", (name, since, config.RSS_SNAPSHOT_MAX))
        rows = cur.fetchall()
        items.extend(row_json(r) for r in rows)
        cur.execute("SELECT count(*), min(published) FROM rss_items WHERE feed = %s", (name,))
        total, oldest = cur.fetchone()
        st = (status or {}).get(name) or {}
        meta.append({"name": name, "label": label, "url": url, "total": total, "inSnapshot": len(rows),
                     "oldest": oldest.isoformat(timespec="seconds") if oldest else None, **st})
    body = {"generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "days": config.RSS_SNAPSHOT_DAYS, "feeds": meta, "items": items}
    return db.put_snapshot(cur, "rss", body)


def history(cur, feed=None, before=None, q=None, limit=50):
    """Older entries for /api/rss (the whole archive, newest first)."""
    where, args = [], []
    if feed:
        where.append("feed = %s"); args.append(feed)
    if before:
        where.append("published < %s"); args.append(before)
    if q:
        where.append("(title ILIKE %s OR body ILIKE %s OR %s = ANY(cves))")
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        args += [like, like, q.upper()]
    sql = f"SELECT {COLS} FROM rss_items" + (" WHERE " + " AND ".join(where) if where else "") + \
          " ORDER BY published DESC, guid LIMIT %s"
    cur.execute(sql, args + [limit])
    return [row_json(r) for r in cur.fetchall()]


def run():
    """Poll every feed once. Returns a stats dict."""
    now = dt.datetime.now(dt.timezone.utc)
    status, stats = {}, {"new": 0, "updated": 0, "queued": 0, "failed": []}
    fetched = {}
    for name, label, url in feeds():
        try:
            fetched[name] = parse(_get(url), name)
            status[name] = {"status": "ok", "fetchedAt": now.isoformat(timespec="seconds"), "count": len(fetched[name])}
        except Exception as e:
            log.warning("RSS %s 실패: %s", name, e)
            stats["failed"].append(name)
            status[name] = {"status": "failed", "error": str(e)[:200]}
    with db.connect() as c, db.advisory_lock(c, db.LOCK_RSS) as got:
        if not got:
            return {"skipped": "busy"}
        with c.cursor() as cur:
            prev = db.kv_get(cur, "rss_status", {}) or {}
            for name, its in fetched.items():
                for it in its:
                    if it["published"] is None:
                        it["published"] = now
                    r = upsert(cur, it)
                    if r:
                        stats[r] += 1
                    stats["queued"] += queue_translation(cur, it)
            for name, st in status.items():
                # on failure keep the last successful fetchedAt so the page can say how stale it is
                prev[name] = st if st["status"] == "ok" else {**(prev.get(name) or {}), **st}
            db.kv_set(cur, "rss_status", prev)
            build_snapshot(cur, prev)
        c.commit()
    log.info("RSS 새 글 %d, 바뀐 글 %d, 번역 대기 %d, 실패 %s", stats["new"], stats["updated"], stats["queued"], stats["failed"] or "-")
    return stats
