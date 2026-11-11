"""Import the JSON state files published by the original artifact so the first run can be incremental.

Expected files (any may be missing): meta.json store.json kevcache.json kisa.json changes.json packages.json ko.json
"""
import json
import logging
import os

from psycopg.types.json import Jsonb

from . import db

log = logging.getLogger("radar.seed")


def _load(d, name):
    p = os.path.join(d, name + ".json")
    if not os.path.isfile(p):
        return None
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def is_empty():
    with db.connect() as c:
        r = c.execute("SELECT count(*) FROM snapshots WHERE name = 'meta'").fetchone()[0]
    return r == 0


def has_seed(d):
    return bool(d) and os.path.isfile(os.path.join(d, "meta.json")) and os.path.isfile(os.path.join(d, "store.json"))


def run(d, force=False, with_ko=True):
    if not has_seed(d):
        raise SystemExit(f"seed 폴더에 meta.json, store.json이 없습니다: {d}")
    if not force and not is_empty():
        log.info("DB에 이미 데이터가 있어 seed를 건너뜁니다 (--force로 덮어쓰기)")
        return {"skipped": True}
    meta = _load(d, "meta") or {}
    store = (_load(d, "store") or {}).get("items") or []
    kevcache = (_load(d, "kevcache") or {}).get("items") or {}
    kisa = (_load(d, "kisa") or {}).get("items") or []
    changes = (_load(d, "changes") or {}).get("days") or []
    packages = _load(d, "packages")
    ko = (_load(d, "ko") or {}).get("items") or {}
    with db.connect() as c:
        with c.cursor() as cur:
            db.put_snapshot(cur, "meta", meta)
            if packages:
                db.put_snapshot(cur, "packages", packages)
            cur.execute("TRUNCATE cve_store")
            with cur.copy("COPY cve_store (cve_id, published, score, vendor, major, item) FROM STDIN") as cp:
                for it in store:
                    if it.get("id") and it.get("published") and it.get("score") is not None:
                        cp.write_row((it["id"], it["published"], it["score"], it.get("vendor") or "", it.get("major") or "", db.dumps(it)))
            cur.execute("TRUNCATE kev_cache")
            with cur.copy("COPY kev_cache (cve_id, row) FROM STDIN") as cp:
                for k, v in kevcache.items():
                    cp.write_row((k, db.dumps(v)))
            cur.execute("TRUNCATE kisa_notices")
            for k in kisa:
                if k.get("ntt") and k.get("date"):
                    cur.execute("INSERT INTO kisa_notices (ntt, date, item) VALUES (%s, %s, %s)", (k["ntt"], k["date"], Jsonb(k)))
            cur.execute("TRUNCATE change_days")
            for x in changes:
                if x.get("date"):
                    cur.execute("INSERT INTO change_days (day, item) VALUES (%s, %s)", (x["date"], Jsonb(x)))
            n_ko = 0
            if with_ko:
                for key, v in ko.items():
                    t = (v or {}).get("t")
                    if not t:
                        continue
                    cur.execute("""INSERT INTO translations (key, ko, engine, status, priority) VALUES (%s, %s, 'seed', 'done', 9)
                                   ON CONFLICT (key) DO NOTHING""", (key, t))
                    n_ko += 1
        c.commit()
    res = {"store": len(store), "kevcache": len(kevcache), "kisa": len(kisa), "changes": len(changes), "ko": n_ko,
           "cursor": meta.get("deltaCursor")}
    log.info("seed 완료 %s", res)
    return res
