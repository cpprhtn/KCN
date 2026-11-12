"""Command line.

  python -m radar web                      HTTP server
  python -m radar worker                   scheduler (collect on COLLECT_CRON + background translation)
  python -m radar collect [--full] [--no-kisa] [--no-packages]
  python -m radar translate [--limit N] [--all] [--retry-failed]
  python -m radar seed DIR [--force] [--no-ko]
  python -m radar ko-set KEY "한국어 문장"     hand-written Korean (never overwritten by MT)
  python -m radar ko-reset KEY | --seed    give KEY (or every seed row) back to LibreTranslate
  python -m radar rss                      poll the RSS feeds (RSS_FEEDS) once
  python -m radar status
"""
import argparse
import json
import logging
import sys


def main(argv=None):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    ap = argparse.ArgumentParser(prog="radar", description="KCM 서버")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("web")
    sub.add_parser("worker")
    p = sub.add_parser("collect")
    p.add_argument("--full", action="store_true")
    p.add_argument("--no-kisa", action="store_true")
    p.add_argument("--no-packages", action="store_true")
    p.add_argument("--kisa-file", help="JSON array [{title,date,url}] used instead of scraping boho.or.kr")
    p = sub.add_parser("translate")
    p.add_argument("--limit", type=int)
    p.add_argument("--all", action="store_true", help="keep going until the queue is empty")
    p.add_argument("--retry-failed", action="store_true")
    p = sub.add_parser("seed")
    p.add_argument("dir")
    p.add_argument("--force", action="store_true")
    p.add_argument("--no-ko", action="store_true")
    p = sub.add_parser("ko-set")
    p.add_argument("key")
    p.add_argument("text")
    p = sub.add_parser("ko-reset")
    p.add_argument("key", nargs="?")
    p.add_argument("--seed", action="store_true")
    p = sub.add_parser("summarize", help="EXAONE으로 오늘의 요약 생성")
    p.add_argument("--force", action="store_true")
    p.add_argument("--dry-run", action="store_true", help="모델에 보낼 입력만 출력")
    sub.add_parser("rss", help="RSS 피드(RSS_FEEDS)를 지금 한 번 읽기")
    sub.add_parser("status")
    a = ap.parse_args(argv)

    from . import db
    if a.cmd == "web":
        from . import web
        return web.main()
    if a.cmd == "worker":
        from . import worker
        return worker.main()
    db.init_schema()
    if a.cmd == "collect":
        from . import collect
        kisa_items = None
        if a.kisa_file:
            with open(a.kisa_file, encoding="utf-8") as fh:
                kisa_items = json.load(fh)
        rid = db.run_start("collect-full" if a.full else "collect")
        try:
            s = collect.run(full=a.full, kisa_items=kisa_items, skip_kisa=a.no_kisa, skip_packages=a.no_packages)
        except Exception as e:
            db.run_finish(rid, "failed", error=str(e))
            raise
        db.run_finish(rid, "ok", s)
        print(json.dumps(s, ensure_ascii=False, indent=1))
    elif a.cmd == "translate":
        from . import translate
        if a.retry_failed:
            print("재시도 대기열로 옮김:", translate.retry_failed())
        while True:
            r = translate.run_pending(a.limit)
            print(json.dumps(r, ensure_ascii=False))
            if not a.all or not r.get("remaining") or r.get("skipped") or not (r.get("done") or r.get("failed")):
                break
    elif a.cmd == "seed":
        from . import seed
        print(json.dumps(seed.run(a.dir, force=a.force, with_ko=not a.no_ko), ensure_ascii=False))
    elif a.cmd == "ko-set":
        from . import translate
        translate.set_manual(a.key, " ".join(a.text.split()))
        print("저장:", a.key)
    elif a.cmd == "ko-reset":
        from . import translate
        if not a.key and not a.seed:
            ap.error("KEY 또는 --seed가 필요합니다")
        print("기계 번역 대기열로 옮김:", translate.clear_manual(key=a.key) if a.key else translate.clear_manual(engine="seed"))
    elif a.cmd == "summarize":
        from . import summary
        if a.dry_run:
            with db.connect() as c:
                prompt, allowed, counts = summary.build_digest(c.cursor())
            print(prompt or "(입력할 항목 없음)"); print(counts)
        else:
            print(json.dumps(summary.run(force=a.force), ensure_ascii=False))
    elif a.cmd == "rss":
        from . import rss
        print(json.dumps(rss.run(), ensure_ascii=False))
    elif a.cmd == "status":
        with db.connect() as c:
            for r in c.execute("SELECT id, kind, status, started_at, finished_at, left(coalesce(error,''), 200) FROM runs ORDER BY id DESC LIMIT 10"):
                print(*r, sep=" | ")
            print("translations:", dict(c.execute("SELECT status, count(*) FROM translations GROUP BY status").fetchall()))
            print("rss:", c.execute("SELECT feed, count(*), max(published) FROM rss_items GROUP BY feed ORDER BY feed").fetchall())
            print("snapshots:", [r[0] for r in c.execute("SELECT name FROM snapshots ORDER BY name")])


if __name__ == "__main__":
    main()
