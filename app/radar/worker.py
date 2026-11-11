"""Long-running worker: scheduled collection + background translation."""
import datetime as dt
import logging
import signal
import time
import traceback
from zoneinfo import ZoneInfo

from croniter import croniter

from . import collect, config, db, seed, summary, translate

log = logging.getLogger("radar.worker")
STOP = False
RETRY_AFTER_FAIL = dt.timedelta(minutes=30)


def _stop(*_):
    global STOP
    STOP = True
    log.info("종료 신호를 받았습니다. 현재 작업이 끝나면 멈춥니다")


def nap(seconds):
    end = time.monotonic() + max(0, seconds)
    while not STOP and time.monotonic() < end:
        time.sleep(max(0.0, min(5.0, end - time.monotonic())))


def collect_once(full=False):
    rid = db.run_start("collect-full" if full else "collect")
    try:
        s = collect.run(full=full)
        db.run_finish(rid, "ok", s)
    except Exception as e:
        log.error("수집 실패: %s\n%s", e, traceback.format_exc())
        db.run_finish(rid, "failed", error=f"{e}\n{traceback.format_exc()[-2000:]}")
        return False
    try:
        r = summary.run(force=True)        # fresh data -> fresh briefing
        log.info("요약: %s", r)
    except Exception as e:
        log.error("요약 단계 오류: %s", e)
    return True


def startup_reason(seeded, tz):
    """Why the worker should collect right away, or None."""
    if seeded:
        return "seed를 넣었음"
    if config.COLLECT_ON_START:
        return "COLLECT_ON_START"
    with db.connect() as c:
        with c.cursor() as cur:
            cur.execute("SELECT name FROM snapshots")
            have = {r[0] for r in cur.fetchall()}
            meta = db.get_snapshot(cur, "meta", {}) or {}
    missing = {"meta", "insights", "kev", "critical"} - have
    if missing:
        return "스냅샷 없음: " + ", ".join(sorted(missing))
    gen = collect.pdate(meta.get("generatedAt"))
    if not gen:
        return "meta.generatedAt 없음"
    # the most recent scheduled time already passed without a successful run (server was down)
    prev_slot = croniter(config.COLLECT_CRON, dt.datetime.now(tz)).get_prev(dt.datetime)
    if gen < prev_slot:
        return f"예약 시각 {prev_slot.isoformat()} 수집을 놓침"
    return None


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    tz = ZoneInfo(config.TZ)
    db.init_schema()
    if not croniter.is_valid(config.COLLECT_CRON):
        raise SystemExit(f"COLLECT_CRON 형식이 잘못됐습니다: {config.COLLECT_CRON!r}")

    seeded = False
    if seed.is_empty() and seed.has_seed(config.SEED_DIR):
        log.info("빈 DB — %s 에서 초기 데이터를 불러옵니다", config.SEED_DIR)
        try:
            seeded = not seed.run(config.SEED_DIR).get("skipped")
        except Exception as e:
            log.error("seed 실패 (전체 수집으로 진행): %s", e)

    why = startup_reason(seeded, tz)
    first = why is not None
    if first:
        log.info("수집을 바로 시작합니다 (%s)", why)
        ok = collect_once()
    now = dt.datetime.now(tz)
    next_collect = croniter(config.COLLECT_CRON, now).get_next(dt.datetime)
    if first and not ok:
        next_collect = min(next_collect, now + RETRY_AFTER_FAIL)
    log.info("다음 수집: %s (%s)", next_collect.isoformat(), config.COLLECT_CRON)

    next_translate = dt.datetime.now(tz)
    while not STOP:
        now = dt.datetime.now(tz)
        if now >= next_collect:
            ok = collect_once()
            now = dt.datetime.now(tz)
            next_collect = croniter(config.COLLECT_CRON, now).get_next(dt.datetime)
            if not ok:
                next_collect = min(next_collect, now + RETRY_AFTER_FAIL)
            log.info("다음 수집: %s", next_collect.isoformat())
            next_translate = now
        if now >= next_translate and not STOP:
            try:
                r = translate.run_pending()
            except Exception as e:
                log.error("번역 작업 오류: %s", e)
                r = {"remaining": 0, "skipped": "error"}
            now = dt.datetime.now(tz)
            if r.get("remaining") and not r.get("skipped") and r.get("done", 0) + r.get("failed", 0) > 0:
                next_translate = now                                     # keep draining the queue
            elif r.get("skipped") == "libretranslate not ready":
                next_translate = now + dt.timedelta(minutes=1)
            else:
                next_translate = now + dt.timedelta(minutes=config.TRANSLATE_INTERVAL_MIN)
        wake = min(next_collect, next_translate)
        nap((wake - dt.datetime.now(tz)).total_seconds())
    log.info("worker 종료")
