"""Korean briefing written by EXAONE, on SUMMARY_CRON (default 07:00, 12:00, 19:00) with every run kept in summary_history (any OpenAI-compatible /chat/completions endpoint).

Default target: LG EXAONE API Platform (https://api.exaone.ai/v1, model k-exaone_v2.5). K-EXAONE 2.5 always
reasons; reasoning comes back in message.reasoning_content and counts toward max_tokens.
FriendliAI serverless (https://api.friendli.ai/serverless/v1) with older EXAONE models works too.
A self-hosted vLLM/SGLang EXAONE works too: point EXAONE_BASE_URL at it (e.g. http://exaone:8000/v1).

The model only sees the last ~2 days of collected data. Any CVE id it returns that was not in that input is dropped,
so the page never links to an id the model made up.
"""
import datetime as dt
import json
import logging
import re
import time
import urllib.error
import urllib.request
from zoneinfo import ZoneInfo

from psycopg.types.json import Jsonb

from . import config, db

log = logging.getLogger("radar.summary")

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
THINK_RE = re.compile(r"<think>.*?</think>", re.S | re.I)
FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.M)
LEVELS = ("urgent", "watch", "info")
WINDOW_DAYS = 2

SYSTEM = """당신은 한국 기업의 인프라·보안 운영 담당자를 위한 아침 취약점 브리핑을 쓰는 분석가입니다.
규칙:
- 입력 데이터에 있는 사실만 씁니다. 입력에 없는 CVE 번호, 버전, 벤더, 수치는 절대 만들지 않습니다.
- 우선순위: 실제 악용(KEV, 악용 새로 확인) > 인증 없이 원격 + PoC > 경계 장비(VPN·방화벽·공유기) > 주요 벤더 정기 업데이트 > KISA 권고.
- 쉬운 한국어로, 담당자가 무엇을 해야 하는지(업데이트 버전, 외부 노출 차단, 침해 흔적 점검)를 분명히 씁니다.
- 반드시 아래 JSON 하나만 출력합니다. 설명이나 코드 블록 표시를 붙이지 않습니다.
{"headline": "오늘 상황을 한 문장으로(60자 이내)",
 "points": [{"level": "urgent|watch|info", "title": "짧은 제목(25자 이내)", "text": "1~2문장 설명", "ids": ["CVE-..."]}],
 "actions": ["오늘 할 일 한 줄", "..."]}
- points는 3~6개, actions는 1~4개. urgent는 실제 악용이 확인된 것에만 씁니다."""


def enabled():
    return bool(config.EXAONE_API_KEY) and config.SUMMARY_ENABLED


def _today():
    return dt.datetime.now(ZoneInfo(config.TZ)).date()


def _is_rce(c):
    return c.get("av") == "N" and c.get("pr") == "N" and c.get("ui") in ("N", None)


def _has_sig(c):
    return bool(c.get("kev")) or c.get("exploitation") in ("active", "poc", "public poc")


def _clip(s, n):
    s = " ".join(str(s or "").split())
    return s if len(s) <= n else s[:n - 1] + "…"


def _fix(fx):
    out = []
    for f in (fx or [])[:2]:
        p = (f.get("p") + " ") if f.get("p") else ""
        if f.get("lt"):
            out.append(f"{p}{f['lt']} 이상")
        elif f.get("le"):
            out.append(f"{p}{f['le']} 이하 영향")
    return ", ".join(out)


def build_digest(cur, today=None):
    """Returns (prompt_text, allowed_ids, counts). Empty prompt when nothing happened."""
    today = today or _today()
    since = (today - dt.timedelta(days=WINDOW_DAYS)).isoformat()
    kev = (db.get_snapshot(cur, "kev", {}) or {}).get("items", [])
    crit = (db.get_snapshot(cur, "critical", {}) or {}).get("items", [])
    upd = (db.get_snapshot(cur, "updates", {}) or {}).get("items", [])
    kisa = (db.get_snapshot(cur, "kisa", {}) or {}).get("items", [])
    changes = (db.get_snapshot(cur, "changes", {}) or {}).get("days", [])
    ko = (db.get_snapshot(cur, "ko", {}) or {}).get("items", {})

    def say(i, en):
        k = (ko.get(i) or {}).get("t")
        return _clip(k or en, 220)

    lines, allowed = [], set()
    k_new = [k for k in kev if k.get("added", "") >= since]
    if k_new:
        lines.append("## 실제 악용 목록(CISA KEV)에 새로 추가")
        for k in k_new[:15]:
            allowed.add(k["id"])
            tags = [t for t, on in (("랜섬웨어에 쓰임", k.get("ransomware") == "Known"), ("경계 장비", k.get("edge")),
                                    ("침해 흔적 점검 필요", k.get("forensic"))) if on]
            lines.append(f"- {k['id']} | {k.get('vendor')} {k.get('product')} | {say(k['id'], k.get('summary') or k.get('name'))}"
                         + (f" | 수정: {_fix(k.get('fix'))}" if _fix(k.get("fix")) else "") + (f" | {', '.join(tags)}" if tags else ""))
    ev_active = []
    ev_poc = 0
    for d in changes:
        if d.get("date", "") < since:
            continue
        for e in d.get("items", []):
            if e.get("type") in ("crit_active", "kev_ransomware"):
                ev_active.append(e)
            elif e.get("type") == "crit_poc":
                ev_poc += 1
    if ev_active:
        lines.append("## 악용·랜섬웨어 사용이 새로 확인됨")
        seen = set()
        for e in ev_active[:12]:
            if e["id"] in seen:
                continue
            seen.add(e["id"])
            allowed.add(e["id"])
            what = "랜섬웨어 사용 확인" if e["type"] == "kev_ransomware" else "실제 악용 확인"
            lines.append(f"- {e['id']} | {e.get('vendor')} {e.get('product')} | {what}")
    c_new = [c for c in crit if c.get("published", "") >= since]
    hot = sorted([c for c in c_new if _is_rce(c) and _has_sig(c)], key=lambda c: -(c.get("score") or 0))
    if hot:
        lines.append("## 새 Critical 중 인증 없이 원격 공격 가능 + PoC/악용 신호")
        for c in hot[:10]:
            allowed.add(c["id"])
            lines.append(f"- {c['id']} | {c.get('vendor')} {c.get('product')} | CVSS {c.get('score')} | {say(c['id'], c.get('summary'))}"
                         + (f" | 수정: {_fix(c.get('fix'))}" if _fix(c.get("fix")) else "") + (" | 경계 장비" if c.get("edge") else ""))
    groups = [g for g in upd if g.get("date", "") >= since and (g.get("kev") or g.get("exploited") or (g.get("maxScore", 0) >= 9 and g.get("nRemote")))]
    groups.sort(key=lambda g: (len(g.get("kev") or []), g.get("maxScore", 0)), reverse=True)
    if groups:
        lines.append("## 주요 벤더 보안 업데이트")
        for g in groups[:8]:
            ids = (g.get("kev") or []) + [i for i in (g.get("cves") or [])[:2] if i not in (g.get("kev") or [])]
            allowed.update(ids)
            lines.append(f"- {g['vendor']} ({', '.join((g.get('products') or [])[:3])}) | CVE {g.get('count')}건, 최고 {g.get('maxScore')}점, "
                         f"인증 없이 원격 {g.get('nRemote')}건, 실제 악용 {len(g.get('kev') or [])}건 | 대표 CVE: {', '.join(ids[:3])}"
                         + (f" | 수정: {', '.join(g.get('fixes')[:2])}" if g.get("fixes") else ""))
    rss_items = [r for r in (db.get_snapshot(cur, "rss", {}) or {}).get("items", []) if r.get("date", "") >= since]
    if rss_items:
        lines.append("## KNVD(KISA 보안취약점 정보포털) 새 글")
        for r in rss_items[:12]:
            allowed.update(r.get("cves") or [])
            title = say(f"rss:{r['feed']}:{r['id']}:t", r.get("title")) if r.get("lang") == "en" else _clip(r.get("title"), 160)
            extra = f" | CVSS {r['cvss']}" if r.get("cvss") is not None else ""
            cves = ", ".join((r.get("cves") or [])[:3])
            lines.append(f"- {r['date']} {title}{extra}" + (f" | {cves}" if cves else ""))
    k_kisa = [k for k in kisa if k.get("date", "") >= since]
    if k_kisa:
        lines.append("## KISA 보호나라 권고")
        for k in k_kisa[:10]:
            allowed.update(k.get("cves") or [])
            lines.append(f"- {k['date']} {k['title']}")
    counts = {"kevNew": len(k_new), "exploitedNew": len(ev_active), "pocNew": ev_poc, "critNew": len(c_new),
              "hot": len(hot), "updates": len(groups), "kisa": len(k_kisa), "knvd": len(rss_items)}
    if not lines:
        return "", allowed, counts
    head = (f"기준일: {today.isoformat()} (최근 {WINDOW_DAYS}일)\n"
            f"새 Critical(CVSS 9.0+) {len(c_new)}건, PoC 새로 공개 {ev_poc}건.\n")
    return head + "\n".join(lines), allowed, counts


def _call(prompt):
    body = {
        "model": config.EXAONE_MODEL,
        "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
        "max_tokens": config.SUMMARY_MAX_TOKENS,
        "temperature": 0.3,
        "top_p": 0.95,
        "stream": False,
    }
    if config.EXAONE_REASONING_EFFORT:
        body["reasoning_effort"] = config.EXAONE_REASONING_EFFORT   # K-EXAONE 2.5: thinking can't be disabled
    elif not config.EXAONE_THINKING:
        body["chat_template_kwargs"] = {"enable_thinking": False}  # older EXAONE on vLLM/SGLang/Friendli
    data = json.dumps(body).encode("utf-8")
    url = config.EXAONE_BASE_URL.rstrip("/") + "/chat/completions"
    last = None
    for attempt in range(3):
        req = urllib.request.Request(url, data=data, headers={
            "Content-Type": "application/json", "Authorization": "Bearer " + config.EXAONE_API_KEY})
        try:
            with urllib.request.urlopen(req, timeout=config.SUMMARY_TIMEOUT) as r:
                res = json.loads(r.read())
            choice = (res.get("choices") or [{}])[0]
            msg = choice.get("message") or {}
            text = msg.get("content") or ""
            if not text.strip():
                if choice.get("finish_reason") == "length":
                    raise RuntimeError("추론 중 max_tokens 소진 — SUMMARY_MAX_TOKENS를 늘리거나 "
                                       "EXAONE_REASONING_EFFORT를 낮추세요")
                raise RuntimeError("빈 응답: " + json.dumps(res, ensure_ascii=False)[:300])
            return text
        except urllib.error.HTTPError as e:
            detail = e.read()[:400].decode("utf-8", "replace")
            last = RuntimeError(f"HTTP {e.code}: {detail}")
            if e.code in (400, 401, 403, 404, 422):
                break                                   # config problem: retrying won't help
        except Exception as e:
            last = e
        time.sleep(5 * (attempt + 1))
    raise last


def parse(text, allowed):
    t = THINK_RE.sub("", text).strip()
    t = FENCE_RE.sub("", t).strip()
    a, b = t.find("{"), t.rfind("}")
    if a < 0 or b <= a:
        raise ValueError("JSON을 찾지 못함: " + t[:200])
    obj = json.loads(t[a:b + 1])
    head = _clip(obj.get("headline"), 90)
    points = []
    for p in obj.get("points") or []:
        if not isinstance(p, dict):
            continue
        txt = _clip(p.get("text"), 320)
        title = _clip(p.get("title"), 60)
        if not (txt or title):
            continue
        ids = [i for i in (p.get("ids") or []) if isinstance(i, str) and i in allowed]
        # ids mentioned in the prose must also exist in the input
        bogus = [i for i in CVE_RE.findall(title + " " + txt) if i not in allowed]
        for i in bogus:
            txt = txt.replace(i, "").replace("()", "").strip()
            title = title.replace(i, "").strip()
        lvl = p.get("level") if p.get("level") in LEVELS else "info"
        points.append({"level": lvl, "title": title, "text": txt, "ids": ids[:4]})
    actions = [_clip(x, 160) for x in (obj.get("actions") or []) if isinstance(x, str) and x.strip()][:4]
    if not head or not points:
        raise ValueError("headline/points 비어 있음")
    order = {l: i for i, l in enumerate(LEVELS)}
    points.sort(key=lambda p: order[p["level"]])
    return {"headline": head, "points": points[:6], "actions": actions}


def run(force=False, slot=""):
    """Generate a briefing now (worker: on SUMMARY_CRON slots). Every success is also kept in summary_history.
    Returns a status dict; never raises for expected failures. `force` is kept for the CLI."""
    if not enabled():
        return {"skipped": "EXAONE_API_KEY 미설정"}
    today = _today()
    with db.connect() as c:
        with c.cursor() as cur:
            prompt, allowed, counts = build_digest(cur, today)
        c.commit()
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    base = {"date": today.isoformat(), "generatedAt": now, "model": config.EXAONE_MODEL, "counts": counts,
            "windowDays": WINDOW_DAYS, "slot": slot}
    if not prompt:
        doc = dict(base, status="ok", headline="지난 이틀 동안 새로 생긴 주요 취약점이 없습니다.", points=[], actions=[], quiet=True)
    else:
        rid = db.run_start("summary")
        try:
            raw = _call(prompt)
            try:
                out = parse(raw, allowed)
            except Exception as e:
                log.warning("요약 형식 오류, 한 번 더 요청: %s", e)
                out = parse(_call(prompt + "\n\n반드시 지정한 JSON 형식 하나만 출력하세요."), allowed)
            doc = dict(base, status="ok", **out)
            db.run_finish(rid, "ok", {"counts": counts, "points": len(out["points"])})
        except Exception as e:
            log.error("요약 생성 실패: %s", e)
            db.run_finish(rid, "failed", error=str(e)[:2000])
            # keep the last good summary visible; the page shows its date
            return {"failed": str(e)[:300]}
    with db.connect() as c:
        with c.cursor() as cur:
            db.put_snapshot(cur, "summary", doc)
            cur.execute("INSERT INTO summary_history (day, slot, doc) VALUES (%s, %s, %s)", (today, slot, Jsonb(doc)))
        c.commit()
    log.info("오늘의 요약 저장: %s", doc["headline"])
    return {"ok": True, "points": len(doc["points"]), "headline": doc["headline"]}


def history(cur, before=None, limit=20):
    """Past briefings for /api/summaries, newest first."""
    if before:
        cur.execute("SELECT id, generated_at, slot, doc FROM summary_history WHERE generated_at < %s ORDER BY generated_at DESC LIMIT %s", (before, limit))
    else:
        cur.execute("SELECT id, generated_at, slot, doc FROM summary_history ORDER BY generated_at DESC LIMIT %s", (limit,))
    return [dict(doc, id=i, at=at.isoformat(timespec="seconds"), slot=slot or doc.get("slot") or "") for i, at, slot, doc in cur.fetchall()]
