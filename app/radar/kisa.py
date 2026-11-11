"""KISA 보호나라 보안공지 list scraper.

Returns [{"title", "date", "url"}] (the shape collect.kisa_norm expects), or None when nothing could be read.
The list page is server-rendered: a <table> with 번호 | 제목(link to view.do?...nttId=N) | 조회수 | 첨부 | 게시일.
"""
import html
import logging
import re
import time
import urllib.request

from . import config

log = logging.getLogger("radar.kisa")

LIST_URL = "https://www.boho.or.kr/kr/bbs/list.do?menuNo=205020&bbsId=B0000133&pageIndex={page}"
ROW_RE = re.compile(r"<tr\b[^>]*>(.*?)</tr>", re.S | re.I)
A_RE = re.compile(r"<a\b[^>]*href=[\"']([^\"']*nttId=(\d+)[^\"']*)[\"'][^>]*>(.*?)</a>", re.S | re.I)
DATE_RE = re.compile(r"(20\d{2})[-./](\d{2})[-./](\d{2})")
TAG_RE = re.compile(r"<[^>]+>")


BADGE_RE = re.compile(r"<(span|em|i|strong|b)\b[^>]*class=[\"'][^\"']*(new|icon|ico|badge|label|attach|file)[^\"']*[\"'][^>]*>.*?</\1>", re.S | re.I)
EDGE_WORD_RE = re.compile(r"^(?:N|NEW|새글)\s+|\s+(?:N|NEW|새글)$")


def _text(s):
    s = BADGE_RE.sub(" ", s)
    t = " ".join(html.unescape(TAG_RE.sub(" ", s)).split())
    return EDGE_WORD_RE.sub("", t).strip()


def parse(page_html):
    out, seen = [], set()
    rows = ROW_RE.findall(page_html)
    for row in rows:
        m = A_RE.search(row)
        if not m:
            continue
        ntt = m.group(2)
        title = _text(m.group(3))
        # the date column comes after the title; search the remainder first, then the whole row
        rest = row[m.end():]
        d = DATE_RE.search(rest) or DATE_RE.search(row)
        if not title or not d or ntt in seen:
            continue
        seen.add(ntt)
        out.append({"title": title, "date": "-".join(d.groups()),
                    "url": f"https://www.boho.or.kr/kr/bbs/view.do?bbsId=B0000133&nttId={ntt}&menuNo=205020"})
    if not out and not rows:
        # markup without a table: pair each link with the next date that follows it
        for m in A_RE.finditer(page_html):
            ntt = m.group(2)
            d = DATE_RE.search(page_html, m.end(), m.end() + 2000)
            title = _text(m.group(3))
            if title and d and ntt not in seen:
                seen.add(ntt)
                out.append({"title": title, "date": "-".join(d.groups()),
                            "url": f"https://www.boho.or.kr/kr/bbs/view.do?bbsId=B0000133&nttId={ntt}&menuNo=205020"})
    return out


def _get(url, timeout=30, tries=3):
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": config.USER_AGENT,
                "Accept": "text/html,application/xhtml+xml",
                "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.5",
            })
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                cs = r.headers.get_content_charset() or "utf-8"
            return raw.decode(cs, errors="replace")
        except Exception as e:
            last = e
            time.sleep(2 * (i + 1))
    raise last


def fetch(pages=None):
    pages = pages or config.KISA_PAGES
    items, ok_pages = [], 0
    for p in range(1, pages + 1):
        try:
            got = parse(_get(LIST_URL.format(page=p)))
        except Exception as e:
            log.warning("KISA page %s 실패: %s", p, e)
            continue
        if got:
            ok_pages += 1
        items.extend(got)
    if not ok_pages:
        return None
    log.info("KISA %s건 (%s페이지)", len(items), ok_pages)
    return items
