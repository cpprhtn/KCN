import { Fragment, useMemo, useState } from "react";
import { useApp } from "../lib/AppContext.jsx";
import { fmt, koOf, mmdd } from "../lib/util.js";
import { Badge, CveLink, DoneBox, ExtLink, FilterSection, labelOf, PageHead, Seg } from "../components/common.jsx";

const STEP = 30;

// Korean title/lead for an entry: as published, or LibreTranslate's output for English feeds.
export function rssText(data, it) {
  const base = "rss:" + it.feed + ":" + it.id;
  if (it.lang !== "en") return { title: it.title, lead: leadOf(it.body), mt: false, pending: false };
  const t = koOf(data, base + ":t"), d = koOf(data, base + ":d");
  return { title: t || it.title, lead: d || leadOf(it.body), mt: !!(t || d), pending: !t, orig: it.title };
}

// First prose lines of the body ("□ 개요" section on KNVD), without tables or URLs.
function leadOf(body) {
  const out = [];
  for (const raw of (body || "").split("\n")) {
    const l = raw.trim();
    if (!l) { if (out.length) break; continue; }
    if (l.startsWith("□")) { if (out.length) break; continue; }
    if (l.startsWith("|") || l.startsWith("※")) continue;
    out.push(l.replace(/^(o|-|•)\s+/, "").replace(/\\([[\]~])/g, "$1").replace(/\s*\[\d+\](~\[\d+\])?/g, ""));
    if (out.join(" ").length > 220) break;
  }
  return out.join(" ");
}

const URL_RE = /(https?:\/\/[^\s<>"')]+)/g;
function Linkify({ text }) {
  const parts = text.split(URL_RE);
  return parts.map((p, i) => (i % 2 ? <ExtLink key={i} href={p}>{p}</ExtLink> : <Fragment key={i}>{p}</Fragment>));
}

// Renders KNVD's plain-text body: "□ 제목" headings, "| a | b |" tables, "o" bullets.
function Body({ body }) {
  const blocks = [];
  let table = null, list = null;
  const flush = () => {
    if (table) { blocks.push({ t: "table", rows: table }); table = null; }
    if (list) { blocks.push({ t: "ul", items: list }); list = null; }
  };
  for (const raw of body.split("\n")) {
    const l = raw.trim();
    if (l.startsWith("|") && l.split("|").length > 2) {
      if (list) { blocks.push({ t: "ul", items: list }); list = null; }
      const cells = l.replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
      if (cells.every((c) => !c || /^:?-{2,}:?$/.test(c))) continue;
      (table = table || []).push(cells);
      continue;
    }
    if (table) { blocks.push({ t: "table", rows: table }); table = null; }
    if (!l) { flush(); continue; }
    if (l.startsWith("□")) { flush(); blocks.push({ t: "h", text: l.replace(/^□\s*/, "") }); continue; }
    if (/^(o|-|•)\s+/.test(l)) { (list = list || []).push(l.replace(/^(o|-|•)\s+/, "")); continue; }
    flush();
    blocks.push({ t: "p", text: l });
  }
  flush();
  return (
    <div className="rss-body">
      {blocks.map((b, i) => {
        if (b.t === "h") return <h4 key={i}>{b.text}</h4>;
        if (b.t === "ul") return <ul key={i}>{b.items.map((x, j) => <li key={j}><Linkify text={x} /></li>)}</ul>;
        if (b.t === "p") return <p key={i}><Linkify text={b.text} /></p>;
        const [head, ...rows] = b.rows;
        return (
          <div className="tw" key={i}>
            <table>
              <thead><tr>{head.map((h, j) => <th key={j}>{h}</th>)}</tr></thead>
              <tbody>{rows.map((r, j) => <tr key={j}>{r.map((c, k) => <td key={k}>{c}</td>)}</tr>)}</tbody>
            </table>
          </div>
        );
      })}
    </div>
  );
}

const sevCls = (it) => (it.cvss >= 9 ? "crit" : it.cvss != null ? "kev" : "kisa");

export function KnvdItem({ it }) {
  const { data, done } = useApp();
  const tx = rssText(data, it);
  const key = "rss:" + it.feed + ":" + it.id;
  const kevIds = useMemo(() => new Set(data.kev.map((k) => k.id)), [data.kev]);
  const kevHits = it.cves.filter((c) => kevIds.has(c));
  const feedLabel = ((data.rss.feeds || []).find((f) => f.name === it.feed) || {}).label || it.feed;
  return (
    <li className={"item" + (done[key] ? " done" : "")}>
      <div className={"score " + sevCls(it)}>
        {it.cvss != null ? <><b>{Number(it.cvss).toFixed(1)}</b><span>CVSS</span></> : <><b>공지</b><span>{mmdd(it.date)}</span></>}
      </div>
      <div className="body">
        <div className="line1">
          <ExtLink href={it.link} className="prod">{tx.title}</ExtLink>
          <span className="date">{it.date}</span>
        </div>
        {tx.lead && <p className={it.lang === "en" && !tx.mt ? "ko-en" : "ko"} title={tx.orig}>{tx.lead}</p>}
        <div className="badges">
          <Badge cls="plain">{feedLabel}</Badge>
          {it.sev && <Badge cls={it.cvss >= 9 ? "rw" : "plain"}>{it.sev}</Badge>}
          {kevHits.length > 0 && <Badge cls="rw">실제 악용(KEV) {kevHits.length}건</Badge>}
          {it.cves.length > 1 && <Badge cls="plain">CVE {it.cves.length}건</Badge>}
          {tx.mt && <Badge cls="plain">기계 번역</Badge>}
          {it.lang === "en" && tx.pending && <Badge cls="poc">번역 대기 중</Badge>}
        </div>
        {it.cves.length > 0 && (
          <div className="act"><b>CVE</b>{it.cves.slice(0, 6).map((c) => <CveLink key={c} id={c} />)}{it.cves.length > 6 && <span className="muted small">외 {it.cves.length - 6}건</span>}</div>
        )}
        <div className="foot item-foot">
          <details className="orig">
            <summary>본문 보기</summary>
            <div className="orig-body">
              {tx.orig && tx.mt && <div className="prod small">{tx.orig}</div>}
              <Body body={it.body} />
            </div>
          </details>
          <ExtLink href={it.link}>KNVD 원문 ↗</ExtLink>
          <DoneBox id={key} />
        </div>
      </div>
    </li>
  );
}

const matches = (data, it, q) => {
  if (!q) return true;
  const tx = rssText(data, it);
  return (it.title + " " + tx.title + " " + it.body + " " + it.cves.join(" ")).toLowerCase().includes(q);
};

export default function Knvd() {
  const { data, ready, loadMsg } = useApp();
  const [feed, setFeed] = useState("all");
  const [q, setQ] = useState("");
  const [shown, setShown] = useState(STEP);
  const [older, setOlder] = useState({ items: [], more: true, busy: false, err: "" });

  const feeds = data.rss.feeds || [];
  const opts = [["all", "전체"], ...feeds.map((f) => [f.name, f.label])];
  const qq = q.trim().toLowerCase();
  const all = useMemo(() => {
    const seen = new Set(), out = [];
    for (const it of data.rss.items.concat(older.items)) {
      const k = it.feed + ":" + it.id;
      if (!seen.has(k)) { seen.add(k); out.push(it); }
    }
    return out.sort((a, b) => (a.at < b.at ? 1 : a.at > b.at ? -1 : 0));
  }, [data.rss.items, older.items]);
  const arr = all.filter((it) => (feed === "all" || it.feed === feed) && matches(data, it, qq));

  const reset = (fn) => { fn(); setShown(STEP); setOlder({ items: [], more: true, busy: false, err: "" }); };

  // Everything older than the snapshot lives only in the database: page through /api/rss.
  const loadOlder = () => {
    const last = arr[arr.length - 1];
    const p = new URLSearchParams({ limit: "50" });
    if (feed !== "all") p.set("feed", feed);
    if (last) p.set("before", last.at);
    if (qq) p.set("q", q.trim());
    setOlder((o) => ({ ...o, busy: true, err: "" }));
    fetch("api/rss?" + p).then((r) => (r.ok ? r.json() : Promise.reject(new Error(r.status))))
      .then((r) => { setOlder((o) => ({ items: o.items.concat(r.items), more: r.more, busy: false, err: "" })); setShown((s) => s + r.items.length); })
      .catch(() => setOlder((o) => ({ ...o, busy: false, err: "이전 기록을 불러오지 못했습니다." })));
  };

  const totalStored = feeds.reduce((s, f) => s + (f.total || 0), 0);
  return (
    <FilterSection id="v-knvd" summary={[labelOf(opts, feed)]}>
      {(fbtn) => <>
        <PageHead title="KNVD">KISA 보안취약점 정보포털(KNVD)의 보안공지와 국내 공개 취약점입니다. RSS를 주기적으로 읽어 모두 데이터베이스에 쌓습니다.</PageHead>
        <div className="toolbar">
          {fbtn}
          <Seg label="피드" opts={opts} value={feed} onPick={(v) => reset(() => setFeed(v))} />
          <input type="search" placeholder="제목, 본문, CVE 검색" value={q} onChange={(e) => reset(() => setQ(e.target.value))} />
        </div>
        <div className="small muted">
          {feeds.map((f, i) => (
            <span key={f.name} className={f.status === "failed" ? "warn" : undefined}>
              {i ? " · " : ""}{f.label} 누적 {fmt(f.total || 0)}건
              {f.fetchedAt ? " (" + new Date(f.fetchedAt).toLocaleString("ko-KR", { month: "numeric", day: "numeric", hour: "numeric", minute: "2-digit" }) + (f.status === "failed" ? " 이후 가져오지 못함)" : " 확인)") : ""}
            </span>
          ))}
        </div>
        <ul className="list">
          {!ready && <li className="empty">{loadMsg}</li>}
          {ready && !feeds.length && <li className="empty">RSS 데이터가 아직 없습니다. worker가 첫 수집을 마치면 나타납니다.</li>}
          {ready && feeds.length > 0 && !arr.length && <li className="empty">조건에 맞는 글이 없습니다{qq ? ". 아래에서 전체 기록을 검색해 보세요." : "."}</li>}
          {arr.slice(0, shown).map((it) => <KnvdItem key={it.feed + it.id} it={it} />)}
        </ul>
        <div className="more">
          {arr.length > shown
            ? <button className="btn ghost" type="button" onClick={() => setShown((s) => s + STEP)}>더 보기 ({fmt(arr.length - shown)}건 남음)</button>
            : ready && totalStored > data.rss.items.length && older.more && (
              <button className="btn ghost" type="button" disabled={older.busy} onClick={loadOlder}>
                {older.busy ? "불러오는 중…" : qq ? "전체 기록에서 더 찾기" : "이전 기록 더 불러오기"}
              </button>
            )}
          {older.err && <span className="small muted">{older.err}</span>}
        </div>
        <p className="muted small">처음 화면에는 최근 {data.rss.days || 180}일 글이 보이고, 그보다 오래된 글은 데이터베이스에서 불러옵니다. 영어로 된 글은 LibreTranslate로 한국어 번역해 보여 주며(원문은 제목에 마우스를 올리거나 본문에서 확인), 번역이 끝나기 전에는 원문이 그대로 보입니다.</p>
      </>}
    </FilterSection>
  );
}
