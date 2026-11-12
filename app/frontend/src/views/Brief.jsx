import { useEffect, useMemo, useRef, useState } from "react";
import { useApp } from "../lib/AppContext.jsx";
import { computeVerdict, reportText } from "../lib/verdict.js";
import { copyText, daysAgo, dayLabel, enName, groupText, hasSig, isRce, kisaRelated, koOf } from "../lib/util.js";
import { Icon } from "../components/Icon.jsx";
import { Badge, CveLink, ExtLink, GroupAction, ItemAction, useFlash } from "../components/common.jsx";
import { slotLabel, SummaryBody } from "./AiHistory.jsx";
import { rssText } from "./Knvd.jsx";

export default function Brief() {
  return (
    <section id="v-brief">
      <div className="page-head"><h1>오늘</h1><p>실제 공격에 쓰이고 있는 것과 바로 위험한 것부터 보여 줍니다.</p></div>
      <Verdict />
      <AiCard />
      <div className="panel brief">
        <div className="brief-top"><h2>이번 주 새로 생긴 것</h2><span className="muted small">최근 7일, 날짜별로 새로 나온 것만 모았습니다.</span></div>
        <Timeline />
      </div>
      <div className="next">
        <a className="next-card" href="#kev"><span className="muted small">목록 보기</span><span className="next-t">실제 악용 전체 <Icon name="arrow" /></span></a>
        <a className="next-card" href="#upd"><span className="muted small">목록 보기</span><span className="next-t">제품 업데이트 <Icon name="arrow" /></span></a>
      </div>
    </section>
  );
}

// ---------- verdict
function VRow({ pill, pillText, it, kind }) {
  const { data } = useApp();
  let body;
  if (kind === "kisa") {
    const rel = kisaRelated(data, it);
    body = <>
      <div className="v-line"><ExtLink href={it.url}>{it.title}</ExtLink><span className="date">KISA {it.date}</span></div>
      <div className="ko-en">{rel.kev.length ? "같은 벤더 KEV(실제 악용) 최근 30일 " + rel.kev.length + "건. KISA 원문에서 해당 버전을 확인하세요." : "KISA 업데이트 권고. 원문에서 해당 제품·버전을 확인하세요."}</div>
    </>;
  } else if (kind === "update") {
    const gt = groupText(data, it);
    body = <>
      <div className="v-line">
        <span className="prod">{it.vendor} 보안 업데이트</span>
        <span className="muted small">{(it.products || []).slice(0, 3).join(", ")}</span>
        <span className="date">공개 {it.date}</span>
      </div>
      <div className={gt.ko ? "ko" : "ko-en"}>{gt.t}</div>
      <GroupAction g={it} />
    </>;
  } else {
    const ko = koOf(data, it.id);
    body = <>
      <div className="v-line">
        <CveLink id={it.id} />
        <span className="prod">{[it.vendor, it.product].filter(Boolean).join(" · ")}</span>
        <span className="date">{kind === "kev" ? "KEV 등재 " + it.added : "공개 " + it.published}</span>
      </div>
      <div className={ko ? "ko" : "ko-en"}>{ko || enName(it)}</div>
      <ItemAction it={it} />
    </>;
  }
  return <li><span className={"pill " + pill}>{pillText}</span><div className="v-body">{body}</div></li>;
}

function Verdict() {
  const { data, ready, loadMsg, done } = useApp();
  const v = useMemo(() => (ready ? computeVerdict(data, done) : null), [data, ready, done]);
  const [flashMsg, flash] = useFlash();
  const [fallback, setFallback] = useState(null);

  const onCopy = () => {
    const text = v ? reportText(data, v) : ""; if (!text) return;
    const fb = () => { setFallback(text); flash("아래에서 복사하세요"); };
    copyText(text).then(() => { setFallback(null); flash("복사했습니다"); }, fb);
  };
  const dateLabel = ready ? "오늘의 판정 · " + new Date(data.meta.generatedAt).toLocaleDateString("ko-KR", { month: "long", day: "numeric", weekday: "short" }) : "오늘의 판정";

  return (
    <div className="verdict" id="verdict" aria-labelledby="vHead">
      <div className="v-top">
        <div className="v-headwrap">
          <span className="v-date">{dateLabel}</span>
          <h2 className={"v-head" + (v ? " " + v.cls : "")} id="vHead">{v ? v.head : loadMsg}</h2>
          <p className="v-sub">{v ? v.sub : ""}</p>
        </div>
        <button className="icon-btn on-dark" type="button" aria-label="보고용으로 복사" title="보고용으로 복사" data-flash={flashMsg || undefined} onClick={onCopy}>
          <Icon name="copy" />
        </button>
      </div>
      <ul className="v-list">
        {v && v.shown.map((r) => <VRow key={r.kind + r.it.id} {...r} />)}
        {v && v.more.length > 0 && (
          <li className="v-old">
            <details>
              <summary>{v.more.length}건 더 보기</summary>
              <ul className="v-list">{v.more.map((r) => <VRow key={r.kind + r.it.id} {...r} />)}</ul>
            </details>
          </li>
        )}
      </ul>
      {fallback != null && <CopyFallback text={fallback} />}
    </div>
  );
}

// Shown when the clipboard API is blocked: pre-selected text to copy by hand.
function CopyFallback({ text }) {
  const ref = useRef(null);
  useEffect(() => { ref.current.focus(); ref.current.select(); }, [text]);
  return <div><textarea ref={ref} className="copyfb" readOnly aria-label="보고용 텍스트" value={text} /></div>;
}

// ---------- latest AI summary (EXAONE)
function AiCard() {
  const { summary: sm } = useApp();
  if (!sm || sm.status !== "ok" || !sm.headline) return null;
  const at = new Date(sm.generatedAt);
  const stale = sm.date !== new Date().toLocaleDateString("sv-SE", { timeZone: "Asia/Seoul" });
  return (
    <div className="ai-card">
      <div className="ai-top">
        <span className="ai-label"><Icon name="spark" />AI 요약{sm.slot ? " · " + slotLabel(sm.slot) : ""}</span>
        <span className="ai-meta">{(stale ? sm.date + " 요약 · " : "") + at.toLocaleTimeString("ko-KR", { hour: "numeric", minute: "2-digit" }) + " 작성"}</span>
      </div>
      <SummaryBody sm={sm} />
      <p className="ai-note">수집한 데이터만 보고 EXAONE이 쓴 요약입니다(매일 7시·12시·19시). 조치 전에 원문과 벤더 공지를 확인하세요. <a href="#ai">지난 요약 보기 →</a></p>
    </div>
  );
}

// ---------- weekly timeline
const EVL = { crit_active: ["악용 새로 확인", "hot"], crit_poc: ["PoC 새로 공개", "kev"], kev_ransomware: ["랜섬웨어 사용 확인", "hot"] };
const prodOf = (e) => [e.vendor, e.product].filter(Boolean).join(" · ");

function PocLines({ pocs }) {
  if (!pocs.length) return null;
  const line = (e) => <li key={"poc" + e.id}><span className="tag2 kev">PoC 새로 공개</span><CveLink id={e.id} /><span className="prod">{prodOf(e)}</span></li>;
  if (pocs.length <= 3) return pocs.map(line);
  const byV = {};
  pocs.forEach((e) => { const v = e.vendor || "기타"; (byV[v] = byV[v] || []).push(e); });
  const vs = Object.keys(byV).sort((a, b) => byV[b].length - byV[a].length);
  return (
    <li>
      <details className="poc">
        <summary>
          <span className="tag2 kev">PoC 새로 공개</span>
          {" " + pocs.length + "건 · " + vs.slice(0, 3).map((v) => v + " " + byV[v].length).join(", ") + (vs.length > 3 ? " 외 " + (vs.length - 3) + "곳" : "")}
        </summary>
        {vs.map((v) => {
          const prods = [...new Set(byV[v].map((e) => e.product).filter(Boolean))].slice(0, 4);
          return (
            <div className="pocv" key={v}>
              <b>{v + " "}</b>
              {prods.length > 0 && <span className="muted small">{prods.join(", ") + " "}</span>}
              {byV[v].slice(0, 6).map((e, i) => <span key={e.id}>{i ? " " : ""}<CveLink id={e.id} /></span>)}
              {byV[v].length > 6 && <span className="muted small">{" 외 " + (byV[v].length - 6) + "건"}</span>}
            </div>
          );
        })}
      </details>
    </li>
  );
}

function TimelineDay({ i }) {
  const { data } = useApp();
  const d = daysAgo(i), lab = dayLabel(d);
  const evs = (data.changes.find((x) => x.date === d) || {}).items || [];
  const rows = [];

  data.kev.filter((v) => v.added === d).forEach((v) => {
    const ko = koOf(data, v.id);
    rows.push(<li key={"kev" + v.id}><span className="tag2 kev">KEV 추가</span><CveLink id={v.id} /><span className="prod">{[v.vendor, v.product].join(" · ")}</span>{ko && <span className="muted">{ko}</span>}</li>);
  });
  const pocs = [];
  evs.forEach((e, j) => {
    const m = EVL[e.type]; if (!m) return;
    if (e.type === "crit_poc") { pocs.push(e); return; }
    rows.push(<li key={"ev" + j}><span className={"tag2 " + m[1]}>{m[0]}</span><CveLink id={e.id} /><span className="prod">{prodOf(e)}</span></li>);
  });
  if (pocs.length) rows.push(<PocLines key="pocs" pocs={pocs} />);
  data.kisa.filter((k) => k.date === d).forEach((k) => {
    const rel = kisaRelated(data, k);
    rows.push(<li key={"kisa" + k.ntt}><span className="tag2 kisa">KISA</span><ExtLink href={k.url}>{k.title}</ExtLink>{rel.kev.length > 0 && <Badge cls="kev">같은 벤더 KEV {rel.kev.length}건</Badge>}</li>);
  });
  data.rss.items.filter((r) => r.date === d).slice(0, 6).forEach((r) => {
    const tx = rssText(data, r);
    rows.push(<li key={"rss" + r.feed + r.id}><span className={"tag2 " + (r.cvss >= 9 ? "hot" : "kisa")}>KNVD</span><ExtLink href={r.link}>{tx.title}</ExtLink>{r.cvss != null && <Badge cls="plain">CVSS {r.cvss}</Badge>}</li>);
  });
  const rssMore = data.rss.items.filter((r) => r.date === d).length - 6;
  if (rssMore > 0) rows.push(<li key="rssmore"><span className="tag2">KNVD</span><a className="muted" href="#knvd">그 외 {rssMore}건</a></li>);
  const ud = data.updates.filter((g) => g.date === d);
  const keyU = ud.filter((g) => g.kev.length || (g.maxScore >= 9 && g.nRemote) || koOf(data, g.gid))
    .sort((a, b) => (b.kev.length - a.kev.length) || (b.maxScore - a.maxScore)).slice(0, 4);
  keyU.forEach((g) => {
    rows.push(<li key={"u" + g.gid}><span className={"tag2 " + (g.kev.length ? "hot" : "kisa")}>업데이트</span><span className="prod">{g.vendor + " " + (g.products || []).slice(0, 2).join(", ")}</span><span className="muted">{groupText(data, g).t}</span></li>);
  });
  if (ud.length > keyU.length) {
    const restV = ud.filter((g) => !keyU.includes(g)).map((g) => g.vendor);
    rows.push(<li key="urest"><span className="tag2">업데이트</span><span className="muted">{"그 외 " + restV.length + "곳: " + restV.slice(0, 8).join(", ") + (restV.length > 8 ? " 등" : "")}</span></li>);
  }
  const cd = data.critical.filter((c) => c.published === d);
  const hotd = cd.filter((c) => isRce(c) && hasSig(c));
  if (cd.length) {
    rows.push(
      <li key="crit">
        <span className={"tag2" + (hotd.length ? " hot" : "")}>신규 Critical</span>
        {cd.length + "건 공개" + (hotd.length ? ", 그중 즉시 위험 " + hotd.length + "건: " : "")}
        {hotd.slice(0, 2).map((c, j) => {
          const nm = [c.product, c.vendor].filter((v) => v && v !== "n/a")[0] || "";
          return <span key={c.id}>{j ? ", " : ""}<CveLink id={c.id} />{nm ? " " + nm : ""}</span>;
        })}
        {hotd.length > 2 ? " 외 " + (hotd.length - 2) + "건" : ""}
      </li>
    );
  }
  return (
    <div className="tl-day">
      <div className="tl-date">{lab.md}<small>{(i === 0 ? "오늘 " : i === 1 ? "어제 " : "") + lab.wd + "요일"}</small></div>
      <ul className="tl-items">{rows.length ? rows : <li className="tl-quiet">새로 생긴 항목 없음</li>}</ul>
    </div>
  );
}

function Timeline() {
  const { ready, loadMsg } = useApp();
  return (
    <div className="tl">
      {ready ? [0, 1, 2, 3, 4, 5, 6].map((i) => <TimelineDay key={i} i={i} />) : <p className="muted">{loadMsg}</p>}
    </div>
  );
}
