import { useEffect, useMemo, useState } from "react";
import { useApp } from "../lib/AppContext.jsx";
import { downloadCsv, filtered, FILTERS, inRange, PAGE, RANGES } from "../lib/list.js";
import { cweName, enLead, fmt, isPoc, isRce, koOf, lagText } from "../lib/util.js";
import { Badge, DoneBox, ExtLink, FilterSection, ItemAction, labelOf, PageHead, Seg, useFlash } from "../components/common.jsx";

const SORTS = [["risk", "위험 신호순"], ["new", "최신순"]];
const TEXT = {
  kev: {
    title: "실제 악용", desc: "미국 CISA가 실제 공격에 쓰였다고 확인한 취약점입니다.",
    note: "KEV는 실제 공격에 쓰인 것이 확인된 취약점만 모은 목록입니다. 등재일은 최초 악용일이 아니라 CISA가 확인해 올린 날입니다.",
  },
  critical: {
    title: "고위험 신규", desc: "최근 공개된 CVSS 9.0 이상 취약점입니다. 악용 신호가 있는 것부터 보여 줍니다.",
    note: "CVSS 9.0 이상만 표시합니다. 위험 신호순은 KEV·SSVC 악용 상태·원격 무인증 조건·자동화 가능 여부를 합산해 정렬합니다. SSVC 평가는 CISA가 붙이며, 공개 직후에는 비어 있을 수 있습니다.",
  },
};

export default function ListView({ kind }) {
  const { data, ready, loadMsg, done, list, setList } = useApp();
  const [qInput, setQInput] = useState(list.q);
  const [csvMsg, flashCsv] = useFlash();

  // top search writes list.q directly; keep the box in sync
  useEffect(() => { setQInput(list.q); }, [list.q]);
  useEffect(() => {
    const q = qInput.trim().toLowerCase();
    if (q === list.q) return;
    const t = setTimeout(() => setList((s) => ({ ...s, q, shown: PAGE })), 150);
    return () => clearTimeout(t);
  }, [qInput]); // eslint-disable-line react-hooks/exhaustive-deps

  const arr = useMemo(() => (ready ? filtered(data, list, done, kind) : []), [data, ready, list, done, kind]);
  const total = useMemo(() => (ready ? inRange(data, kind, list.range[kind]).length : 0), [data, ready, kind, list.range]);

  const fkey = kind === "kev" ? "kf" : "cf";
  const fs = list[fkey];
  const upd = (patch) => setList((s) => ({ ...s, ...patch, shown: PAGE }));
  const T = TEXT[kind];

  return (
    <FilterSection id="v-list" summary={[labelOf(RANGES[kind], list.range[kind]), labelOf(SORTS, list.sort)]}>
      {(fbtn) => <>
        <PageHead title={T.title}>{T.desc}</PageHead>
        <div className="toolbar">
          {fbtn}
          <Seg label="기간" opts={RANGES[kind]} value={list.range[kind]} onPick={(v) => upd({ range: { ...list.range, [kind]: v } })} />
          <Seg label="정렬" opts={SORTS} value={list.sort} onPick={(v) => setList((s) => ({ ...s, sort: v }))} />
          <input type="search" placeholder="CVE, 벤더, 제품, CWE 검색" value={qInput} onChange={(e) => setQInput(e.target.value)} />
        </div>
        <div className="flt" id="flt">
          <span className="lab">조건</span>
          {FILTERS[kind].map(([k, l]) => (
            <button key={k} className="fchip" type="button" aria-pressed={!!fs[k]} onClick={() => upd({ [fkey]: { ...fs, [k]: !fs[k] } })}>{l}</button>
          ))}
        </div>
        <div className="listhead">
          <span className="small muted">{ready ? "최근 " + list.range[kind] + "일 " + fmt(total) + "건 중 " + fmt(arr.length) + "건 표시" : ""}</span>
          <span className="flt">
            <label className="tog"><input type="checkbox" checked={list.hideDone} onChange={(e) => setList((s) => ({ ...s, hideDone: e.target.checked }))} /> 확인한 항목 숨기기</label>
            <button className="btn ghost sm" type="button" disabled={!arr.length} onClick={() => { downloadCsv(kind, arr); flashCsv("저장함", 2000); }}>{csvMsg || "CSV 내보내기"}</button>
          </span>
        </div>
        <ul className="list">
          {!ready && <li className="empty">{loadMsg}</li>}
          {ready && !arr.length && <li className="empty">조건에 맞는 항목이 없습니다. 조건 칩을 일부 해제해 보세요.</li>}
          {arr.slice(0, list.shown).map((it) => <Item key={it.id} it={it} kind={kind} />)}
        </ul>
        {arr.length > list.shown && (
          <div className="more"><button className="btn ghost" type="button" onClick={() => setList((s) => ({ ...s, shown: s.shown + PAGE }))}>더 보기</button></div>
        )}
        <p className="muted small">{T.note}</p>
      </>}
    </FilterSection>
  );
}

const REF_LINKS = [
  ["https://www.cve.org/CVERecord?id=", "CVE 레코드"],
  ["https://nvd.nist.gov/vuln/detail/", "NVD"],
  ["https://api.first.org/data/v1/epss?cve=", "EPSS 점수"],
  ["https://osv.dev/vulnerability/", "OSV"],
  ["https://euvd.enisa.europa.eu/search?text=", "EUVD"],
  ["https://github.com/search?type=code&q=", "GitHub PoC 검색"],
];

function Item({ it, kind }) {
  const { data, done } = useApp();
  const kev = kind === "kev";
  const ko = koOf(data, it.id), en = enLead(it);
  const lt = lagText(it.lagDays);

  const badges = [];
  if (kev) {
    if (it.ransomware === "Known") badges.push(<Badge key="rw" cls="rw">랜섬웨어에 쓰임</Badge>);
    if (it.forensic) badges.push(<Badge key="fo" cls="rw">침해 흔적도 점검</Badge>);
    if (it.lagDays != null && it.lagDays <= 7) badges.push(<Badge key="lag" cls="kev">{lt}</Badge>);
  } else {
    if (it.kev) badges.push(<Badge key="kev" cls="rw">실제 악용</Badge>);
    else if (it.exploitation === "active") badges.push(<Badge key="act" cls="rw">악용 확인</Badge>);
    else if (isPoc(it)) badges.push(<Badge key="poc" cls="poc">PoC 공개</Badge>);
    if (isRce(it)) badges.push(<Badge key="rce" cls="plain">인증 없이 원격</Badge>);
  }
  if (it.edge) badges.push(<Badge key="edge" cls="plain">경계 장비</Badge>);

  const meta = [];
  if (kev) {
    if (lt && !(it.lagDays <= 7)) meta.push(<Badge key="lt" cls="plain">{lt}</Badge>);
    if (it.cwes && it.cwes[0]) meta.push(<Badge key="cwe" cls="plain">{cweName(it.cwes[0])}</Badge>);
    if (it.due) meta.push(<Badge key="due" cls="plain">미 연방기관 조치기한 {it.due}</Badge>);
  } else {
    if (it.automatable === "yes") meta.push(<Badge key="auto" cls="plain">공격 자동화 가능</Badge>);
    if (it.cwe) meta.push(<Badge key="cwe" cls="plain">{cweName(it.cwe)}</Badge>);
    if (it.scoreSource && it.scoreSource !== "CNA") meta.push(<Badge key="src" cls="plain">점수 출처: {it.scoreSource.replace("ADP:", "")}</Badge>);
  }

  return (
    <li className={"item " + (kev ? "is-kev" : "is-crit") + (done[it.id] ? " done" : "")}>
      <div className={"score " + (kev ? "kev" : "crit")}>
        {kev ? <><b>악용</b><span>{it.score != null ? "CVSS " + Number(it.score).toFixed(1) : "점수 없음"}</span></>
             : <><b>{Number(it.score).toFixed(1)}</b><span>CVSS</span></>}
      </div>
      <div className="body">
        <div className="line1">
          <span className="prod">{[it.vendor, it.product].filter((x) => x && x !== "n/a").join(" · ") || it.id}</span>
          <span className="date">{kev ? "등재 " + it.added : "공개 " + it.published}</span>
        </div>
        <p className={ko ? "ko" : "ko-en"} title={ko && en ? en : undefined}>{ko || en}</p>
        {badges.length > 0 && <div className="badges">{badges}</div>}
        <ItemAction it={it} />
        <div className="foot item-foot">
          <details className="orig">
            <summary><span className="mono cid">{it.id}</span> 원문·세부 정보</summary>
            <div className="orig-body">
              {kev && it.name && <div className="prod small">{it.name}</div>}
              {it.summary && (ko || it.summary !== en) && <p className="desc">{it.summary}</p>}
              {meta.length > 0 && <div className="badges">{meta}</div>}
              {!kev && it.vector && <div className="small muted mono vec">{it.vector}</div>}
              <div className="foot">
                {REF_LINKS.map(([u, l]) => <ExtLink key={l} href={u + encodeURIComponent(it.id)}>{l}</ExtLink>)}
              </div>
            </div>
          </details>
          {!(it.refs && it.refs.length) && (
            <ExtLink href={"https://www.google.com/search?q=" + encodeURIComponent(it.id + " " + (it.vendor || "") + " advisory")}>벤더 공지 찾기 ↗</ExtLink>
          )}
          <DoneBox id={it.id} />
        </div>
      </div>
    </li>
  );
}
