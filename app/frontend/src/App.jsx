import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { REF_VIEWS, useApp } from "./lib/AppContext.jsx";
import { filtered, NO_CF, NO_KF, PAGE } from "./lib/list.js";
import { daysAgo, LS } from "./lib/util.js";
import { Icon } from "./components/Icon.jsx";
import Brief from "./views/Brief.jsx";
import AiHistory from "./views/AiHistory.jsx";
import ListView from "./views/ListView.jsx";
import Knvd from "./views/Knvd.jsx";
import Updates from "./views/Updates.jsx";
import Packages from "./views/Packages.jsx";
import Kisa from "./views/Kisa.jsx";
import Insights from "./views/Insights.jsx";
import Sources from "./views/Sources.jsx";
import Routine from "./views/Routine.jsx";

export default function App() {
  return (
    <div className="app">
      <TopBar />
      <Sidebar />
      <Main />
    </div>
  );
}

// ---------- top bar
function TopBar() {
  const { data, ready, done, list, setList, setView } = useApp();
  const [q, setQ] = useState("");

  // KEV first, then 90-day Critical
  const onSearch = (e) => {
    e.preventDefault();
    const s = q.trim().toLowerCase(); if (!s || !ready) return;
    const next = { ...list, q: s, hideDone: false, kf: NO_KF, cf: NO_CF, range: { kev: 90, critical: 90 }, shown: PAGE };
    setList(next);
    setView(filtered(data, next, done, "kev").length ? "kev" : "critical");
    document.getElementById("main")?.scrollIntoView({ block: "start" });
  };

  return (
    <header className="topbar">
      <a className="logo" href="#brief" aria-label="KCN 홈"><Icon name="logo" /><span>KCN</span></a>
      <Fresh />
      <form className="search" role="search" onSubmit={onSearch}>
        <Icon name="search" />
        <input type="search" placeholder="CVE 번호나 제품 이름으로 찾기" aria-label="취약점 검색" autoComplete="off" value={q} onChange={(e) => setQ(e.target.value)} />
      </form>
      <div className="top-actions"><ThemeButton /></div>
    </header>
  );
}

function Fresh() {
  const { data, ready } = useApp();
  if (!ready) return <span className="fresh" aria-live="polite"><span className="dot" aria-hidden="true" /><span>불러오는 중…</span></span>;
  const t = new Date(data.meta.generatedAt), hrs = (Date.now() - t.getTime()) / 36e5;
  const s = t.toLocaleString("ko-KR", { month: "long", day: "numeric", hour: "numeric", minute: "2-digit" });
  return (
    <span className={"fresh" + (hrs > 36 ? " stale" : "")} aria-live="polite">
      <span className="dot" aria-hidden="true" />
      <span>{s + " 기준" + (hrs > 36 ? " · 갱신이 " + Math.floor(hrs / 24) + "일째 멈춰 있습니다" : "")}</span>
    </span>
  );
}

function ThemeButton() {
  const root = document.documentElement;
  const cur = () => root.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  const [theme, setTheme] = useState(cur);
  const flip = () => {
    const t = cur() === "dark" ? "light" : "dark";
    root.dataset.theme = t; LS.set("kcn.theme", t); setTheme(t);
  };
  return (
    <button className="icon-btn" type="button" aria-label="밝은 화면/어두운 화면 전환" onClick={flip}>
      <Icon name={theme === "dark" ? "sun" : "moon"} />
    </button>
  );
}

// ---------- sidebar
const TABS = [
  ["brief", "today", "오늘"],
  ["kev", "flame", "실제 악용"],
  ["knvd", "flag", "KNVD"],
  ["upd", "update", "제품 업데이트"],
  ["pkg", "box", "패키지"],
  ["kisa", "flag", "KISA 권고"],
  ["critical", "shield", "고위험 신규"],
  ["ai", "spark", "AI 요약 기록"],
  ["sources", "book", "자료", "insights"],
];

function counts(data) {
  if (!data.meta) return {};
  const d14 = daysAgo(14), d30 = daysAgo(30);
  return {
    kev: data.kev.length,
    critical: data.critical.filter((c) => c.published >= d14).length,
    upd: data.updates.filter((g) => g.date >= d30).length,
    pkg: data.pkg.ghsa.length || "",
    kisa: data.kisa.filter((k) => k.date >= d30).length,
    knvd: data.rss.items.filter((r) => r.date >= d30).length || "",
  };
}

function Sidebar() {
  const { data, view, setView } = useApp();
  const nav = useRef(null);
  const [fade, setFade] = useState(false);
  const tabKey = REF_VIEWS.includes(view) ? "insights" : view;
  const c = counts(data);

  // Phones: the tab row scrolls sideways; fade the edge and keep the selected tab in view.
  useLayoutEffect(() => {
    const t = nav.current; if (!t) return;
    const sel = t.querySelector('[aria-selected="true"]');
    if (sel && t.scrollWidth > t.clientWidth) {
      const l = sel.offsetLeft - 16, r = sel.offsetLeft + sel.offsetWidth + 16;
      if (l < t.scrollLeft) t.scrollLeft = l; else if (r > t.scrollLeft + t.clientWidth) t.scrollLeft = r - t.clientWidth;
    }
    setFade(t.scrollWidth - t.clientWidth - t.scrollLeft > 6);
  }, [tabKey]);
  useEffect(() => {
    const t = nav.current;
    const on = () => setFade(t.scrollWidth - t.clientWidth - t.scrollLeft > 6);
    t.addEventListener("scroll", on, { passive: true }); window.addEventListener("resize", on);
    return () => { t.removeEventListener("scroll", on); window.removeEventListener("resize", on); };
  }, []);

  const m = data.meta;
  const kisaWarn = m && !(m.kisaStatus === "ok" || m.kisaStatus === "skipped")
    ? "KISA 공지를 이번에 가져오지 못했습니다" + (m.kisaFetchedAt ? " (마지막 성공 " + new Date(m.kisaFetchedAt).toLocaleDateString("ko-KR", { month: "long", day: "numeric" }) + ")" : "")
    : "";

  return (
    <aside className="sidebar">
      <nav ref={nav} className={"tabs side-nav" + (fade ? " tfade" : "")} role="tablist" aria-label="보기">
        {TABS.map(([v, icon, label, key]) => (
          <button key={v} className="tab" role="tab" type="button" aria-selected={tabKey === (key || v)} onClick={() => setView(v)}>
            <Icon name={icon} /><span className="lbl">{label}</span>{c[v] !== undefined && c[v] !== "" && <span className="cnt">{c[v]}</span>}
          </button>
        ))}
      </nav>
      <details className="side-group gloss">
        <summary>용어가 낯설다면</summary>
        <dl>
          <div><dt>실제 악용 (KEV)</dt><dd>미국 CISA가 "실제 공격에 쓰였다"고 확인한 취약점 목록. 점수와 상관없이 가장 먼저 처리합니다.</dd></div>
          <div><dt>CVSS 점수</dt><dd>0~10점 심각도. 9.0 이상이 Critical. 점수가 높아도 실제 공격이 없을 수 있고, 반대도 있습니다.</dd></div>
          <div><dt>PoC 공개</dt><dd>공격 방법을 보여 주는 코드가 공개됨. 곧 실제 공격으로 이어지기 쉽습니다.</dd></div>
          <div><dt>인증 없이 원격</dt><dd>로그인 없이 네트워크 너머에서 공격할 수 있음. 외부에 열린 서비스라면 특히 급합니다.</dd></div>
          <div><dt>경계 장비</dt><dd>VPN·방화벽·공유기처럼 인터넷과 내부망 사이에 있는 장비. 공개 직후 대량 스캔이 시작됩니다.</dd></div>
          <div><dt>KNVD</dt><dd>KISA 보안취약점 정보포털. 국내 제품 취약점과 보안공지를 한국어로 냅니다.</dd></div>
          <div><dt>확인함</dt><dd>처리했거나 해당 없음을 확인한 항목. 오늘의 판정에서 빠집니다(이 브라우저에만 저장).</dd></div>
        </dl>
      </details>
      {kisaWarn && <p className="fresh-sub">{kisaWarn}</p>}
    </aside>
  );
}

// ---------- main
const REF_NAV = [["sources", "정보원"], ["routine", "대응 루틴"], ["insights", "인사이트"]];

function Main() {
  const { view, setView } = useApp();
  return (
    <main className="main" id="main">
      {REF_VIEWS.includes(view) && (
        <div className="seg refnav" role="group" aria-label="자료 종류">
          {REF_NAV.map(([v, l]) => <button key={v} type="button" aria-pressed={v === view} onClick={() => setView(v)}>{l}</button>)}
        </div>
      )}
      {view === "brief" && <Brief />}
      {view === "ai" && <AiHistory />}
      {(view === "kev" || view === "critical") && <ListView key={view} kind={view} />}
      {view === "knvd" && <Knvd />}
      {view === "upd" && <Updates />}
      {view === "pkg" && <Packages />}
      {view === "kisa" && <Kisa />}
      {view === "insights" && <Insights />}
      {view === "sources" && <Sources />}
      {view === "routine" && <Routine />}

      <p className="muted small">서버에서 정해진 일정에 자동 갱신됩니다(CVE·KEV 매일, KNVD RSS 30분마다, AI 요약 7시·12시·19시). 한국어 설명은 LibreTranslate 기계 번역이라 어색할 수 있으니 원문(영문)과 벤더 공지를 함께 확인하세요. 데이터: CISA KEV(GitHub 공식 미러), CVE List V5(CVEProject/cvelistV5), CISA Vulnrichment(SSVC), KISA KNVD·보호나라. CVSS는 CNA 점수를 우선하고, 없으면 CISA ADP 점수를 씁니다. "경계 장비"는 벤더·제품명 기반 추정입니다. 조치 판단은 벤더 공지로 최종 확인하세요.</p>
      <footer className="site-foot">
        <span>만들고 관리하는 사람</span>
        <a href="https://github.com/cpprhtn" target="_blank" rel="noopener">GitHub · cpprhtn ↗</a>
      </footer>
    </main>
  );
}
