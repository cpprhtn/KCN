import { useMemo } from "react";
import { useApp } from "../lib/AppContext.jsx";
import { PAGE } from "../lib/list.js";
import { copyText, fmt, koOf, mmdd, uniq } from "../lib/util.js";
import { Badge, CveLink, DoneBox, ExtLink, FilterSection, labelOf, PageHead, Seg, useFlash } from "../components/common.jsx";

const KINDS = [["adv", "취약점 (High·Critical)"], ["mal", "악성 패키지"]];
const SEVS = [["all", "High+Critical"], ["C", "Critical만"]];

// Upgrade command per ecosystem; names and versions are validated before they reach a shell line.
function pkgCmds(p) {
  const out = [], n = p.n;
  if (!/^[@A-Za-z0-9._/-]{1,120}$/.test(n)) return out;
  (p.fix || []).slice(0, 2).forEach((f) => {
    if (!/^[0-9][0-9A-Za-z.+_-]{0,40}$/.test(f)) return;
    const c = {
      npm: "npm i " + n + "@" + f,
      PyPI: 'pip install -U "' + n + ">=" + f + '"',
      Go: "go get " + n + "@v" + f,
      Packagist: 'composer require "' + n + ":>=" + f + '"',
      NuGet: "dotnet add package " + n + " --version " + f,
      RubyGems: "bundle update " + n,
      "crates.io": "cargo update -p " + n,
    }[p.e];
    if (c) out.push({ v: f, cmd: c });
  });
  return out;
}
const pkgTerm = (it) => (it.p ? it.p.map((x) => x.n) : [it.n]).join(" ").toLowerCase();
const byPub = (a, b) => (a.pub < b.pub ? 1 : a.pub > b.pub ? -1 : 0);

export default function Packages() {
  const { data, ready, loadMsg, pkg, setPkg } = useApp();
  const set = (patch) => setPkg((s) => ({ ...s, ...patch, shown: PAGE }));
  const adv = pkg.kind === "adv";
  const src = adv ? data.pkg.ghsa : data.pkg.mal;

  const ecoCount = useMemo(() => {
    const m = {};
    src.forEach((it) => (adv ? it.p.map((x) => x.e) : [it.e]).forEach((e) => { m[e] = (m[e] || 0) + 1; }));
    return m;
  }, [src, adv]);

  const arr = useMemo(() => {
    const q = pkg.q.trim().toLowerCase();
    const a = src.filter((it) => {
      if (adv && pkg.sev === "C" && it.sev !== "C") return false;
      if (pkg.eco && (adv ? it.p.every((x) => x.e !== pkg.eco) : it.e !== pkg.eco)) return false;
      if (q && !pkgTerm(it).includes(q) && !(it.s || "").toLowerCase().includes(q) && !(it.cve || it.id).toLowerCase().includes(q)) return false;
      return true;
    });
    return adv ? a.sort((x, y) => ((y.kev ? 1 : 0) - (x.kev ? 1 : 0)) || ((y.sev === "C" ? 1 : 0) - (x.sev === "C" ? 1 : 0)) || byPub(x, y)) : a.sort(byPub);
  }, [src, adv, pkg.sev, pkg.eco, pkg.q]);

  return (
    <FilterSection id="v-pkg" summary={[labelOf(KINDS, pkg.kind), adv ? labelOf(SEVS, pkg.sev) : null].filter(Boolean)}>
      {(fbtn) => <>
        <PageHead title="패키지">npm·PyPI 등 오픈소스 패키지의 고위험 권고와 악성 패키지입니다.</PageHead>
        <div className="toolbar">
          {fbtn}
          <Seg label="종류" opts={KINDS} value={pkg.kind} onPick={(v) => set({ kind: v, eco: "" })} />
          <Seg label="심각도" opts={SEVS} value={pkg.sev} onPick={(v) => set({ sev: v })} hidden={!adv} />
          <input type="search" placeholder="패키지명, CVE 검색" value={pkg.q} onChange={(e) => set({ q: e.target.value })} />
        </div>
        <div className="flt" id="pkgEco">
          <span className="lab">생태계</span>
          {Object.keys(ecoCount).sort((a, b) => ecoCount[b] - ecoCount[a]).slice(0, 8).map((e) => (
            <button key={e} className="fchip" type="button" aria-pressed={pkg.eco === e} onClick={() => set({ eco: pkg.eco === e ? "" : e })}>{e + " " + ecoCount[e]}</button>
          ))}
        </div>
        <div className="small muted">
          {ready && (adv ? "GitHub 검수 보안 권고 중 High·Critical, 최근 " + (data.pkg.ghsaDays || 30) + "일" : "OpenSSF 악성 패키지 DB, 최근 " + (data.pkg.malDays || 14) + "일") + " · " + fmt(arr.length) + "건"}
        </div>
        <ul className="list">
          {!ready && <li className="empty">{loadMsg}</li>}
          {ready && !adv && <li className="note">악성 패키지가 설치돼 있다면 해당 PC나 서버 전체가 침해된 것으로 보고, 패키지를 지운 뒤 거기 저장된 키·토큰·비밀번호를 다른 기기에서 교체하세요. 이름이 비슷한 가짜(타이포스쿼팅)가 대부분이라 목록 전체를 볼 필요는 없고, 내가 쓰는 패키지 이름이 있는지만 확인하면 됩니다.</li>}
          {ready && !arr.length && <li className="empty">조건에 맞는 항목이 없습니다.</li>}
          {arr.slice(0, pkg.shown).map((it) => <PkgItem key={it.id} it={it} adv={adv} />)}
          {arr.length > pkg.shown && (
            <li className="more"><button className="btn ghost" type="button" onClick={() => setPkg((s) => ({ ...s, shown: s.shown + PAGE }))}>
              더 보기 ({fmt(arr.length - pkg.shown)}건 남음)
            </button></li>
          )}
        </ul>
        <p className="muted small">데이터: GitHub Advisory Database(검수된 권고), OpenSSF malicious-packages. 내 프로젝트 전체를 검사하려면 자료의 osv-scanner를 쓰세요.</p>
      </>}
    </FilterSection>
  );
}

function CmdCopy({ cmd }) {
  const [msg, flash] = useFlash();
  return (
    <span className="cmdw">
      <code className="cmd">{cmd}</code>
      <button className="btn ghost sm" type="button" onClick={() => copyText(cmd).then(() => flash("복사됨", 1500), () => flash("복사 안 됨", 1500))}>{msg || "복사"}</button>
    </span>
  );
}

function PkgItem({ it, adv }) {
  const { data, done } = useApp();
  const ko = koOf(data, it.id), key = "pkg:" + it.id;
  const fx = adv ? it.p.flatMap((x) => x.fix.map((f) => x.n + " " + f)) : [];
  const cmds = adv ? it.p.flatMap(pkgCmds).slice(0, 2) : [];
  return (
    <li className={"item" + (done[key] ? " done" : "")}>
      <div className={"score " + (adv && it.sev !== "C" ? "kev" : "crit")}><b>{adv ? (it.sev === "C" ? "CRIT" : "HIGH") : "MAL"}</b><span>{mmdd(it.pub)}</span></div>
      <div className="body">
        <div className="line1">
          {adv ? <>
            <ExtLink href={"https://github.com/advisories/" + encodeURIComponent(it.id)} className="cve">{it.id}</ExtLink>
            {it.p.map((x, i) => <span key={i} className="prod" title={x.e}>{x.n}</span>)}
            {it.np > it.p.length && <span className="muted small">외 {it.np - it.p.length}개</span>}
          </> : <>
            <ExtLink href={"https://osv.dev/vulnerability/" + encodeURIComponent(it.id)} className="prod">{it.n}</ExtLink>
            <span className="muted small">{it.id}</span>
          </>}
          <span className="date">{it.pub}</span>
        </div>
        {adv && (ko || it.s) && <div className="desc" title={ko && it.s ? it.s : undefined}>{ko || it.s}</div>}
        <div className="badges">
          {adv ? <>
            {it.kev && <Badge cls="kev">실제 악용 (KEV)</Badge>}
            {uniq(it.p.map((x) => x.e)).map((e) => <Badge key={e} cls="plain">{e}</Badge>)}
            {fx.length ? <Badge cls="plain mono">수정: {fx.slice(0, 2).join(", ") + (fx.length > 2 ? " …" : "")}</Badge> : <Badge cls="plain">수정 버전 미공개</Badge>}
          </> : <><Badge cls="rw">악성코드 포함</Badge><Badge cls="plain">{it.e}</Badge></>}
        </div>
        {cmds.length > 0 && (
          <div className="act cmdrow">
            {cmds.map((k) => <CmdCopy key={k.cmd} cmd={k.cmd} />)}
            {cmds.length > 1 && <span className="muted small">주 버전이 여러 개면 쓰는 쪽에 맞는 줄을 고르세요.</span>}
          </div>
        )}
        <div className="foot">
          {adv && it.cve && <CveLink id={it.cve} />}
          {!adv && it.g && <ExtLink href={"https://github.com/advisories/" + encodeURIComponent(it.g)}>{it.g}</ExtLink>}
          <DoneBox id={key} />
        </div>
      </div>
    </li>
  );
}
