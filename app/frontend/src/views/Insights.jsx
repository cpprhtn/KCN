import { useApp } from "../lib/AppContext.jsx";
import { NO_CF } from "../lib/list.js";
import { cweName, fmt, pct } from "../lib/util.js";
import { Columns, HBars, Legend, TableView } from "../components/Charts.jsx";
import { PageHead } from "../components/common.jsx";

function Card({ title, lead, why, wide, children }) {
  return (
    <div className={"card" + (wide ? " wide" : "")}>
      <h3>{title}</h3>
      {lead && <p className="lead">{lead}</p>}
      {why && <p className="why">{why}</p>}
      {children}
    </div>
  );
}

const OC = ["var(--o1)", "var(--o2)", "var(--o3)", "var(--o4)", "var(--o5)"];
const sum = (a, f) => a.reduce((s, x) => s + f(x), 0);

export default function Insights() {
  const { data, ready, loadMsg, setList, setView } = useApp();
  const I = data.ins;
  return (
    <section id="v-insights">
      <PageHead title="인사이트">최근 1년 실제 악용과 최근 2주 고위험 취약점의 흐름입니다.</PageHead>
      <div className="igrid">
        {!ready || !I ? <div className="card wide"><p className="muted">{loadMsg}</p></div> : <Cards I={I} meta={data.meta} onFunnel={() => {
          setList((s) => ({ ...s, cf: { ...NO_CF, rce: true, sig: true }, range: { ...s.range, critical: 14 }, sort: "risk" }));
          setView("critical");
          window.scrollTo({ top: 0 });
        }} />}
      </div>
    </section>
  );
}

function Cards({ I, meta, onFunnel }) {
  // 1. funnel
  const F = I.critFunnel, fAll = F[0].count, fLast = F[F.length - 1].count, S = I.critSsvc;
  // 2. lag
  const L = I.kevLagDist, lt = sum(L, (b) => b.count), fast = L[0].count + L[1].count, old = L[4].count;
  // 3. severity
  const SV = I.kevSeverity, st = sum(SV, (s) => s.count), nonCrit = st - SV[0].count;
  // 4. monthly
  const M = I.kevMonthly, s12 = sum(M.slice(-12), (m) => m.total), p12 = sum(M.slice(0, 12), (m) => m.total), r12 = sum(M.slice(-12), (m) => m.ransomware);
  // 7. daily
  const D = I.critDaily, peak = D.reduce((m, d) => (d.count > m.count ? d : m), D[0]), topV = I.critVendors[0];
  const thisYear = new Date().getFullYear();

  return <>
    <Card wide title="신규 Critical 중 실제로 먼저 볼 것"
      lead={<>최근 {meta.windowCveDays}일 CVSS 9.0+ <b>{fmt(fAll)}건</b> 중 원격·무인증·무조작이면서 악용 신호까지 있는 건 <b>{fmt(fLast)}건({pct(fLast, fAll)}%)</b>입니다.</>}
      why="점수만으로 줄 세우면 수백 건이 같은 우선순위가 됩니다. 공격 조건(CVSS 벡터)과 악용 신호(SSVC·KEV)를 겹치면 이번 주에 볼 목록이 한 자릿수~두 자릿수로 줄어듭니다.">
      <HBars rows={F.map((s, i) => ({ label: s.label, count: s.count, color: OC[i] }))} total={fAll} />
      <button className="btn sm" type="button" style={{ width: "max-content" }} onClick={onFunnel}>이 {fLast}건 목록으로 보기</button>
      <p className="src">SSVC(CISA 평가) 기준: 평가된 {fmt(S.rated)}건 중 악용 확인 {fmt(S.exploitation.active || 0)} · PoC {fmt(S.exploitation.poc || 0)} · 자동화 가능 {fmt(S.automatableYes)} · 자동화 가능+완전 장악 {fmt(S.autoAndTotal)}건. 평가 전 {fmt(S.exploitation.unknown || 0)}건.</p>
      <TableView head={["단계", "건수"]} rows={F.map((s) => [s.label, s.count])} />
    </Card>

    <Card title="공개에서 KEV 등재까지"
      lead={<>최근 12개월 KEV <b>{fmt(lt)}건</b> 중 <b>{pct(fast, lt)}%</b>는 공개 후 7일 안에 등재됐고, <b>{pct(old, lt)}%</b>는 공개된 지 1년이 넘은 취약점이었습니다.</>}
      why="패치를 빨리 하는 것과 오래된 미패치 자산을 정리하는 것, 둘 다 필요하다는 뜻입니다. 등재일은 최초 악용일보다 늦으므로 실제 여유는 이보다 짧습니다.">
      <Columns items={L.map((b) => ({ x: b.label, xl: b.label, segs: [{ v: b.count }] }))} />
      <p className="src">중앙값 {I.kevLagMedian != null ? fmt(I.kevLagMedian) + "일" : "–"} · CVE 레코드 공개일과 KEV 등재일의 차이</p>
      <TableView head={["구간", "건수", "비율"]} rows={L.map((b) => [b.label, b.count, pct(b.count, lt) + "%"])} />
    </Card>

    <Card title="CVSS만 보면 놓치는 KEV"
      lead={<>최근 12개월 KEV의 <b>{pct(nonCrit, st)}%</b>는 CVSS Critical(9.0+)이 아니었습니다. High 이하 <b>{fmt(nonCrit)}건</b>도 실제 공격에 쓰였습니다.</>}
      why={"\"Critical만 긴급 패치\" 같은 점수 기준 SLA는 실제 공격의 상당 부분을 뒤로 미룹니다. KEV 등재 자체를 별도 트리거로 두는 게 안전합니다."}>
      <HBars rows={SV.map((s) => ({ label: s.label, count: s.count }))} total={st} />
      <TableView head={["심각도", "건수"]} rows={SV.map((s) => [s.label, s.count])} />
    </Card>

    <Card wide title="월별 KEV 등재 추이"
      lead={<>최근 12개월 <b>{fmt(s12)}건</b>, 그 전 12개월은 {fmt(p12)}건({s12 >= p12 ? "+" : ""}{pct(s12 - p12, p12)}%). 랜섬웨어 연관은 {fmt(r12)}건입니다.</>}
      why={"등재 속도가 빨라질수록 \"KEV 전부 즉시 패치\"를 운영으로 감당하기 어려워집니다. 자산 대조로 범위를 좁히는 단계가 필요합니다."}>
      <Legend items={[["var(--s1)", "기타 KEV"], ["var(--s2)", "랜섬웨어 사용 확인"]]} />
      <Columns every={3} items={M.map((m) => ({ x: m.month, xl: m.month.slice(2).replace("-", "."), segs: [{ v: m.total - m.ransomware, name: "기타" }, { v: m.ransomware, cls: "s2", name: "랜섬웨어" }] }))} />
      <p className="src">이번 달은 집계 중인 부분 월입니다. 랜섬웨어 표시는 CISA가 확인한 경우만 포함하며 나중에 바뀔 수 있습니다.</p>
      <TableView head={["월", "전체", "랜섬웨어"]} rows={M.map((m) => [m.month, m.total, m.ransomware])} />
    </Card>

    <Card title="어디가 공격받나: KEV 벤더 Top 10"
      lead={<>최근 12개월 KEV의 <b>{pct(I.kevEdge, I.kevWindowCount)}%({fmt(I.kevEdge)}건)</b>가 VPN·방화벽·라우터 같은 경계 장비 제품이었습니다.</>}
      why="경계 장비는 인터넷에 직접 노출되고 EDR을 설치할 수 없어 침투 초기 거점으로 자주 쓰입니다. 경계 장비는 벤더·제품명 기반 추정치입니다.">
      <HBars rows={I.kevVendors.map((v) => ({ label: v.label, count: v.count }))} />
      <TableView head={["벤더", "건수"]} rows={I.kevVendors.map((v) => [v.label, v.count])} />
    </Card>

    <Card title="공격 유형: 실제 악용 vs 신규 Critical"
      why="왼쪽은 최근 12개월 KEV(실제 악용), 오른쪽은 최근 14일 신규 Critical에서 많이 나온 약점 유형(CWE)입니다. 두 목록이 겹치는 유형은 코드 리뷰·WAF 룰 우선순위로 쓸 수 있습니다.">
      <div className="cols2">
        <div><div className="eyebrow">KEV · 12개월</div><HBars rows={I.kevCwe.map((v) => ({ label: cweName(v.label), count: v.count }))} /></div>
        <div><div className="eyebrow">신규 Critical · 14일</div><HBars rows={I.critCwe.map((v) => ({ label: cweName(v.label), count: v.count }))} /></div>
      </div>
      <p className="src">CWE가 비어 있는 건 제외: KEV {fmt(I.kevCweUnclassified || 0)}건, 신규 Critical {fmt(I.critCweUnclassified || 0)}건. CNA가 CWE를 붙이지 않은 경우입니다.</p>
    </Card>

    <Card wide title="신규 Critical은 언제, 누구에게서"
      lead={<>가장 많았던 날은 <b>{peak.date.slice(5).replace("-", "/")} {fmt(peak.count)}건</b>, 가장 많이 낸 곳은 <b>{topV ? topV.label + " " + fmt(topV.count) + "건" : "–"}</b>입니다.</>}
      why="Critical 공개는 벤더 정기 패치일에 몰립니다. 급증일은 대부분 한 벤더의 일괄 공개라서, 그날 해당 벤더 자산만 따로 보면 됩니다.">
      <Columns every={2} items={D.map((d) => ({ x: d.date, xl: d.date.slice(5).replace("-", "/"), segs: [{ v: d.count }] }))} />
      <HBars rows={I.critVendors.map((v) => ({ label: v.label, count: v.count }))} total={fAll} />
      <TableView head={["날짜", "건수"]} rows={D.map((d) => [d.date, d.count])} />
    </Card>

    <Card title="연도별 등재 속도" why={"KEV 등재 연도 기준입니다. \"1년 이내 중앙값\"은 공개 1년 안에 등재된 건만 모아 계산해 오래된 취약점의 영향을 뺀 값입니다."}>
      <TableView open head={["연도", "등재", "1년 이내 중앙값(일)", "7일 이내", "1년 초과"]}
        rows={I.kevLagByYear.map((y) => [y.year + (y.year === thisYear ? " (진행 중)" : ""), y.n, y.medianRecent != null ? y.medianRecent : "–", y.within7 + " (" + pct(y.within7, y.n) + "%)", y.over1y + " (" + pct(y.over1y, y.n) + "%)"])} />
    </Card>
  </>;
}
