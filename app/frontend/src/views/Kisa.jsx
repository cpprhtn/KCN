import { useApp } from "../lib/AppContext.jsx";
import { daysAgo, kisaRelated, mmdd } from "../lib/util.js";
import { Badge, CveLink, DoneBox, ExtLink, FilterSection, labelOf, PageHead, Seg } from "../components/common.jsx";

const RANGE = [[7, "7일"], [30, "30일"], [90, "90일"]];
const KIND = { update: "업데이트 권고", vuln: "취약점 조치 권고", notice: "주의·대응 권고" };

export default function Kisa() {
  const { data, ready, loadMsg, done, kisa, setKisa } = useApp();
  const from = daysAgo(kisa.range);
  const arr = ready ? data.kisa.filter((k) => k.date >= from) : [];
  return (
    <FilterSection id="v-kisa" summary={[labelOf(RANGE, kisa.range)]}>
      {(fbtn) => <>
        <PageHead title="KISA 권고">KISA 보호나라에 올라온 보안 공지입니다.</PageHead>
        <div className="toolbar">
          {fbtn}
          <Seg label="기간" opts={RANGE} value={kisa.range} onPick={(v) => setKisa({ range: v })} />
        </div>
        <ul className="list">
          {!ready && <li className="empty">{loadMsg}</li>}
          {ready && !arr.length && <li className="empty">이 기간에 KISA 권고가 없습니다.</li>}
          {arr.map((k) => {
            const rel = kisaRelated(data, k), key = "kisa:" + k.ntt;
            return (
              <li key={k.ntt} className={"item" + (done[key] ? " done" : "")}>
                <div className="score kisa"><b>KISA</b><span>{mmdd(k.date)}</span></div>
                <div className="body">
                  <div className="line1"><ExtLink href={k.url} className="prod">{k.title}</ExtLink><span className="date">{k.date}</span></div>
                  <div className="badges">
                    <Badge cls="plain">{KIND[k.kind] || "권고"}</Badge>
                    {rel.kev.length > 0 && <Badge cls="kev">같은 벤더 KEV(실제 악용) 30일 {rel.kev.length}건</Badge>}
                    {rel.crit.length > 0 && <Badge cls="rw">즉시 위험 Critical {rel.crit.length}건</Badge>}
                  </div>
                  {(rel.kev.length > 0 || rel.crit.length > 0) && (
                    <div className="act">
                      <b>관련</b>
                      {rel.kev.concat(rel.crit.filter((c) => !rel.kev.some((k) => k.id === c.id))).slice(0, 5).map((x) => <span key={x.id}><CveLink id={x.id} />{" " + x.product}</span>)}
                    </div>
                  )}
                  <div className="foot"><DoneBox id={key} /></div>
                </div>
              </li>
            );
          })}
        </ul>
      </>}
    </FilterSection>
  );
}
