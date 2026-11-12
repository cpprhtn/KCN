import { useMemo } from "react";
import { useApp } from "../lib/AppContext.jsx";
import { daysAgo, groupText, isRce, koOf } from "../lib/util.js";
import { Badge, CveLink, DoneBox, FilterSection, GroupAction, labelOf, PageHead, Seg } from "../components/common.jsx";

const RANGE = [[7, "7일"], [30, "30일"], [90, "90일"]];
const SEV = [["all", "7.0 이상 전부"], ["urgent", "급한 것만"]];
const STEP = 30;

export default function Updates() {
  const { data, ready, loadMsg, done, upd, setUpd } = useApp();
  const set = (patch) => setUpd((s) => ({ ...s, ...patch, shown: STEP }));
  const arr = useMemo(() => {
    if (!ready) return [];
    const from = daysAgo(upd.range);
    return data.updates
      .filter((g) => g.date >= from && (upd.sev !== "urgent" || g.kev.length || (g.maxScore >= 9 && g.nRemote) || g.exploited.length))
      .sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : b.maxScore - a.maxScore));
  }, [data, ready, upd.range, upd.sev]);

  return (
    <FilterSection id="v-upd" summary={[labelOf(RANGE, upd.range), labelOf(SEV, upd.sev)]}>
      {(fbtn) => <>
        <PageHead title="제품 업데이트">국내에서 많이 쓰는 제품의 보안 업데이트를 벤더·날짜별로 묶었습니다.</PageHead>
        <div className="toolbar">
          {fbtn}
          <Seg label="기간" opts={RANGE} value={upd.range} onPick={(v) => set({ range: v })} />
          <Seg label="심각도" opts={SEV} value={upd.sev} onPick={(v) => set({ sev: v })} />
          <span className="small muted" id="updCount">{ready ? "최근 " + upd.range + "일 " + arr.length + "개 업데이트 묶음" : ""}</span>
        </div>
        <ul className="list">
          {!ready && <li className="empty">{loadMsg}</li>}
          {ready && !arr.length && <li className="empty">조건에 맞는 업데이트가 없습니다.</li>}
          {arr.slice(0, upd.shown).map((g) => <Group key={g.gid} g={g} done={!!done[g.gid]} />)}
          {arr.length > upd.shown && (
            <li className="more"><button className="btn ghost" type="button" onClick={() => setUpd((s) => ({ ...s, shown: s.shown + STEP }))}>
              더 보기 ({arr.length - upd.shown}개 남음)
            </button></li>
          )}
        </ul>
        <p className="muted small">국내에서 많이 쓰는 제품(Synology·QNAP·ipTIME·Microsoft·Google·Apple·삼성·Fortinet·Ivanti·Cisco·한컴 등 50여 곳)은 CVSS 7.0 이상까지 모아, 벤더가 같은 날 낸 취약점을 한 묶음으로 보여줍니다. CVE 레코드가 공개되는 즉시 반영되므로 KISA 권고보다 빠른 경우가 많습니다. 90일 동안 보관합니다.</p>
      </>}
    </FilterSection>
  );
}

function Group({ g, done }) {
  const { data } = useApp();
  const gt = groupText(data, g);
  const items = g.items || [];
  return (
    <li className={"item" + (done ? " done" : "")}>
      <div className={"score " + (g.maxScore >= 9 ? "crit" : "kev")}><b>{g.maxScore.toFixed(1)}</b><span>최고점</span></div>
      <div className="body">
        <div className="line1">
          <span className="prod">{g.vendor} 보안 업데이트</span>
          <span className="muted small">{(g.products || []).slice(0, 4).join(", ")}</span>
          <span className="date">공개 {g.date}</span>
        </div>
        <div className={gt.ko ? "ko" : "ko-en"}>{gt.t}</div>
        <div className="badges">
          {g.kev.length > 0 ? <Badge cls="rw">실제 악용 {g.kev.length}건</Badge>
            : g.exploited.length > 0 ? <Badge cls="poc">PoC 공개 {g.exploited.length}건</Badge> : null}
          <Badge cls="plain">CVE {g.count || g.cves.length}건</Badge>
          {g.nCrit > 0 && <Badge cls="plain">9.0점 이상 {g.nCrit}건</Badge>}
          {g.nRemote > 0 && <Badge cls="plain">인증 없이 원격 {g.nRemote}건</Badge>}
        </div>
        <GroupAction g={g} />
        <details className="tbl">
          <summary>CVE 목록 보기{(g.count || 0) > items.length ? " (점수 높은 " + items.length + "건)" : ""}</summary>
          <ul className="tl-items" style={{ marginTop: 8 }}>
            {items.map((c) => (
              <li key={c.id}>
                <CveLink id={c.id} />
                <span className="b plain mono">{c.score.toFixed(1)}</span>
                <span className="prod">{c.product}</span>
                {isRce(c) && <Badge cls="plain">인증 없이 원격</Badge>}
                <span className="muted">{koOf(data, c.id) || c.d}</span>
              </li>
            ))}
          </ul>
        </details>
        <div className="foot"><DoneBox id={g.gid} /></div>
      </div>
    </li>
  );
}
