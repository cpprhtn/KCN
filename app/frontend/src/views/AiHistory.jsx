import { useCallback, useEffect, useState } from "react";
import { Icon } from "../components/Icon.jsx";
import { CveLink, PageHead } from "../components/common.jsx";

export const LEVEL = { urgent: ["지금", "lv-urgent"], watch: ["이번 주", "lv-watch"], info: ["참고", "lv-info"] };

export function slotLabel(slot) {
  const h = parseInt((slot || "").slice(0, 2), 10);
  if (isNaN(h)) return "수동 실행";
  return (h < 12 ? "오전 " : h === 12 ? "낮 " : h < 18 ? "오후 " : "저녁 ") + (h > 12 ? h - 12 : h) + "시";
}

// The body of one briefing; shared by the "오늘" card and the history list.
export function SummaryBody({ sm }) {
  return <>
    <p className="ai-head">{sm.headline}</p>
    {sm.points && sm.points.length > 0 && (
      <ul className="ai-points">
        {sm.points.map((pt, i) => {
          const lv = LEVEL[pt.level] || LEVEL.info;
          return (
            <li key={i} className={lv[1]}>
              <span className="lv">{lv[0]}</span>
              <div className="pt-body">
                <strong>{pt.title}</strong>
                <p>{pt.text}</p>
                {pt.ids && pt.ids.length > 0 && <div className="pt-ids">{pt.ids.map((id) => <CveLink key={id} id={id} />)}</div>}
              </div>
            </li>
          );
        })}
      </ul>
    )}
    {sm.actions && sm.actions.length > 0 && (
      <div className="ai-actions"><h3>할 일</h3><ul>{sm.actions.map((a, i) => <li key={i}>{a}</li>)}</ul></div>
    )}
  </>;
}

const dayKey = (iso) => new Date(iso).toLocaleDateString("sv-SE", { timeZone: "Asia/Seoul" });
const dayTitle = (iso) => new Date(iso).toLocaleDateString("ko-KR", { timeZone: "Asia/Seoul", month: "long", day: "numeric", weekday: "short" });
const timeOf = (iso) => new Date(iso).toLocaleTimeString("ko-KR", { timeZone: "Asia/Seoul", hour: "numeric", minute: "2-digit" });

export default function AiHistory() {
  const [st, setSt] = useState({ items: [], more: true, busy: false, err: "", loaded: false });

  const load = useCallback((before) => {
    const p = new URLSearchParams({ limit: "15" });
    if (before) p.set("before", before);
    setSt((s) => ({ ...s, busy: true, err: "" }));
    fetch("api/summaries?" + p, { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(r.status))))
      .then((r) => setSt((s) => ({ items: before ? s.items.concat(r.items) : r.items, more: r.more, busy: false, err: "", loaded: true })))
      .catch(() => setSt((s) => ({ ...s, busy: false, loaded: true, err: "요약 기록을 불러오지 못했습니다." })));
  }, []);
  useEffect(() => { load(null); }, [load]);

  const days = [];
  st.items.forEach((sm) => {
    const k = dayKey(sm.at);
    if (!days.length || days[days.length - 1].k !== k) days.push({ k, title: dayTitle(sm.at), items: [] });
    days[days.length - 1].items.push(sm);
  });

  return (
    <section id="v-ai">
      <PageHead title="AI 요약 기록">ChatGPT가 매일 오전 7시·낮 12시·저녁 7시에 쓴 브리핑을 모두 보관합니다. 수집한 데이터만 보고 쓴 요약이니 조치 전에 원문과 벤더 공지를 확인하세요.</PageHead>
      {!st.loaded && <p className="muted">불러오는 중…</p>}
      {st.loaded && !st.items.length && !st.err && <p className="empty">아직 기록이 없습니다. OpenAI API 키가 설정돼 있으면 다음 예약 시각에 첫 요약이 생깁니다.</p>}
      {days.map((d) => (
        <div className="ai-day" key={d.k}>
          <h2 className="ai-day-h">{d.title}</h2>
          {d.items.map((sm, i) => (
            <details className="ai-card ai-hist" key={sm.id} open={d === days[0] && i === 0}>
              <summary className="ai-top">
                <span className="ai-label"><Icon name="spark" />{slotLabel(sm.slot)}</span>
                <span className="ai-meta">{timeOf(sm.at)} 작성{sm.quiet ? " · 새 항목 없음" : ""}</span>
                <span className="ai-sum">{sm.headline}</span>
              </summary>
              <SummaryBody sm={sm} />
            </details>
          ))}
        </div>
      ))}
      <div className="more">
        {st.more && st.items.length > 0 && (
          <button className="btn ghost" type="button" disabled={st.busy} onClick={() => load(st.items[st.items.length - 1].at)}>
            {st.busy ? "불러오는 중…" : "이전 기록 더 보기"}
          </button>
        )}
        {st.err && <span className="small muted">{st.err}</span>}
      </div>
    </section>
  );
}
