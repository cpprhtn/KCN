import { fmt, pct } from "../lib/util.js";
import { useTip } from "./Tip.jsx";

export function TableView({ head, rows, open }) {
  return (
    <details className="tbl" open={open}>
      <summary>표로 보기</summary>
      <div className="tw">
        <table>
          <thead><tr>{head.map((h, i) => <th key={i} className={i ? "n" : undefined}>{h}</th>)}</tr></thead>
          <tbody>
            {rows.map((r, ri) => (
              <tr key={ri}>{r.map((c, i) => <td key={i} className={i ? "n" : undefined}>{String(c)}</td>)}</tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}

// rows: [{label, count, color?}] ; total adds a % suffix
export function HBars({ rows, total }) {
  const tip = useTip();
  const max = Math.max(1, ...rows.map((r) => r.count));
  return (
    <div className="hb">
      {rows.map((r, i) => (
        <div className="hb-row" key={i} {...tip(fmt(r.count) + "건" + (total ? " · " + pct(r.count, total) + "%" : ""), r.label)}>
          <span className="hb-l" title={r.label}>{r.label}</span>
          <span className="hb-t"><span className="hb-b" style={{ width: (r.count / max) * 100 + "%", background: r.color }} /></span>
          <span className="hb-v">{fmt(r.count)}{total ? <small>{pct(r.count, total)}%</small> : null}</span>
        </div>
      ))}
    </div>
  );
}

function niceMax(m) {
  if (m <= 5) return 5;
  const p = Math.pow(10, Math.floor(Math.log10(m))), n = m / p;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p;
}

// items: [{x, xl, segs:[{v, cls, name}]}]
export function Columns({ items, every = 1 }) {
  const tip = useTip();
  const tot = items.map((it) => it.segs.reduce((a, s) => a + s.v, 0));
  const top = niceMax(Math.max(1, ...tot));
  return (
    <div className="col-chart">
      <div className="col-plot">
        {[0, 0.5, 1].map((f) => (
          <div key={f} className={"col-grid" + (f === 0 ? " base" : "")} style={{ bottom: f * 100 + "%" }}>
            <span>{fmt(Math.round(top * f))}</span>
          </div>
        ))}
        <div className="col-bars">
          {items.map((it, i) => {
            const nz = it.segs.filter((s) => s.v > 0);
            const lbl = it.segs.length > 1 ? it.segs.map((s) => s.name + " " + s.v).join(" · ") : "";
            return (
              <div className="col" key={i} {...tip(fmt(tot[i]) + "건", it.x + (lbl ? " — " + lbl : ""))}>
                {nz.map((s, j) => (
                  <div key={j} className={"cs " + (s.cls || "") + (j === nz.length - 1 ? " top" : "")}
                       style={{ height: "calc(" + (s.v / top) * 100 + "% - 2px)", minHeight: "2px" }} />
                ))}
              </div>
            );
          })}
        </div>
      </div>
      <div className="col-x">
        {items.map((it, i) => <span key={i}>{i % every === 0 || i === items.length - 1 ? it.xl : ""}</span>)}
      </div>
    </div>
  );
}

export function Legend({ items }) {
  return (
    <div className="legend">
      {items.map(([color, label]) => <span key={label}><i style={{ background: color }} />{label}</span>)}
    </div>
  );
}
