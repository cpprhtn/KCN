import { useCallback, useEffect, useRef, useState } from "react";
import { cveUrl, fixText, groupFix, host } from "../lib/util.js";
import { useApp } from "../lib/AppContext.jsx";

export function ExtLink({ href, className, children }) {
  return <a href={href} className={className} target="_blank" rel="noopener">{children}</a>;
}

export const CveLink = ({ id }) => <ExtLink href={cveUrl(id)} className="cve">{id}</ExtLink>;

export function Badge({ cls, children }) {
  return <span className={"b " + cls}>{children}</span>;
}

// Segmented buttons: opts = [[value, label], ...]
export function Seg({ opts, value, onPick, label, hidden }) {
  return (
    <div className="seg" role="group" aria-label={label} hidden={hidden}>
      {opts.map(([v, l]) => (
        <button key={String(v)} type="button" aria-pressed={value === v} onClick={() => onPick(v)}>{l}</button>
      ))}
    </div>
  );
}

// "확인함" checkbox, saved in this browser only.
export function DoneBox({ id }) {
  const { done, toggleDone } = useApp();
  return (
    <label className="tog">
      <input type="checkbox" id={"done-" + id.replace(/[^A-Za-z0-9_-]/g, "_")} checked={!!done[id]} onChange={(e) => toggleDone(id, e.target.checked)} />
      확인함
    </label>
  );
}

function ActRow({ fix, refs }) {
  if (!fix && !(refs && refs.length)) return null;
  return (
    <div className="act">
      {fix && <span><b>버전</b>{fix}</span>}
      {(refs || []).slice(0, 2).map((u) => <ExtLink key={u} href={u}>{host(u) + " 공지 ↗"}</ExtLink>)}
    </div>
  );
}
export const ItemAction = ({ it }) => <ActRow fix={fixText(it.fix)} refs={it.refs} />;
export const GroupAction = ({ g }) => <ActRow fix={groupFix(g)} refs={g.refs} />;

// Phones fold each view's toolbar behind one "필터 · …" button.
export function FilterSection({ id, summary, children }) {
  const [open, setOpen] = useState(false);
  return (
    <section id={id} className={open ? undefined : "fcollapsed"}>
      {children(
        <button className="btn ghost sm fbtn" type="button" aria-expanded={open} onClick={() => setOpen(!open)}>
          {"필터" + (summary.length ? " · " + summary.join(" · ") : "") + (open ? "  ▴" : "  ▾")}
        </button>
      )}
    </section>
  );
}

export function PageHead({ title, children }) {
  return <div className="page-head"><h1>{title}</h1><p>{children}</p></div>;
}

export const labelOf = (opts, v) => (opts.find((o) => o[0] === v) || [, ""])[1];

// Temporary label (e.g. "복사했습니다") that reverts after a moment.
export function useFlash() {
  const [msg, setMsg] = useState(null);
  const timer = useRef(0);
  useEffect(() => () => clearTimeout(timer.current), []);
  const flash = useCallback((m, ms = 2200) => {
    setMsg(m); clearTimeout(timer.current);
    timer.current = setTimeout(() => setMsg(null), ms);
  }, []);
  return [msg, flash];
}
