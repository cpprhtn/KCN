import { createContext, useContext, useLayoutEffect, useMemo, useRef, useState } from "react";

const TipCtx = createContext(null);

// A single floating tooltip for all charts. The context value never changes,
// so moving the pointer re-renders only <Tip/>, not the charts.
export function TipProvider({ children }) {
  const api = useRef(null);
  const value = useMemo(() => ({
    show: (x, y, val, label) => api.current && api.current({ x, y, val, label }),
    hide: () => api.current && api.current(null),
  }), []);
  return (
    <TipCtx.Provider value={value}>
      {children}
      <Tip bind={(fn) => { api.current = fn; }} />
    </TipCtx.Provider>
  );
}

function Tip({ bind }) {
  const [t, setT] = useState(null);
  const ref = useRef(null);
  bind(setT);
  useLayoutEffect(() => {
    const n = ref.current;
    if (!t || !n) return;
    const w = n.offsetWidth, h = n.offsetHeight;
    const nx = Math.min(t.x + 12, window.innerWidth - w - 8);
    let ny = t.y - h - 12; if (ny < 8) ny = t.y + 16;
    n.style.left = Math.max(8, nx) + "px"; n.style.top = ny + "px";
  }, [t]);
  return (
    <div className="tip" ref={ref} hidden={!t}>
      {t && <><b>{t.val}</b><span>{t.label}</span></>}
    </div>
  );
}

// Spread onto any element that should show the tooltip on hover / keyboard focus.
export function useTip() {
  const tip = useContext(TipCtx);
  return (val, label) => ({
    tabIndex: 0,
    "aria-label": label + ": " + val,
    onPointerMove: (e) => tip.show(e.clientX, e.clientY, val, label),
    onPointerLeave: tip.hide,
    onFocus: (e) => { const r = e.currentTarget.getBoundingClientRect(); tip.show(r.left + r.width / 2, r.top, val, label); },
    onBlur: tip.hide,
  });
}
