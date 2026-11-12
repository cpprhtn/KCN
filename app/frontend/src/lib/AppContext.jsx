import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { LS, lsMigrated } from "./util.js";
import { initialListState, PAGE } from "./list.js";
import { useData } from "./useData.js";

export const VIEWS = ["brief", "ai", "kev", "knvd", "upd", "pkg", "kisa", "critical", "insights", "sources", "routine"];
export const REF_VIEWS = ["sources", "routine", "insights"];

const Ctx = createContext(null);
export const useApp = () => useContext(Ctx);

const viewFromHash = () => { const v = location.hash.slice(1); return VIEWS.includes(v) ? v : "brief"; };

export function AppProvider({ children }) {
  const { data, loadMsg, summary } = useData();
  const [view, setViewState] = useState(viewFromHash);
  const [done, setDone] = useState(() => lsMigrated("kcn.done", "radar.done", {}));

  // Per-view filter state lives here so it survives switching tabs.
  const [list, setList] = useState({ ...initialListState, shown: PAGE });
  const [upd, setUpd] = useState({ range: 30, sev: "all", shown: 30 });
  const [kisa, setKisa] = useState({ range: 30 });
  const [pkg, setPkg] = useState({ kind: "adv", sev: "all", eco: "", q: "", shown: PAGE });

  const setView = useCallback((v, push = true) => {
    if (!VIEWS.includes(v)) v = "brief";
    setViewState(v);
    setList((s) => ({ ...s, shown: PAGE }));
    if (push && location.hash !== "#" + v) {
      try { history.replaceState(null, "", "#" + v); } catch { location.hash = v; }
    }
  }, []);

  useEffect(() => {
    const onHash = () => setView(location.hash.slice(1), false);
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, [setView]);

  const toggleDone = useCallback((id, on) => {
    setDone((d) => {
      const n = { ...d };
      if (on) n[id] = Date.now(); else delete n[id];
      LS.set("kcn.done", n);
      return n;
    });
  }, []);

  const value = useMemo(() => ({
    data, loadMsg, summary, ready: !!data.meta,
    view, setView, done, toggleDone,
    list, setList, upd, setUpd, kisa, setKisa, pkg, setPkg,
  }), [data, loadMsg, summary, view, setView, done, toggleDone, list, upd, kisa, pkg]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
