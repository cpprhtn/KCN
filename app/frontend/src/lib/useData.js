import { useEffect, useState } from "react";

export const LOADING = "불러오는 중…";
const FAILED = "데이터를 불러오지 못했습니다. 서버를 처음 띄웠다면 첫 수집이 끝날 때까지(수 분~수십 분) 기다린 뒤 새로고침해 주세요.";

const EMPTY = { meta: null, ins: null, kev: [], critical: [], kisa: [], ko: {}, changes: [], updates: [], pkg: { ghsa: [], mal: [] }, rss: { feeds: [], items: [] }, archiveLoaded: false };

// Snapshots are served by the FastAPI web service at data/<name>.json (from PostgreSQL).
async function getJson(name) {
  const r = await fetch("data/" + name + ".json", { cache: "no-store" });
  if (!r.ok) throw new Error(name + " " + r.status);
  return r.json();
}
const optJson = (name, dflt) => getJson(name).catch(() => dflt);

export function useData() {
  const [data, setData] = useState(EMPTY);
  const [loadMsg, setLoadMsg] = useState(LOADING);
  const [summary, setSummary] = useState(null);

  useEffect(() => {
    let alive = true;
    Promise.all([
      getJson("meta"), getJson("insights"), getJson("kev"), getJson("critical"),
      optJson("kisa", { items: [] }), optJson("ko", { items: {} }), optJson("changes", { days: [] }),
      optJson("updates", { items: [] }), optJson("packages", { ghsa: [], mal: [] }),
      optJson("rss", { feeds: [], items: [] }),
    ]).then(([meta, ins, kev, critical, kisa, ko, changes, updates, pkg, rss]) => {
      if (!alive) return;
      const base = {
        meta, ins,
        kev: kev.items || [],
        critical: critical.items || [],
        kisa: kisa.items || [],
        ko: ko.items || {},
        changes: changes.days || [],
        updates: updates.items || [],
        pkg: { ghsa: pkg.ghsa || [], mal: pkg.mal || [], ghsaDays: pkg.ghsaDays, malDays: pkg.malDays },
        rss: { feeds: rss.feeds || [], items: rss.items || [], days: rss.days },
        archiveLoaded: false,
      };
      setData(base);
      // Older (15-90 day) Critical CVEs come in a second, lighter file so the first screen stays fast.
      optJson("archive", { items: [] }).then((a) => {
        if (!alive) return;
        const have = new Set(base.critical.map((c) => c.id));
        const extra = (a.items || []).filter((x) => !have.has(x.id));
        setData({ ...base, critical: base.critical.concat(extra), archiveLoaded: true });
      });
    }).catch(() => { if (alive) setLoadMsg(FAILED); });
    optJson("summary", null).then((s) => { if (alive) setSummary(s); });
    return () => { alive = false; };
  }, []);

  return { data, loadMsg, summary };
}
