import { daysAgo, hasSig, isRce, riskScore } from "./util.js";

export const PAGE = 40;

export const RANGES = {
  kev: [[7, "7일"], [30, "30일"], [90, "90일"]],
  critical: [[3, "3일"], [7, "7일"], [14, "14일"], [30, "30일"], [90, "90일"]],
};
export const FILTERS = {
  kev: [["rw", "랜섬웨어 연관"], ["edge", "경계 장비"], ["fast", "공개 7일 내 등재"], ["old", "1년 넘은 취약점"]],
  critical: [["rce", "원격·무인증·무조작"], ["sig", "PoC·악용·KEV"], ["edge", "경계 장비"], ["auto", "SSVC 자동화 가능"]],
};
export const NO_KF = { rw: false, edge: false, fast: false, old: false };
export const NO_CF = { rce: false, sig: false, edge: false, auto: false };

export const initialListState = {
  q: "", hideDone: false, sort: "risk",
  range: { kev: 30, critical: 14 },
  kf: NO_KF, cf: NO_CF,
};

const dateOf = (it, kind) => (kind === "kev" ? it.added : it.published);

export function inRange(data, kind, days) {
  const from = daysAgo(days);
  return (kind === "kev" ? data.kev : data.critical).filter((it) => dateOf(it, kind) >= from);
}

export function filtered(data, st, done, kind) {
  const { kf, cf, q } = st;
  return inRange(data, kind, st.range[kind]).filter((it) => {
    if (st.hideDone && done[it.id]) return false;
    if (kind === "kev") {
      if (kf.rw && it.ransomware !== "Known") return false;
      if (kf.edge && !it.edge) return false;
      if (kf.fast && !(it.lagDays != null && it.lagDays <= 7)) return false;
      if (kf.old && !(it.lagDays != null && it.lagDays > 365)) return false;
    } else {
      if (cf.rce && !isRce(it)) return false;
      if (cf.sig && !hasSig(it)) return false;
      if (cf.edge && !it.edge) return false;
      if (cf.auto && it.automatable !== "yes") return false;
    }
    if (q) {
      const hay = (it.id + " " + it.vendor + " " + it.product + " " + (it.name || "") + " " + (it.summary || "") + " " + (it.cwe || "") + " " + (it.cwes || []).join(" ")).toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }).sort((a, b) => {
    if (st.sort === "risk") { const r = riskScore(b, kind) - riskScore(a, kind); if (r) return r; }
    const da = dateOf(a, kind), db = dateOf(b, kind);
    if (da !== db) return da < db ? 1 : -1;
    return (b.score || 0) - (a.score || 0);
  });
}

// ---------- CSV
function csvCell(v) {
  v = v == null ? "" : Array.isArray(v) ? v.join(" ") : String(v);
  return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
}
const CSV_COLS = {
  kev: [["cve","id"],["vendor","vendor"],["product","product"],["name","name"],["date_added","added"],["due_date","due"],["cve_published","published"],["lag_days","lagDays"],["cvss","score"],["ransomware","ransomware"],["edge_device","edge"],["cwe","cwes"],["required_action","action"]],
  critical: [["cve","id"],["published","published"],["cvss","score"],["cvss_version","cvssVersion"],["vector","vector"],["vendor","vendor"],["product","product"],["cwe","cwe"],["ssvc_exploitation","exploitation"],["ssvc_automatable","automatable"],["ssvc_technical_impact","techImpact"],["kev","kev"],["edge_device","edge"],["summary","summary"]],
};
export function buildCsv(kind, arr) {
  const cols = CSV_COLS[kind];
  const lines = [cols.map((c) => c[0]).join(",")];
  arr.forEach((it) => lines.push(cols.map((c) => csvCell(it[c[1]])).join(",")));
  return "﻿" + lines.join("\n");
}
export function downloadCsv(kind, arr) {
  const name = kind + "-" + new Date().toISOString().slice(0, 10) + ".csv";
  const url = URL.createObjectURL(new Blob([buildCsv(kind, arr)], { type: "text/csv;charset=utf-8" }));
  const a = document.createElement("a");
  a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
