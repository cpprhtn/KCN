import { daysAgo, enName, fixText, groupFix, groupText, hasSig, isRce, koOf, riskScore, uniq } from "./util.js";

const MAX_SHOWN = 4;

// Today's call: new KEV in 7 days first, then remote/no-auth Critical with an exploit signal in 14 days.
// Returns { head, cls, sub, shown:[row], more:[row], all:[row] } where row = { pill, pillText, it, kind }.
export function computeVerdict(data, done) {
  const from7 = daysAgo(7), from14 = daysAgo(14);
  const k7 = data.kev.filter((v) => v.added >= from7 && !done[v.id]).sort((a, b) => riskScore(b, "kev") - riskScore(a, "kev"));
  const k7ids = new Set(k7.map((x) => x.id));
  const hot = data.critical
    .filter((c) => c.published >= from14 && isRce(c) && hasSig(c) && !c.kev && !done[c.id] && !k7ids.has(c.id))
    .sort((a, b) => riskScore(b, "critical") - riskScore(a, "critical"));
  const edgeN = k7.filter((v) => v.edge).length;

  if (!k7.length && !hot.length) {
    return { head: "지난 7일 새로 확인된 실제 악용이 없습니다", cls: "ok", sub: "고위험 신규 목록은 왼쪽 메뉴에서 볼 수 있습니다.", shown: [], more: [], all: [] };
  }
  const head = k7.length ? "지난 7일 실제 악용 " + k7.length + "건이 새로 확인됐습니다" : "즉시 위험한 고위험 취약점 " + hot.length + "건";
  const sub = [
    k7.length && edgeN ? "그중 VPN·방화벽 같은 경계 장비 " + edgeN + "건" : "",
    hot.length && k7.length ? "최근 2주 고위험 중 인증 없이 원격 + 공격 코드 공개 " + hot.length + "건" : "",
    "처리했으면 각 항목의 ‘확인함’을 누르세요",
  ].filter(Boolean).join(" · ");
  const all = [
    ...k7.slice(0, 20).map((it) => ({ pill: "p1", pillText: "실제 악용", it, kind: "kev" })),
    ...hot.slice(0, 8).map((it) => ({ pill: "p2", pillText: "즉시 위험", it, kind: "critical" })),
  ];
  return { head, cls: k7.length ? "p1" : "p2", sub, shown: all.slice(0, MAX_SHOWN), more: all.slice(MAX_SHOWN), all };
}

export function reportText(data, verdict) {
  if (!data.meta) return "";
  const L = [], gen = new Date(data.meta.generatedAt).toLocaleDateString("ko-KR");
  L.push("[KCN] " + gen + " 기준", "", "■ 오늘 판정: " + verdict.head);
  verdict.all.forEach(({ pillText, it, kind }) => {
    if (kind === "kisa") { L.push("- [" + pillText + "] KISA " + it.date + " " + it.title + " " + it.url); return; }
    if (kind === "update") {
      const gf = groupFix(it);
      L.push("- [" + pillText + "] " + it.vendor + " 보안 업데이트 (" + it.date + "): " + groupText(data, it).t + (gf ? " (버전: " + gf + ")" : "") + ((it.refs || [])[0] ? " " + it.refs[0] : ""));
      return;
    }
    let line = "- [" + pillText + "] " + it.id + " " + [it.vendor, it.product].filter(Boolean).join(" ") + ": " + (koOf(data, it.id) || enName(it));
    const ft = fixText(it.fix); if (ft) line += " (버전: " + ft + ")";
    L.push(line);
  });
  const from7 = daysAgo(7), k7 = data.kev.filter((v) => v.added >= from7);
  const crit14 = data.critical.filter((c) => c.published >= daysAgo(14));
  const hot = crit14.filter((c) => isRce(c) && hasSig(c)).length;
  const kisa7 = data.kisa.filter((k) => k.date >= from7);
  L.push("", "■ 최근 7일");
  L.push("- 실제 악용(KEV) 신규 " + k7.length + "건: 경계 장비 " + k7.filter((v) => v.edge).length + "건, 랜섬웨어 연관 " + k7.filter((v) => v.ransomware === "Known").length + "건, 침해 흔적 점검 필요 " + k7.filter((v) => v.forensic).length + "건");
  L.push("- 신규 CVSS 9.0+ (14일) " + crit14.length + "건 중 원격·무인증·무조작 + 악용 신호 " + hot + "건");
  if (kisa7.length) L.push("- KISA 권고 " + kisa7.length + "건: " + uniq(kisa7.map((k) => k.vendor || k.title)).join(", "));
  L.push("", "출처: CISA KEV, CVE List V5, KISA 보호나라 · " + location.origin + location.pathname);
  return L.join("\n");
}
