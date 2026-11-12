// Pure helpers shared by every view. No React here.

export const LS = {
  get(k, d) {
    try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch { return d; }
  },
  set(k, v) {
    try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* private mode */ }
  },
};

// Storage keys moved from "radar.*" to "KCN.*"; read the old ones once so nothing is lost.
export function lsMigrated(key, oldKey, d) {
  const v = LS.get(key, undefined);
  if (v !== undefined) return v;
  const old = LS.get(oldKey, undefined);
  if (old !== undefined) { LS.set(key, old); return old; }
  return d;
}

export const CWE = {"CWE-78":"OS 명령어 삽입","CWE-77":"명령어 삽입","CWE-94":"코드 삽입","CWE-22":"경로 조작","CWE-23":"경로 조작","CWE-287":"부적절한 인증","CWE-306":"인증 누락","CWE-288":"대체 경로 인증 우회","CWE-290":"스푸핑 인증 우회","CWE-502":"역직렬화","CWE-416":"해제 후 사용(UAF)","CWE-787":"범위 밖 쓰기","CWE-125":"범위 밖 읽기","CWE-89":"SQL 삽입","CWE-79":"XSS","CWE-434":"위험한 파일 업로드","CWE-20":"입력 검증 미흡","CWE-269":"권한 관리 오류","CWE-862":"권한 확인 누락","CWE-863":"잘못된 권한 확인","CWE-918":"SSRF","CWE-798":"하드코딩된 자격증명","CWE-843":"타입 혼동","CWE-122":"힙 오버플로","CWE-121":"스택 오버플로","CWE-120":"버퍼 오버플로","CWE-119":"메모리 경계 오류","CWE-352":"CSRF","CWE-611":"XXE","CWE-639":"권한 없는 객체 접근(IDOR)","CWE-284":"접근 제어 미흡","CWE-276":"잘못된 기본 권한","CWE-200":"정보 노출","CWE-1321":"프로토타입 오염","CWE-74":"삽입(Injection)","CWE-917":"표현식 언어 삽입","CWE-400":"리소스 고갈","CWE-190":"정수 오버플로","CWE-59":"링크 추적","CWE-427":"검색 경로 조작","CWE-345":"진위 검증 미흡","CWE-693":"보호 기능 실패","CWE-1336":"템플릿 삽입","CWE-732":"잘못된 권한 설정","CWE-770":"무제한 리소스 할당","CWE-401":"메모리 누수","CWE-476":"NULL 역참조","CWE-305":"주요 약점 인증 우회","CWE-912":"숨겨진 기능","CWE-15":"외부 설정 제어","CWE-668":"잘못된 영역 노출"};
export const cweName = (c) => (CWE[c] ? c + " " + CWE[c] : c);

export const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
export function daysAgo(n) { const d = new Date(); d.setDate(d.getDate() - n); return d.toISOString().slice(0, 10); }
export const pct = (a, b) => (b ? Math.round((a * 100) / b) : 0);
export const fmt = (n) => Number(n).toLocaleString("ko-KR");
export const uniq = (arr) => arr.filter((v, i, a) => a.indexOf(v) === i);
export const cveUrl = (id) => "https://www.cve.org/CVERecord?id=" + encodeURIComponent(id);

// ---------- signals
export const isRce = (it) => it.av === "N" && it.pr === "N" && (it.ui === "N" || !it.ui);
export const hasSig = (it) => it.kev || it.exploitation === "active" || it.exploitation === "poc" || it.exploitation === "public poc";
export const isPoc = (it) => it.exploitation === "poc" || it.exploitation === "public poc";

export function riskScore(it, kind) {
  if (kind === "kev") {
    return (it.edge ? 6 : 0) + (it.ransomware === "Known" ? 5 : 0) + (it.lagDays != null && it.lagDays <= 7 ? 4 : 0) + (isRce(it) ? 2 : 0);
  }
  return (it.kev ? 12 : 0) + (it.exploitation === "active" ? 10 : isPoc(it) ? 6 : 0)
    + (isRce(it) ? 5 : 0) + (it.automatable === "yes" ? 2 : 0) + (it.techImpact === "total" ? 1 : 0) + (it.edge ? 2 : 0);
}

export function lagText(d) {
  if (d == null) return null;
  if (d <= 0) return "공개 당일·이전 등재";
  if (d <= 365) return "공개 " + d + "일 만에 등재";
  return "공개 " + (d / 365).toFixed(1) + "년 된 취약점";
}

// Kernel records all open with the same boilerplate; the patch subject line says more.
const KERNEL = /^In the Linux kernel, the following vulnerability has been resolved:\s*/i;
export const enLead = (it) => (it.summary || it.name || "").replace(KERNEL, "").split("\n")[0];
export const enName = (it) => (it.name || it.summary || "").replace(KERNEL, "").split("\n")[0];

export function host(u) { try { return new URL(u).hostname.replace(/^www\./, ""); } catch { return "공지"; } }

export function fixText(fx) {
  return (fx || []).slice(0, 3).map((f) => {
    const p = f.p ? f.p + " " : "";
    return f.lt ? p + f.lt + " 이상으로" : p + f.le + " 이하 영향";
  }).join(" · ");
}

export const koOf = (data, id) => { const k = data.ko[id]; return k && k.t ? k.t : ""; };

export function groupText(data, g) {
  const ko = koOf(data, g.gid);
  if (ko) return { t: ko, ko: true };
  const prods = (g.products || []).slice(0, 2).join(", ");
  let t = g.vendor + (prods ? " " + prods : "") + " 취약점 " + (g.count || g.cves.length) + "건이 고쳐졌습니다.";
  if (g.nRemote) t += " 그중 " + g.nRemote + "건은 인증 없이 원격 공격이 가능합니다(최고 " + g.maxScore.toFixed(1) + "점).";
  else t += " 최고 " + g.maxScore.toFixed(1) + "점.";
  if (g.kev && g.kev.length) t += " 실제 악용이 확인된 취약점이 포함돼 있습니다.";
  else if (g.exploited && g.exploited.length) t += " 공개된 공격 코드(PoC)가 있는 취약점이 포함돼 있습니다.";
  return { t, ko: false };
}
export const groupFix = (g) => (g.fixes || []).join(" · ");

const wordRe = (t) => new RegExp("(^|[^\\p{L}\\p{N}])" + esc(t) + "($|[^\\p{L}\\p{N}])", "iu");
export function kisaRelated(data, k) {
  const from = daysAgo(30), ids = k.cves || [];
  const re = k.vendor ? wordRe(k.vendor) : null;
  const kev = data.kev.filter((v) => v.added >= from && (ids.includes(v.id) || (re && re.test(v.vendor + " | " + v.product))));
  const crit = data.critical.filter((c) => c.published >= from && isRce(c) && hasSig(c) && (ids.includes(c.id) || (re && re.test(c.vendor + " | " + c.product))));
  return { kev, crit };
}

export function dayLabel(d) {
  const dt = new Date(d + "T00:00:00Z");
  return { md: (dt.getUTCMonth() + 1) + "/" + dt.getUTCDate(), wd: "일월화수목금토".charAt(dt.getUTCDay()) };
}

export const mmdd = (d) => d.slice(5).replace("-", "/");

export async function copyText(text) {
  if (!navigator.clipboard) throw new Error("no clipboard");
  await navigator.clipboard.writeText(text);
}
