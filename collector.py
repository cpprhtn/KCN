"""Critical Vulnerability Radar - incremental collector (v5: + packages).

Collect:
  python3 -I collector.py --state <dir> --out <dir> [--kisa <file>] [--work <dir>] [--full]
Merge Korean one-line summaries written by the operator:
  python3 -I collector.py --out <dir> --merge-ko <file>

--state  folder with the previously published data files (any may be missing):
         meta.json critical.json kevcache.json kisa.json ko.json changes.json packages.json
--out    output folder: <out>/data/*.json (publish each at artifact path data/<name>.json),
         <out>/summary.json, <out>/ko_todo.json
--kisa   JSON array of KISA notices [{"title","date","url"}] fetched from
         https://www.boho.or.kr/kr/bbs/list.do?menuNo=205020&bbsId=B0000133 . Omit if the fetch failed.
--merge-ko  JSON object {"CVE-...": "한국어 한 줄"}; only IDs listed in <out>/ko_todo.json are accepted.

Incremental logic
  * CISA KEV catalog: downloaded whole each run (~2 MB).
  * KEV enrichment (publish date, CVSS, SSVC, advisory links, affected versions) cached in kevcache.json;
    only new KEV IDs, IDs changed in the CVE deltaLog since the last run, and old-format rows are re-fetched.
  * Critical CVEs: prior items from critical.json; only records listed new/updated in cvelistV5
    cves/deltaLog.json since (cursor - 1h) are fetched and upserted/removed.
  * deltaLog keeps ~30 days. If the cursor is older (or state is missing) a full rebuild runs.
  * changes.json: diff events between runs (PoC/active newly seen, ransomware use confirmed), 14 days kept.
"""
import argparse, collections, concurrent.futures as cf, datetime as dt, io, json, os, re, statistics, sys, urllib.request, zipfile

DAYS_CVE, DAYS_KEV_LIST, KISA_KEEP_DAYS, CHANGES_KEEP_DAYS = 14, 90, 90, 14
RETAIN_DAYS = 90          # CVE items are kept this long (critical.json)
MAJOR_MIN_SCORE = 7.0     # for widely used products, keep High (7.0+) as well as Critical
ZIP_URL = "https://github.com/CVEProject/cvelistV5/releases/download/cve_{d}_at_end_of_day/{d}_delta_CVEs_at_end_of_day.zip"
# Products widely used in Korean companies and homes. Matched against the CNA vendor (or assigner) name.
MAJOR = [("Synology", r"synology"), ("QNAP", r"qnap"), ("ASUSTOR", r"asustor"), ("ipTIME", r"iptime|efm networks"),
         ("Microsoft", r"^microsoft"), ("Google", r"^google|chrome"), ("Apple", r"^apple"), ("Samsung", r"samsung"),
         ("Mozilla", r"mozilla"), ("Adobe", r"^adobe"), ("Oracle", r"^oracle"), ("Fortinet", r"fortinet"),
         ("Ivanti", r"ivanti"), ("Cisco", r"^cisco"), ("Palo Alto Networks", r"palo ?alto"), ("SonicWall", r"sonicwall"),
         ("Citrix", r"citrix"), ("F5", r"^f5"), ("Juniper", r"juniper"), ("Check Point", r"check ?point"),
         ("VMware", r"vmware|broadcom"), ("Atlassian", r"atlassian"), ("GitLab", r"gitlab"), ("Jenkins", r"jenkins"),
         ("Apache", r"apache software"), ("PHP", r"^php( group)?$"), ("Node.js", r"^node\.?js"), ("nginx", r"nginx"),
         ("OpenSSL", r"openssl"), ("OpenSSH", r"openssh|openbsd"), ("Zoom", r"^zoom"), ("Docker", r"^docker"),
         ("Kubernetes", r"kubernetes"), ("Red Hat", r"red ?hat"), ("SAP", r"^sap\b|^sap se"), ("Hancom", r"hancom|한글과컴퓨터"),
         ("AhnLab", r"ahnlab"), ("TP-Link", r"tp-?link"), ("D-Link", r"d-?link"), ("Zyxel", r"zyxel"),
         ("Hikvision", r"hikvision"), ("Dahua", r"dahua"), ("HPE", r"hewlett|^hpe|aruba"), ("Dell", r"^dell"),
         ("Lenovo", r"lenovo"), ("Veeam", r"veeam"), ("Progress", r"progress software"), ("ConnectWise", r"connectwise"),
         ("BeyondTrust", r"beyondtrust"), ("Grafana", r"grafana"), ("Elastic", r"^elastic"), ("Veritas", r"veritas"),
         ("WinRAR", r"rarlab|win\.?rar"), ("7-Zip", r"7-?zip"), ("Notepad++", r"notepad\+\+"), ("Kakao", r"kakao"), ("Naver", r"naver"),
         # developer / small-service stack
         ("Next.js", r"vercel|next\.?js"), ("Django", r"django"), ("Laravel", r"laravel"), ("WordPress", r"^wordpress"), ("Automattic", r"automattic"),
         ("Ruby on Rails", r"rubyonrails|ruby on rails"), ("Spring", r"^spring|pivotal"), ("Redis", r"^redis"), ("PostgreSQL", r"postgresql"),
         ("MariaDB", r"mariadb"), ("MongoDB", r"mongodb"), ("Express", r"expressjs"), ("Python", r"^python( software foundation)?$"),
         ("Go", r"^golang$|^go$"), ("Rust", r"rust-lang"), ("Supabase", r"supabase"), ("Traefik", r"traefik"), ("Caddy", r"caddy"),
         ("Prometheus", r"prometheus"), ("Nextcloud", r"nextcloud"), ("Gitea", r"gitea|forgejo"), ("n8n", r"^n8n"),
         ("Strapi", r"strapi"), ("HashiCorp", r"hashicorp"), ("Cloudflare", r"cloudflare"), ("Amazon", r"^amazon|^aws"),
         ("LangChain", r"langchain"), ("Ollama", r"ollama"), ("Hugging Face", r"hugging ?face")]
MAJOR_RE = [(n, re.compile(rx, re.I)) for n, rx in MAJOR]
def major_of(vendor, assigner=""):
    # The CNA (assigner) only counts when the record names no vendor: GitLab, Red Hat and others assign CVEs for other people's products.
    v = (vendor or "").strip()
    use_assigner = v.lower() in ("", "n/a", "unknown")
    for n, rx in MAJOR_RE:
        if rx.search(v) or (use_assigner and rx.search(assigner or "")):
            return n
    return ""
RAW = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/"
KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
KCACHE_LEN = 13  # [pub, score, ver, src, av, pr, ui, automatable, techImpact, refs, fix, ransomware, exploitation]

ap = argparse.ArgumentParser()
ap.add_argument("--state"); ap.add_argument("--out", required=True)
ap.add_argument("--kisa"); ap.add_argument("--work"); ap.add_argument("--full", action="store_true")
ap.add_argument("--merge-ko")
A = ap.parse_args()
log = lambda *a: print(*a, file=sys.stderr, flush=True)

def load(path, default=None):
    try:
        return json.load(open(path))
    except Exception:
        return default

def dump(path, body):
    json.dump(body, open(path, "w"), ensure_ascii=False, separators=(",", ":"))

# ======================================================================= merge-ko mode
if A.merge_ko:
    todo = load(os.path.join(A.out, "ko_todo.json"), []) or []
    allowed = {t["id"] for t in todo}
    new = load(A.merge_ko, {}) or {}
    ko_path = os.path.join(A.out, "data", "ko.json")
    ko = load(ko_path, {"items": {}}) or {"items": {}}
    today_s = dt.date.today().isoformat()
    ok = bad = 0
    for cid, text in new.items():
        if cid not in allowed or not isinstance(text, str):
            bad += 1; continue
        t = " ".join(text.split())
        if not (8 <= len(t) <= 180):
            bad += 1; continue
        ko["items"][cid] = {"t": t, "at": today_s}; ok += 1
    dump(ko_path, ko)
    print(json.dumps({"merged": ok, "rejected": bad, "total": len(ko["items"]), "todo": len(allowed)}, ensure_ascii=False))
    sys.exit(0)

if not A.state:
    ap.error("--state is required for a collect run")
WORK = A.work or os.path.join(A.out, "_work")
for p in (A.out, WORK, os.path.join(A.out, "data")):
    os.makedirs(p, exist_ok=True)
now = dt.datetime.now(dt.timezone.utc); today = now.date(); today_s = today.isoformat()

def get(url, timeout=40, tries=3):
    last = None
    for _ in range(tries):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                return r.read()
        except Exception as e:
            last = e
            if getattr(e, "code", None) == 404:
                break
    raise last

def pdate(s):
    if not s: return None
    try:
        t = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)
    except Exception:
        return None

def rec_url(cid):
    _, y, n = cid.split("-")
    return f"{RAW}{y}/{int(n)//1000}xxx/{cid}.json"

# ---------- record helpers
def best_cvss(rec):
    out = []
    cont = rec.get("containers", {})
    blocks = [("CNA", cont.get("cna", {}))] + [("ADP:" + a.get("providerMetadata", {}).get("shortName", "?"), a) for a in cont.get("adp", []) or []]
    for src, b in blocks:
        for m in b.get("metrics", []) or []:
            for k in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
                if k in m and "baseScore" in m[k]:
                    out.append((float(m[k]["baseScore"]), m[k].get("vectorString", ""), src, k.replace("cvssV", "").replace("_", ".")))
    if not out: return None
    cna = [o for o in out if o[2] == "CNA"]
    return max(cna or out, key=lambda o: o[0])

def vec_parts(v):
    return dict(p.split(":", 1) for p in (v or "").split("/") if ":" in p)

def ssvc(rec):
    r = {}
    for a in rec.get("containers", {}).get("adp", []) or []:
        for m in a.get("metrics", []) or []:
            o = m.get("other", {})
            if o.get("type") == "ssvc":
                for opt in o.get("content", {}).get("options", []):
                    for k, v in opt.items():
                        r[k.strip().lower()] = str(v).strip().lower()
    return r

def first_cwe(cna):
    for pt in cna.get("problemTypes", []) or []:
        for d in pt.get("descriptions", []):
            if d.get("cweId"): return d["cweId"]
    return ""

URL_OK = re.compile(r"^https?://[^\s\"'<>]{4,300}$")
SKIP_HOSTS = ("cisa.gov", "nvd.nist.gov", "cve.org", "cve.mitre.org")
def refs_from_record(cna):
    refs = cna.get("references", []) or []
    tagged = [r["url"] for r in refs if r.get("url") and set(r.get("tags") or []) & {"vendor-advisory", "patch", "mitigation", "release-notes"}]
    pool = tagged or [r.get("url") for r in refs[:2]]
    out = []
    for u in pool:
        if u and URL_OK.match(u) and not any(h in u for h in SKIP_HOSTS) and u not in out:
            out.append(u)
    return out[:3]

def refs_from_notes(notes):
    out = []
    for u in re.findall(r"https?://[^\s;]+", notes or ""):
        u = u.rstrip(".,)")
        if URL_OK.match(u) and not any(h in u for h in SKIP_HOSTS) and u not in out:
            out.append(u)
    return out[:3]

HEXHASH = re.compile(r"^[0-9a-f]{12,}$", re.I)
def ver_ok(s):
    """Keep human-readable versions only (no git hashes, no long comma lists)."""
    return len(s) <= 30 and "," not in s and not HEXHASH.match(s)

def fix_from_record(cna):
    """Affected-version summary: list of {p?, from?, lt|le} (max 4)."""
    aff = [a for a in (cna.get("affected", []) or []) if a.get("versions")]
    multi = len({a.get("product") for a in aff}) > 1
    out = []
    for a in aff:
        for v in a.get("versions", []) or []:
            if v.get("status") != "affected": continue
            e = {}
            lt, le = str(v.get("lessThan") or ""), str(v.get("lessThanOrEqual") or "")
            if lt and lt not in ("*", "-") and ver_ok(lt): e["lt"] = lt
            elif le and le not in ("*", "-") and ver_ok(le): e["le"] = le
            else: continue
            fv = str(v.get("version") or "")
            if fv and fv not in ("0", "*", "-", "n/a") and ver_ok(fv): e["from"] = fv
            if multi: e["p"] = (a.get("product") or "")[:50]
            if e not in out: out.append(e)
            if len(out) >= 4: return out
    return out

EDGE_VENDORS = re.compile(r"\b(fortinet|ivanti|pulse secure|citrix|palo alto|sonicwall|juniper|f5|check point|zyxel|d-link|tp-link|totolink|netgear|draytek|sophos|watchguard|barracuda|array networks|sangfor|tenda|ruijie|four-faith|digiever|arista|versa|cyberoam|mikrotik)\b", re.I)
EDGE_PRODUCTS = re.compile(r"(vpn|firewall|gateway|router|fortios|fortigate|fortiweb|fortimanager|fortiproxy|pan-os|globalprotect|netscaler|connect secure|policy secure|big-ip|sonicos|\bsma\b|junos|\basa\b|adaptive security|firepower|secure firewall|ios xe|sd-wan|velocloud|expressway|edge router)", re.I)
def is_edge(vendor, product):
    return bool(EDGE_VENDORS.search(vendor or "") or EDGE_PRODUCTS.search(product or ""))

def sev_band(s):
    if s is None: return "none"
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low" if s > 0 else "none"

def is_hot(c):
    return c.get("av") == "N" and c.get("pr") == "N" and c.get("ui") in ("N", None) and \
        (c.get("kev") or c.get("exploitation") in ("poc", "public poc", "active"))

# ---------- load prior state
S = A.state
prior_meta = load(os.path.join(S, "meta.json"), {}) or {}
prior_crit = (load(os.path.join(S, "store.json"), {}) or {}).get("items") or (load(os.path.join(S, "critical.json"), {}) or {}).get("items", []) or []
prior_crit_by = {c["id"]: c for c in prior_crit}
kevcache = ((load(os.path.join(S, "kevcache.json"), {}) or {}).get("items")) or {}
prior_kevcache = {k: list(v) for k, v in kevcache.items()}
prior_kisa = (load(os.path.join(S, "kisa.json"), {}) or {}).get("items", []) or []
prior_ko = (load(os.path.join(S, "ko.json"), {}) or {}).get("items", {}) or {}
prior_changes = (load(os.path.join(S, "changes.json"), {}) or {}).get("days", []) or []
prior_pkg = load(os.path.join(S, "packages.json"), {}) or {}

# ---------- downloads
kev = json.loads(get(KEV_URL, 90)); kv = kev["vulnerabilities"]; kev_ids = {v["cveID"] for v in kv}
kv_by = {v["cveID"]: v for v in kv}
dl_path = os.path.join(WORK, "deltaLog.json")
open(dl_path, "wb").write(get(RAW + "deltaLog.json", 180))
delta = json.load(open(dl_path))
times = [pdate(d["fetchTime"]) for d in delta]
oldest, newest = min(times), max(times)

cursor = pdate(prior_meta.get("deltaCursor"))
reason = None
if A.full: reason = "--full"
elif not cursor: reason = "no cursor in state"
elif not kevcache: reason = "no kevcache in state"
elif cursor - dt.timedelta(hours=1) < oldest: reason = "cursor older than deltaLog window"
FULL = reason is not None
cut = now - dt.timedelta(days=DAYS_CVE)
retain_cut = now - dt.timedelta(days=RETAIN_DAYS)
today0 = dt.datetime.combine(today, dt.time(0), tzinfo=dt.timezone.utc)
since = today0 if FULL else cursor - dt.timedelta(hours=1)

changed = {}
for d, t in zip(delta, times):
    if t >= since:
        for n in d.get("new", []) + d.get("updated", []):
            changed[n["cveId"]] = n["githubLink"]
log("mode", "FULL (" + reason + ")" if FULL else "INCREMENTAL", "since", since.isoformat(), "changed", len(changed))

# ---------- KEV enrichment (cached)
def fetch_kev_enrich(cid):
    try:
        rec = json.loads(get(rec_url(cid)))
    except Exception:
        return cid, None
    cna = rec.get("containers", {}).get("cna", {})
    tp = pdate(rec.get("cveMetadata", {}).get("datePublished"))
    c = best_cvss(rec); sv = ssvc(rec); vp = vec_parts(c[1] if c else "")
    return cid, [tp.date().isoformat() if tp else None, c[0] if c else None, c[3] if c else None, c[2] if c else None,
                 vp.get("AV"), vp.get("PR"), vp.get("UI"), sv.get("automatable"), sv.get("technical impact"),
                 refs_from_record(cna), fix_from_record(cna), None, sv.get("exploitation")]

if FULL:
    need_kev = sorted(kev_ids)
else:
    need_kev = sorted({c for c in kev_ids if c not in kevcache or len(kevcache[c]) < KCACHE_LEN or c in changed})
kev_fail = 0
with cf.ThreadPoolExecutor(48) as ex:
    for cid, row in ex.map(fetch_kev_enrich, need_kev):
        if row: kevcache[cid] = row
        elif cid not in kevcache: kev_fail += 1
kevcache = {k: (list(v) + [None] * KCACHE_LEN)[:KCACHE_LEN] for k, v in kevcache.items() if k in kev_ids}
log("kev enrich fetched", len(need_kev), "failed(new)", kev_fail)

events = []  # diff events for changes.json
kev_all = []
for v in kv:
    cid = v["cveID"]
    c = kevcache.get(cid) or [None] * KCACHE_LEN
    rw = v.get("knownRansomwareCampaignUse", "Unknown")
    prev = prior_kevcache.get(cid)
    if prev and len(prev) >= 12 and prev[11] and prev[11] != "Known" and rw == "Known":
        events.append({"type": "kev_ransomware", "id": cid, "vendor": v["vendorProject"], "product": v["product"]})
    c[11] = rw
    kevcache[cid] = c
    lag = (dt.date.fromisoformat(v["dateAdded"]) - dt.date.fromisoformat(c[0])).days if c[0] else None
    note_refs = refs_from_notes(v.get("notes", ""))
    refs = (note_refs + [u for u in (c[9] or []) if u not in note_refs])[:3]
    kev_all.append({
        "id": cid, "vendor": v["vendorProject"], "product": v["product"], "name": v["vulnerabilityName"],
        "added": v["dateAdded"], "due": v["dueDate"], "action": v["requiredAction"][:300],
        "ransomware": rw, "forensic": str(v.get("forensicTriage", "")).lower() == "yes",
        "summary": v["shortDescription"][:420],
        "cwes": v.get("cwes", []) or [], "published": c[0], "lagDays": lag, "score": c[1], "cvssVersion": c[2],
        "scoreSource": c[3], "av": c[4], "pr": c[5], "ui": c[6], "automatable": c[7], "techImpact": c[8],
        "refs": refs, "fix": c[10] or [], "edge": is_edge(v["vendorProject"], v["product"]),
    })

# ---------- critical CVEs (upsert)
SKIP = object()
def process_record(rec):
    """CVE record -> stored item, or None when it does not qualify (any more)."""
    meta = rec.get("cveMetadata", {})
    cid = meta.get("cveId")
    if not cid or meta.get("state") != "PUBLISHED": return None
    tp = pdate(meta.get("datePublished"))
    if not tp or tp < retain_cut: return None
    c = best_cvss(rec)
    if not c: return None
    cna = rec.get("containers", {}).get("cna", {})
    aff = cna.get("affected", []) or []
    vendor = (aff[0].get("vendor", "") if aff else "")[:80]; product = (aff[0].get("product", "") if aff else "")[:80]
    major = major_of(vendor, meta.get("assignerShortName", ""))
    if c[0] < 9.0 and not (major and c[0] >= MAJOR_MIN_SCORE): return None
    desc = next((d["value"] for d in cna.get("descriptions", []) if d.get("lang", "").startswith("en")), "")
    vp = vec_parts(c[1]); sv = ssvc(rec)
    products = []
    for a in aff:
        pn = (a.get("product") or "")[:60]
        if pn and pn not in products: products.append(pn)
    return {
        "id": cid, "published": tp.date().isoformat(), "score": c[0], "cvssVersion": c[3], "vector": c[1], "scoreSource": c[2],
        "vendor": vendor, "product": product, "cwe": first_cwe(cna)[:40], "summary": desc[:420],
        "assigner": meta.get("assignerShortName", ""), "exploitation": sv.get("exploitation"),
        "automatable": sv.get("automatable"), "techImpact": sv.get("technical impact"),
        "av": vp.get("AV"), "pr": vp.get("PR"), "ui": vp.get("UI"), "kev": False, "edge": False,
        "refs": refs_from_record(cna), "fix": fix_from_record(cna), "major": major, "products": products[:6],
    }

def fetch_crit(item):
    cid, url = item
    try:
        rec = json.loads(get(url))
    except Exception:
        return cid, SKIP
    return cid, process_record(rec)

def fetch_zip_day(d):
    try:
        return d, zipfile.ZipFile(io.BytesIO(get(ZIP_URL.format(d=d), 300)))
    except Exception as e:
        log("zip failed", d, e)
        return d, None

cut_d = cut.date().isoformat()
retain_d = retain_cut.date().isoformat()
crit_map = {} if FULL else {c["id"]: c for c in prior_crit if c.get("published", "") >= retain_d}
added = updated = removed = skipped = zip_fail = 0
if FULL:
    # Backfill RETAIN_DAYS from the daily delta archives (each holds every record changed that day), oldest first.
    zdays = [(today - dt.timedelta(days=i)).isoformat() for i in range(RETAIN_DAYS, 0, -1)]
    with cf.ThreadPoolExecutor(6) as ex:
        for d, z in ex.map(fetch_zip_day, zdays):
            if z is None:
                zip_fail += 1; continue
            for name in z.namelist():
                if not name.endswith(".json"): continue
                try:
                    rec = json.loads(z.read(name))
                except Exception:
                    continue
                cid = rec.get("cveMetadata", {}).get("cveId")
                if not cid: continue
                r = process_record(rec)
                if r is None:
                    crit_map.pop(cid, None)
                else:
                    crit_map[cid] = r
    log("backfill days", len(zdays), "zip failures", zip_fail, "items", len(crit_map))
need_upgrade = [] if FULL else [cid for cid, c in crit_map.items() if "products" not in c and cid not in changed]
targets = dict(changed)
for cid in need_upgrade:
    targets[cid] = rec_url(cid)
with cf.ThreadPoolExecutor(48) as ex:
    for cid, r in ex.map(fetch_crit, targets.items()):
        if r is SKIP: skipped += 1; continue
        if r is None:
            if cid in crit_map: del crit_map[cid]; removed += 1
            continue
        if cid in crit_map: updated += 1
        else: added += 1
        crit_map[cid] = r
crit = list(crit_map.values())
for c in crit:
    c["major"] = major_of(c["vendor"], c.get("assigner", ""))   # re-derive so list changes apply to stored items
    c["kev"] = c["id"] in kev_ids
    c["edge"] = is_edge(c["vendor"], c["product"])
    p = prior_crit_by.get(c["id"])
    if p is not None:
        pe, ne = p.get("exploitation"), c.get("exploitation")
        if ne == "active" and pe != "active":
            events.append({"type": "crit_active", "id": c["id"], "vendor": c["vendor"], "product": c["product"]})
        elif ne in ("poc", "public poc") and pe not in ("poc", "public poc", "active"):
            events.append({"type": "crit_poc", "id": c["id"], "vendor": c["vendor"], "product": c["product"]})
# KEV-listed CVEs: SSVC exploitation upgrades from kevcache
for cid, row in kevcache.items():
    prev = prior_kevcache.get(cid)
    if prev and len(prev) >= KCACHE_LEN and row[12] == "active" and prev[12] not in ("active", None) and cid not in crit_map:
        v = kv_by[cid]
        events.append({"type": "crit_active", "id": cid, "vendor": v["vendorProject"], "product": v["product"]})
crit.sort(key=lambda r: (r["published"], r["score"]), reverse=True)
crit_all = crit                                     # stored: 90 days, >=9.0 or major >=7.0
crit = [c for c in crit_all if c["score"] >= 9.0 and c["published"] >= cut_d]   # insights window: 14 days, >=9.0
log("critical total", len(crit), "added", added, "updated", updated, "removed", removed, "fetch-failed", skipped, "events", len(events))

# ---------- changes.json (diff events, merged per day)
days = {d["date"]: d for d in prior_changes if d.get("date", "") >= (today - dt.timedelta(days=CHANGES_KEEP_DAYS)).isoformat()}
if prior_kevcache or prior_crit:  # only diff against a real previous state
    day = days.setdefault(today_s, {"date": today_s, "items": []})
    seen = {(e["type"], e["id"]) for e in day["items"]}
    for e in events:
        if (e["type"], e["id"]) not in seen:
            day["items"].append(e); seen.add((e["type"], e["id"]))
    day["runAt"] = now.isoformat(timespec="seconds")
changes = {"days": sorted(days.values(), key=lambda d: d["date"], reverse=True)}

# ---------- KISA notices
kisa_status, kisa_new = "skipped", 0
KISA_VENDOR = re.compile(r"^(.+?)\s*제품\s*보안\s*업데이트\s*권고")
KISA_VENDOR2 = re.compile(r"^([A-Za-z0-9][A-Za-z0-9.+_ -]{0,30}?)\s*(?:신규\s*)?(?:보안\s*)?취약점")
def kisa_norm(it):
    m = re.search(r"nttId=(\d+)", str(it.get("url", "") or ""))
    if m: ntt = m.group(1)
    elif re.fullmatch(r"\d+", str(it.get("nttId", ""))): ntt = str(it["nttId"])
    else: return None
    title = " ".join(str(it.get("title", "")).split())[:200]
    date = str(it.get("date", ""))[:10]
    if not title or not re.match(r"^\d{4}-\d{2}-\d{2}$", date): return None
    vm = KISA_VENDOR.match(title); vm2 = None if vm else KISA_VENDOR2.match(title)
    return {"ntt": ntt, "title": title, "date": date,
            "url": f"https://www.boho.or.kr/kr/bbs/view.do?bbsId=B0000133&nttId={ntt}&menuNo=205020",
            "vendor": (vm or vm2).group(1).strip() if (vm or vm2) else "", "kind": "update" if vm else ("vuln" if vm2 else "notice"),
            "cves": sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", title)))}
kisa_map = {k["ntt"]: k for k in prior_kisa if k.get("ntt")}
if A.kisa:
    raw = load(A.kisa, None)
    if isinstance(raw, list) and raw:
        for it in raw:
            n = kisa_norm(it) if isinstance(it, dict) else None
            if n:
                if n["ntt"] not in kisa_map and n["date"] >= (today - dt.timedelta(days=KISA_KEEP_DAYS)).isoformat(): kisa_new += 1
                kisa_map[n["ntt"]] = n
        kisa_status = "ok"
    else:
        kisa_status = "failed"
keep_from = (today - dt.timedelta(days=KISA_KEEP_DAYS)).isoformat()
kisa_items = sorted([k for k in kisa_map.values() if k["date"] >= keep_from], key=lambda k: (k["date"], k["ntt"]), reverse=True)


# ---------- package advisories (GitHub reviewed High/Critical) and malicious packages (OpenSSF), read from public git repos
import shutil, subprocess
PKG_DAYS, MAL_DAYS = 30, 14
GHSA_RE = re.compile(r"^GHSA(-[0-9a-z]{4}){3}$")
MAL_RE = re.compile(r"^MAL-\d{4}-\d{1,8}$")
GIT_ENV = dict(os.environ, GIT_TERMINAL_PROMPT="0")
def git(args, cwd=None, timeout=300, inp=None):
    r = subprocess.run(["git", "-c", "core.quotepath=off", "-c", "core.hooksPath=/dev/null"] + args, cwd=cwd, env=GIT_ENV,
                       capture_output=True, text=True, timeout=timeout, input=inp)
    if r.returncode != 0:
        raise RuntimeError("git " + " ".join(args[:2]) + ": " + (r.stderr or "")[-200:])
    return r.stdout
def clean(x, n):
    return " ".join(str(x or "").split())[:n]
def fetch_ghsa():
    d = os.path.join(WORK, "ghsa"); shutil.rmtree(d, ignore_errors=True)
    git(["clone", "-q", "--depth", "1", "--filter=blob:none", "--sparse", "https://github.com/github/advisory-database.git", d])
    months = sorted({(today - dt.timedelta(days=i)).strftime("%Y/%m") for i in range(0, PKG_DAYS + 3)})
    git(["sparse-checkout", "set"] + ["advisories/github-reviewed/" + m for m in months], cwd=d)
    cut_s = (today - dt.timedelta(days=PKG_DAYS)).isoformat()
    out = []
    for m in months:
        base = os.path.join(d, "advisories", "github-reviewed", m)
        if not os.path.isdir(base): continue
        for root, _, names in os.walk(base):
            for fn in names:
                if not fn.endswith(".json"): continue
                try: a = json.load(open(os.path.join(root, fn)))
                except Exception: continue
                gid = a.get("id", "")
                if not GHSA_RE.match(gid) or a.get("withdrawn"): continue
                sv = ((a.get("database_specific") or {}).get("severity") or "").upper()
                pub = str(a.get("published", ""))[:10]
                if sv not in ("CRITICAL", "HIGH") or pub < cut_s: continue
                pk, seen = [], set()
                for af in a.get("affected") or []:
                    pp = af.get("package") or {}
                    e, n = clean(pp.get("ecosystem"), 24), clean(pp.get("name"), 120)
                    if not e or not n or (e, n) in seen: continue
                    seen.add((e, n))
                    fx = []
                    for rg in af.get("ranges") or []:
                        for ev in rg.get("events") or []:
                            if ev.get("fixed"): fx.append(clean(ev["fixed"], 40))
                    pk.append({"e": e, "n": n, "fix": fx[:2]})
                if not pk: continue
                cves = [x for x in (a.get("aliases") or []) if re.match(r"^CVE-\d{4}-\d{4,}$", str(x))]
                out.append({"id": gid, "cve": cves[0] if cves else "", "sev": "C" if sv == "CRITICAL" else "H", "pub": pub,
                            "s": clean(a.get("summary"), 160), "p": pk[:4], "np": len(pk), "kev": bool(cves and cves[0] in kev_ids)})
    out.sort(key=lambda x: (x["kev"], x["sev"] == "C", x["pub"], x["id"]), reverse=True)
    return out[:800]
def fetch_mal():
    d = os.path.join(WORK, "mal"); shutil.rmtree(d, ignore_errors=True)
    since = (today - dt.timedelta(days=MAL_DAYS)).isoformat()
    git(["clone", "-q", "--filter=blob:none", "--no-checkout", "--shallow-since=" + since, "https://github.com/ossf/malicious-packages.git", d])
    roots = git(["rev-list", "--max-parents=0", "HEAD"], cwd=d).split()
    if not roots: return []
    names = git(["diff", "--name-only", "-z", "--diff-filter=A", roots[-1], "HEAD", "--", "osv/malicious"], cwd=d).split("\0")
    paths = [x for x in names if x and re.match(r"^osv/malicious/[^/]+/.+/MAL-\d{4}-\d+\.json$", x) and "\n" not in x]
    if not paths: return []
    git(["checkout", "HEAD", "--pathspec-from-file=-", "--pathspec-file-nul"], cwd=d, inp="\0".join(paths) + "\0")
    cut_s = since; out = []
    for x in paths:
        try: a = json.load(open(os.path.join(d, x)))
        except Exception: continue
        mid = a.get("id", ""); pub = str(a.get("published", ""))[:10]
        if not MAL_RE.match(mid) or a.get("withdrawn") or pub < cut_s: continue
        pp = ((a.get("affected") or [{}])[0].get("package")) or {}
        e, n = clean(pp.get("ecosystem"), 24), clean(pp.get("name"), 120)
        if not e or not n: continue
        g = [x for x in (a.get("aliases") or []) if GHSA_RE.match(str(x))]
        out.append({"id": mid, "e": e, "n": n, "pub": pub, "g": g[0] if g else ""})
    out.sort(key=lambda x: (x["pub"], x["id"]), reverse=True)
    return out[:2500]
pkg_status = {}
pkg_ghsa, pkg_mal = prior_pkg.get("ghsa", []) or [], prior_pkg.get("mal", []) or []
for nm, fn in (("ghsa", fetch_ghsa), ("mal", fetch_mal)):
    try:
        res = fn(); pkg_status[nm] = "ok"
        if nm == "ghsa": pkg_ghsa = res
        else: pkg_mal = res
        log("packages", nm, len(res))
    except Exception as e:
        pkg_status[nm] = "failed"; log("packages", nm, "FAILED", str(e)[:200])
pkg_cut = (today - dt.timedelta(days=PKG_DAYS)).isoformat(); mal_cut = (today - dt.timedelta(days=MAL_DAYS)).isoformat()
pkg_ghsa = [x for x in pkg_ghsa if x.get("pub", "") >= pkg_cut]; pkg_mal = [x for x in pkg_mal if x.get("pub", "") >= mal_cut]

# ---------- aggregates (insights)
def months_back(n):
    y, m, out = today.year, today.month, []
    for _ in range(n):
        out.append(f"{y:04d}-{m:02d}"); m -= 1
        if m == 0: y, m = y - 1, 12
    return out[::-1]
mc = {m: [0, 0] for m in months_back(24)}
for k in kev_all:
    if k["added"][:7] in mc:
        mc[k["added"][:7]][0] += 1
        if k["ransomware"] == "Known": mc[k["added"][:7]][1] += 1
monthly = [{"month": m, "total": a, "ransomware": b} for m, (a, b) in mc.items()]
y_cut = (today - dt.timedelta(days=365)).isoformat()
k12 = [k for k in kev_all if k["added"] >= y_cut]
lags = [k["lagDays"] for k in k12 if k["lagDays"] is not None]
B = [("le0", "공개 당일·이전", lambda x: x <= 0), ("d7", "1–7일", lambda x: 1 <= x <= 7), ("d30", "8–30일", lambda x: 8 <= x <= 30),
     ("d365", "31일–1년", lambda x: 31 <= x <= 365), ("old", "1년 초과", lambda x: x > 365)]
lag_dist = [{"key": k, "label": l, "count": sum(1 for x in lags if f(x))} for k, l, f in B]
lag_by_year = []
for y in range(today.year - 3, today.year + 1):
    ys = [k["lagDays"] for k in kev_all if k["added"].startswith(str(y)) and k["lagDays"] is not None]
    rec_ = [x for x in ys if x <= 365]
    lag_by_year.append({"year": y, "n": len(ys), "medianRecent": statistics.median(rec_) if rec_ else None,
                        "within7": sum(1 for x in ys if x <= 7), "over1y": sum(1 for x in ys if x > 365)})
sevc = collections.Counter(sev_band(k["score"]) for k in k12)
kev_sev = [{"key": s, "label": l, "count": sevc.get(s, 0)} for s, l in
           [("critical", "Critical 9.0+"), ("high", "High 7.0–8.9"), ("medium", "Medium 4.0–6.9"), ("low", "Low"), ("none", "점수 없음")]]
def top(counter, n):
    return [{"label": a, "count": b} for a, b in counter.most_common() if a != "(미분류)"][:n]
def vtop(names, n):
    g = collections.defaultdict(collections.Counter)
    for x in names: g[x.lower()][x] += 1
    rows = sorted(({"label": c.most_common(1)[0][0], "count": sum(c.values())} for c in g.values()), key=lambda r: -r["count"])
    return rows[:n]
# ---------- product update groups (major vendors, vendor x publish date)
groups = {}
for c in crit_all:
    if not c.get("major"): continue
    gid = (c["major"].replace(" ", "_") + ":" + c["published"])
    g = groups.setdefault(gid, {"gid": gid, "vendor": c["major"], "date": c["published"], "products": [], "cves": [],
                                "maxScore": 0, "nCrit": 0, "nRemote": 0, "kev": [], "exploited": [], "refs": []})
    g["cves"].append(c["id"]); g["maxScore"] = max(g["maxScore"], c["score"])
    if c["score"] >= 9: g["nCrit"] += 1
    if c.get("av") == "N" and c.get("pr") == "N" and c.get("ui") in ("N", None): g["nRemote"] += 1
    if c["id"] in kev_ids: g["kev"].append(c["id"])
    if c.get("exploitation") in ("poc", "public poc", "active"): g["exploited"].append(c["id"])
    for p in c.get("products") or [c.get("product")]:
        if p and p not in g["products"] and len(g["products"]) < 8: g["products"].append(p)
    for u in c.get("refs") or []:
        if u not in g["refs"] and len(g["refs"]) < 3: g["refs"].append(u)
updates = sorted(groups.values(), key=lambda g: (g["date"], g["maxScore"]), reverse=True)
by_id = {c["id"]: c for c in crit_all}
for g in updates:
    its = sorted([by_id[i] for i in g["cves"] if i in by_id], key=lambda c: -c["score"])
    g["count"] = len(its)
    g["items"] = [{"id": c["id"], "score": c["score"], "product": c["product"], "av": c.get("av"), "pr": c.get("pr"), "ui": c.get("ui"),
                   "cwe": c.get("cwe", ""), "d": c["summary"][:160]} for c in its[:10]]
    fixes, seen = [], set()
    for c in its:
        for f in c.get("fix") or []:
            if not f.get("lt"): continue
            k = ((f.get("p") or c["product"] or "") + " " + f["lt"]).strip()
            if k not in seen and len(fixes) < 4:
                seen.add(k); fixes.append(k + " 이상")
    g["fixes"] = fixes
    g["cves"] = [c["id"] for c in its]

f_net = [c for c in crit if c["av"] == "N"]; f_na = [c for c in f_net if c["pr"] == "N"]
f_nu = [c for c in f_na if c["ui"] in ("N", None)]
f_sig = [c for c in f_nu if c["kev"] or c["exploitation"] in ("poc", "public poc", "active")]
dlist = [(today - dt.timedelta(days=i)).isoformat() for i in range(DAYS_CVE - 1, -1, -1)]
dc = collections.Counter(c["published"] for c in crit)
insights = {
    "kevWindowFrom": y_cut, "kevWindowCount": len(k12), "kevLagKnown": len(lags),
    "kevLagMedian": statistics.median(lags) if lags else None, "kevLagDist": lag_dist, "kevLagByYear": lag_by_year,
    "kevSeverity": kev_sev, "kevVendors": vtop([k["vendor"] for k in k12], 10),
    "kevCwe": top(collections.Counter(c for k in k12 for c in (k["cwes"][:1] or ["(미분류)"])), 8),
    "kevEdge": sum(1 for k in k12 if k["edge"]), "kevRansomware": sum(1 for k in k12 if k["ransomware"] == "Known"),
    "kevMonthly": monthly,
    "critFunnel": [{"key": "all", "label": "CVSS 9.0+ 신규", "count": len(crit)},
                   {"key": "net", "label": "네트워크로 공격 가능 (AV:N)", "count": len(f_net)},
                   {"key": "noauth", "label": "+ 인증 불필요 (PR:N)", "count": len(f_na)},
                   {"key": "noui", "label": "+ 사용자 조작 불필요 (UI:N)", "count": len(f_nu)},
                   {"key": "sig", "label": "+ PoC·악용 확인 또는 KEV", "count": len(f_sig)}],
    "critDaily": [{"date": d, "count": dc.get(d, 0)} for d in dlist],
    "critVendors": vtop([(c["vendor"] if c["vendor"].strip().lower() not in ("", "n/a", "unknown") else (c["assigner"] or "(미상)")).strip() for c in crit], 10),
    "critCwe": top(collections.Counter(c["cwe"] or "(미분류)" for c in crit), 8),
    "critSsvc": {"exploitation": dict(collections.Counter(c["exploitation"] or "unknown" for c in crit)),
                 "automatableYes": sum(1 for c in crit if c["automatable"] == "yes"),
                 "totalImpact": sum(1 for c in crit if c["techImpact"] == "total"),
                 "autoAndTotal": sum(1 for c in crit if c["automatable"] == "yes" and c["techImpact"] == "total"),
                 "rated": sum(1 for c in crit if c["exploitation"])},
    "kevCweUnclassified": sum(1 for k in k12 if not k["cwes"]),
    "critCweUnclassified": sum(1 for c in crit if not c["cwe"]),
    "critCvssVersion": dict(collections.Counter(c["cvssVersion"] for c in crit)),
    "critEdge": sum(1 for c in crit if c["edge"]),
}

# ---------- Korean one-liner work list
list_cut = (today - dt.timedelta(days=DAYS_KEV_LIST)).isoformat()
kev_list = sorted([k for k in kev_all if k["added"] >= list_cut], key=lambda k: k["added"], reverse=True)
cand = [k for k in kev_all if k["added"] >= (today - dt.timedelta(days=30)).isoformat()]
cand_ids = {k["id"] for k in cand}
hot = sorted([c for c in crit if is_hot(c) and c["id"] not in cand_ids], key=lambda c: (c["published"], c["score"]), reverse=True)[:20]
keep_ids = {k["id"] for k in kev_list} | {c["id"] for c in crit_all} | {g["gid"] for g in updates}
ko_items = {k: v for k, v in prior_ko.items() if k in keep_ids}
def todo_row(x, kind):
    return {"id": x["id"], "kind": kind, "vendor": x["vendor"], "product": x["product"], "name": x.get("name", ""),
            "description": x["summary"][:300], "fix": x.get("fix", [])[:3],
            "score": x.get("score"), "vector": x.get("vector") or "/".join(f"{a}:{b}" for a, b in (("AV", x.get("av")), ("PR", x.get("pr")), ("UI", x.get("ui"))) if b),
            "exploitation": "active (KEV)" if kind == "kev" else x.get("exploitation"),
            "ransomware": x.get("ransomware"), "forensicTriage": x.get("forensic")}
def group_row(g):
    items = [by_id[i] for i in g["cves"] if i in by_id]
    items.sort(key=lambda c: -c["score"])
    return {"id": g["gid"], "kind": "update", "vendor": g["vendor"], "date": g["date"], "products": g["products"],
            "maxScore": g["maxScore"], "count": len(g["cves"]), "remoteNoAuth": g["nRemote"], "kev": g["kev"], "exploited": g["exploited"],
            "cves": [{"id": c["id"], "score": c["score"], "product": c["product"], "cwe": c.get("cwe", ""),
                      "remote": c.get("av") == "N" and c.get("pr") == "N", "description": c["summary"][:140], "fix": [f for f in (c.get("fix") or []) if f.get("lt")][:2]} for c in items[:4]]}
def worth(g):
    if g["kev"]: return True
    if g["date"] >= cut_d: return g["maxScore"] >= 9.0 or bool(g["exploited"]) or g["nRemote"] > 0
    return g["maxScore"] >= 9.0 and g["nRemote"] > 0
grp_todo = [g for g in updates if g["gid"] not in ko_items and worth(g)]
grp_todo.sort(key=lambda g: (bool(g["kev"]), g["date"], g["maxScore"]), reverse=True)
grp_todo = grp_todo[:15]   # keeps the daily summary work small; any backlog drains over several days and the page shows a template sentence meanwhile
ko_todo = [todo_row(k, "kev") for k in cand if k["id"] not in ko_items] + [todo_row(c, "critical") for c in hot if c["id"] not in ko_items] \
          + [group_row(g) for g in grp_todo]
json.dump(ko_todo, open(os.path.join(A.out, "ko_todo.json"), "w"), ensure_ascii=False, indent=1)

# ---------- write files
meta = {"generatedAt": now.isoformat(timespec="seconds"), "kevCatalogVersion": kev.get("catalogVersion"),
        "kevTotal": kev.get("count"), "windowCveDays": DAYS_CVE, "windowKevDays": DAYS_KEV_LIST,
        "kevCount": len(kev_list), "criticalCount": len(crit), "storedCount": len(crit_all), "retainDays": RETAIN_DAYS,
        "deltaCursor": newest.isoformat(), "mode": "full" if FULL else "incremental",
        "kisaStatus": kisa_status, "kisaFetchedAt": now.isoformat(timespec="seconds") if kisa_status == "ok" else prior_meta.get("kisaFetchedAt"),
        "pkgStatus": pkg_status}
ARCH_KEYS = ("id", "published", "score", "vendor", "product", "major", "av", "pr", "ui", "exploitation", "kev", "edge", "cwe", "assigner")
def arch(c):
    o = {k: c.get(k) for k in ARCH_KEYS if c.get(k) not in (None, "", [], False)}
    o["summary"] = c["summary"][:140]
    if c.get("fix"): o["fix"] = c["fix"][:2]
    if c.get("refs"): o["refs"] = c["refs"][:1]
    return o
def store_item(c):
    o = dict(c); o["summary"] = c["summary"][:240]; return o
recent9 = [c for c in crit_all if c["score"] >= 9.0 and c["published"] >= cut_d]
archive9 = [arch(c) for c in crit_all if c["score"] >= 9.0 and c["published"] < cut_d]
docs = {"meta": meta, "insights": insights, "kev": {"items": kev_list}, "critical": {"items": recent9},
        "archive": {"items": archive9}, "updates": {"items": updates}, "store": {"items": [store_item(c) for c in crit_all]},
        "kevcache": {"updatedAt": meta["generatedAt"], "items": kevcache},
        "kisa": {"items": kisa_items}, "ko": {"items": ko_items}, "changes": changes,
        "packages": {"updatedAt": meta["generatedAt"], "ghsaDays": PKG_DAYS, "malDays": MAL_DAYS, "ghsa": pkg_ghsa, "mal": pkg_mal}}
sizes = {}
for name, body in docs.items():
    p = os.path.join(A.out, "data", name + ".json")
    dump(p, body)
    sizes[name] = os.path.getsize(p)
    if sizes[name] > 15_000_000:
        log("ERROR file too large", name, sizes[name]); sys.exit(2)
summary = {"mode": meta["mode"], "reason": reason, "since": since.isoformat(), "cursor": meta["deltaCursor"],
           "changedRecords": len(changed), "kevEnrichFetched": len(need_kev), "kevTotal": len(kev_ids),
           "kevNew7d": sum(1 for k in kev_all if k["added"] >= (today - dt.timedelta(days=7)).isoformat()),
           "critical": len(crit), "critAdded": added, "critUpdated": updated, "critRemoved": removed,
           "fetchFailed": skipped + kev_fail, "zipFailed": zip_fail, "stored": len(crit_all), "updateGroups": len(updates), "hot": len(f_sig), "events": len(events),
           "pkgStatus": pkg_status, "pkgAdvisories": len(pkg_ghsa), "pkgCritical": sum(1 for x in pkg_ghsa if x["sev"] == "C"), "pkgMalicious": len(pkg_mal),
           "kisaStatus": kisa_status, "kisaNew": kisa_new, "kisaTotal": len(kisa_items),
           "koTodo": len(ko_todo), "koKept": len(ko_items), "sizes": sizes,
           "files": {"data/" + n + ".json": os.path.abspath(os.path.join(A.out, "data", n + ".json")) for n in docs}}
json.dump(summary, open(os.path.join(A.out, "summary.json"), "w"), ensure_ascii=False, indent=1)
print(json.dumps({k: v for k, v in summary.items() if k != "files"}, ensure_ascii=False))
