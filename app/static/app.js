(function(){
  "use strict";
  var LS = {
    get: function(k, d){ try{ var v = localStorage.getItem(k); return v ? JSON.parse(v) : d; }catch(e){ return d; } },
    set: function(k, v){ try{ localStorage.setItem(k, JSON.stringify(v)); }catch(e){} }
  };
  // This server edition shows everything; there is no per-viewer product list.
  var watch = [];
  var done = LS.get("radar.done", {});
  var state = {
    view:"insights", scope:(watch.length ? "mine" : "all"), q:"", hideDone:false, sort:"risk",
    range:{kev:30, critical:14}, shown:40,
    kf:{rw:false, edge:false, fast:false, old:false},
    cf:{rce:false, sig:false, edge:false, auto:false}
  };
  var data = { pkg:{ghsa:[], mal:[]}, meta:null, ins:null, kev:[], critical:[], kisa:[], ko:{}, changes:[], updates:[], archiveLoaded:false };
  var REPORT_URL = location.origin + location.pathname;
  var CWE = {"CWE-78":"OS 명령어 삽입","CWE-77":"명령어 삽입","CWE-94":"코드 삽입","CWE-22":"경로 조작","CWE-23":"경로 조작","CWE-287":"부적절한 인증","CWE-306":"인증 누락","CWE-288":"대체 경로 인증 우회","CWE-290":"스푸핑 인증 우회","CWE-502":"역직렬화","CWE-416":"해제 후 사용(UAF)","CWE-787":"범위 밖 쓰기","CWE-125":"범위 밖 읽기","CWE-89":"SQL 삽입","CWE-79":"XSS","CWE-434":"위험한 파일 업로드","CWE-20":"입력 검증 미흡","CWE-269":"권한 관리 오류","CWE-862":"권한 확인 누락","CWE-863":"잘못된 권한 확인","CWE-918":"SSRF","CWE-798":"하드코딩된 자격증명","CWE-843":"타입 혼동","CWE-122":"힙 오버플로","CWE-121":"스택 오버플로","CWE-120":"버퍼 오버플로","CWE-119":"메모리 경계 오류","CWE-352":"CSRF","CWE-611":"XXE","CWE-639":"권한 없는 객체 접근(IDOR)","CWE-284":"접근 제어 미흡","CWE-276":"잘못된 기본 권한","CWE-200":"정보 노출","CWE-1321":"프로토타입 오염","CWE-74":"삽입(Injection)","CWE-917":"표현식 언어 삽입","CWE-400":"리소스 고갈","CWE-190":"정수 오버플로","CWE-59":"링크 추적","CWE-427":"검색 경로 조작","CWE-345":"진위 검증 미흡","CWE-693":"보호 기능 실패","CWE-1336":"템플릿 삽입","CWE-732":"잘못된 권한 설정","CWE-770":"무제한 리소스 할당","CWE-401":"메모리 누수","CWE-476":"NULL 역참조","CWE-305":"주요 약점 인증 우회","CWE-912":"숨겨진 기능","CWE-15":"외부 설정 제어","CWE-668":"잘못된 영역 노출","CWE-284 ":"접근 제어 미흡"};
  function cweName(c){ return CWE[c] ? c + " " + CWE[c] : c; }

  function el(tag, cls, text){ var e = document.createElement(tag); if(cls) e.className = cls; if(text != null) e.textContent = text; return e; }
  function link(href, text, cls){ var a = el("a", cls, text); a.href = href; a.target = "_blank"; a.rel = "noopener"; return a; }
  function cveLink(id){ return link("https://www.cve.org/CVERecord?id="+encodeURIComponent(id), id, "cve"); }
  function esc(s){ return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
  function daysAgo(n){ var d = new Date(); d.setDate(d.getDate() - n); return d.toISOString().slice(0,10); }
  function pct(a, b){ return b ? Math.round(a * 100 / b) : 0; }
  function fmt(n){ return Number(n).toLocaleString("ko-KR"); }

  // ---------- tooltip
  var tip = document.getElementById("tip");
  function showTip(x, y, val, label){
    tip.textContent = ""; tip.appendChild(el("b", null, val)); tip.appendChild(el("span", null, label));
    tip.hidden = false;
    var w = tip.offsetWidth, h = tip.offsetHeight;
    var nx = Math.min(x + 12, window.innerWidth - w - 8), ny = y - h - 12; if(ny < 8) ny = y + 16;
    tip.style.left = Math.max(8, nx) + "px"; tip.style.top = ny + "px";
  }
  function bindTip(node, val, label){
    node.tabIndex = 0; node.setAttribute("aria-label", label + ": " + val);
    node.addEventListener("pointermove", function(e){ showTip(e.clientX, e.clientY, val, label); });
    node.addEventListener("pointerleave", function(){ tip.hidden = true; });
    node.addEventListener("focus", function(){ var r = node.getBoundingClientRect(); showTip(r.left + r.width/2, r.top, val, label); });
    node.addEventListener("blur", function(){ tip.hidden = true; });
  }

  // ---------- chart builders
  function tableView(head, rows){
    var d = el("details","tbl"); d.appendChild(el("summary",null,"표로 보기"));
    var w = el("div","tw"), t = el("table"), tr = el("tr");
    head.forEach(function(h, i){ var th = el("th", i ? "n" : null, h); tr.appendChild(th); });
    var th0 = el("thead"); th0.appendChild(tr); t.appendChild(th0);
    var tb = el("tbody");
    rows.forEach(function(r){ var row = el("tr"); r.forEach(function(c, i){ row.appendChild(el("td", i ? "n" : null, String(c))); }); tb.appendChild(row); });
    t.appendChild(tb); w.appendChild(t); d.appendChild(w); return d;
  }
  // rows: [{label, count, color?}] ; total for % suffix
  function hbars(rows, opts){
    opts = opts || {};
    var box = el("div","hb"), max = Math.max.apply(null, rows.map(function(r){ return r.count; }).concat([1]));
    rows.forEach(function(r){
      var row = el("div","hb-row");
      var l = el("span","hb-l", r.label); l.title = r.label; row.appendChild(l);
      var t = el("span","hb-t"), b = el("span","hb-b"); b.style.width = (r.count / max * 100) + "%";
      if(r.color) b.style.background = r.color;
      t.appendChild(b); row.appendChild(t);
      var v = el("span","hb-v", fmt(r.count));
      if(opts.total) v.appendChild(el("small", null, pct(r.count, opts.total) + "%"));
      row.appendChild(v);
      bindTip(row, fmt(r.count) + "건" + (opts.total ? " · " + pct(r.count, opts.total) + "%" : ""), r.label);
      box.appendChild(row);
    });
    return box;
  }
  function niceMax(m){ if(m <= 5) return 5; var p = Math.pow(10, Math.floor(Math.log10(m))), n = m / p; return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p; }
  // items: [{x, xl, segs:[{v, cls, name}]}]
  function columns(items, opts){
    opts = opts || {};
    var wrap = el("div","col-chart"), plot = el("div","col-plot");
    var tot = items.map(function(it){ return it.segs.reduce(function(a, s){ return a + s.v; }, 0); });
    var top = niceMax(Math.max.apply(null, tot.concat([1])));
    [0, 0.5, 1].forEach(function(f){
      var g = el("div","col-grid" + (f === 0 ? " base" : "")); g.style.bottom = (f * 100) + "%";
      g.appendChild(el("span", null, fmt(Math.round(top * f)))); plot.appendChild(g);
    });
    var bars = el("div","col-bars");
    items.forEach(function(it, i){
      var c = el("div","col");
      var nz = it.segs.filter(function(s){ return s.v > 0; });
      nz.forEach(function(s, j){
        var sg = el("div","cs " + (s.cls || "") + (j === nz.length - 1 ? " top" : ""));
        sg.style.height = "calc(" + (s.v / top * 100) + "% - 2px)"; sg.style.minHeight = "2px";
        c.appendChild(sg);
      });
      var lbl = it.segs.length > 1 ? it.segs.map(function(s){ return s.name + " " + s.v; }).join(" · ") : "";
      bindTip(c, fmt(tot[i]) + "건", it.x + (lbl ? " — " + lbl : ""));
      bars.appendChild(c);
    });
    plot.appendChild(bars); wrap.appendChild(plot);
    var xs = el("div","col-x"); var every = opts.every || 1;
    items.forEach(function(it, i){ xs.appendChild(el("span", null, (i % every === 0 || i === items.length - 1) ? it.xl : "")); });
    wrap.appendChild(xs);
    return wrap;
  }
  function card(title, lead, why, cls){
    var c = el("div","card" + (cls ? " " + cls : ""));
    c.appendChild(el("h3", null, title));
    if(lead){ var p = el("p","lead"); lead.forEach(function(x){ p.appendChild(typeof x === "string" ? document.createTextNode(x) : x); }); c.appendChild(p); }
    if(why) c.appendChild(el("p","why", why));
    return c;
  }
  function B(t){ return el("b", null, t); }

  // ---------- watchlist
  var matchers = [];
  // Everyday words people type, mapped to the names vendors actually use in advisories.
  var ALIAS = {
    "next.js":["next"], "postgresql":["postgres"], "redis":["ioredis"],
    "nas":["Synology","DiskStation","QNAP","QTS","QuTS","ASUSTOR"], "시놀로지":["Synology","DiskStation"], "시놀":["Synology","DiskStation"],
    "큐냅":["QNAP","QTS"], "윈도우":["Windows"], "윈도":["Windows"], "window":["Windows"], "오피스":["Microsoft Office","Microsoft 365"],
    "아웃룩":["Outlook"], "익스체인지":["Exchange Server"], "크롬":["Chrome"], "엣지":["Microsoft Edge"], "안드로이드":["Android"],
    "아이폰":["iOS","iPhone"], "아이패드":["iPadOS"], "맥":["macOS"], "맥북":["macOS"], "갤럭시":["Samsung Mobile","Galaxy"],
    "삼성":["Samsung"], "공유기":["ipTIME","EFM Networks","TP-Link","D-Link","TOTOLINK","Tenda","Netgear","Archer"],
    "아이피타임":["ipTIME","EFM Networks"], "포티넷":["Fortinet","FortiOS","FortiGate"], "포티게이트":["FortiGate","FortiOS"],
    "vpn":["VPN","Connect Secure","GlobalProtect","FortiOS","SSL VPN","SMA"], "방화벽":["Firewall","FortiOS","PAN-OS","ASA"],
    "한컴":["Hancom","Hangul"], "한글":["Hancom","Hangul"], "안랩":["AhnLab","V3"], "v3":["AhnLab"], "카카오":["Kakao"],
    "c#":[".NET","ASP.NET"], "csharp":[".NET","ASP.NET"], "닷넷":[".NET"], "자바":["Java","JDK"], "파이썬":["Python"],
    "node":["Node.js"], "노드":["Node.js"], "nodejs":["Node.js"], "php":["PHP"], "워드프레스":["WordPress"], "도커":["Docker"],
    "쿠버네티스":["Kubernetes"], "브이엠웨어":["VMware","ESXi"], "esxi":["ESXi","VMware ESX"], "줌":["Zoom"], "엑셀":["Excel"],
    // Distros: kernel CVEs are filed as vendor "Linux", product "Linux"/"Kernel", so a distro name must also reach the kernel.
    // "@Linux" = the record's vendor is exactly "Linux" (the kernel), not any product that merely mentions Linux.
    "ubuntu":["Ubuntu","Canonical","@Linux"], "우분투":["Ubuntu","Canonical","@Linux"], "debian":["Debian","@Linux"], "데비안":["Debian","@Linux"],
    "centos":["CentOS","@Linux"], "rhel":["Red Hat Enterprise Linux","@Linux"], "rocky":["Rocky Linux","@Linux"],
    "리눅스":["@Linux"], "커널":["@Linux"], "kernel":["@Linux"]
  };
  function termsFor(t){ return [t].concat(ALIAS[t.toLowerCase()] || []); }
  function buildMatchers(){
    // Whole words, with an optional plural "s": "Window" finds "Windows", "php" finds PHP but not phpMyFAQ.
    matchers = watch.map(function(w){ var t = w.trim(); if(!t) return null;
      var terms = termsFor(t), words = terms.filter(function(x){ return x.charAt(0) !== "@"; }).map(esc);
      var exactVendor = terms.filter(function(x){ return x.charAt(0) === "@"; }).map(function(x){ return "^" + esc(x.slice(1)) + " \\|"; });
      var src = "(?:(^|[^\\p{L}\\p{N}])(?:" + words.join("|") + ")s?(?=$|[^\\p{L}\\p{N}]))" + (exactVendor.length ? "|" + exactVendor.join("|") : "");
      return { label:t, re:new RegExp(src, "iu") }; }).filter(Boolean);
  }
  function hitsFor(it, kind){
    var parts = [it.vendor, it.product, it.name || ""];
    var hay = parts.join(" | "), out = [];
    matchers.forEach(function(m){ if(m.re.test(hay)) out.push(m.label); });
    return out;
  }
  // ---------- signals
  function isRce(it){ return it.av === "N" && it.pr === "N" && (it.ui === "N" || !it.ui); }
  function hasSig(it){ return it.kev || it.exploitation === "active" || it.exploitation === "poc" || it.exploitation === "public poc"; }
  function riskScore(it, kind){
    var s = it._hits.length ? 100 : 0;
    if(kind === "kev"){
      s += (it.edge ? 6 : 0) + (it.ransomware === "Known" ? 5 : 0) + (it.lagDays != null && it.lagDays <= 7 ? 4 : 0) + (isRce(it) ? 2 : 0);
    } else {
      s += (it.kev ? 12 : 0) + (it.exploitation === "active" ? 10 : (it.exploitation === "poc" || it.exploitation === "public poc") ? 6 : 0)
         + (isRce(it) ? 5 : 0) + (it.automatable === "yes" ? 2 : 0) + (it.techImpact === "total" ? 1 : 0) + (it.edge ? 2 : 0);
    }
    return s;
  }
  function lagText(d){
    if(d == null) return null;
    if(d <= 0) return "공개 당일·이전 등재";
    if(d <= 365) return "공개 " + d + "일 만에 등재";
    return "공개 " + (d / 365).toFixed(1) + "년 된 취약점";
  }

  // ---------- routing
  var REF = ["sources","routine","insights"];
  var VIEWS = ["brief","kev","upd","pkg","kisa","critical","insights","sources","routine"];
  function setView(v, push){
    if(VIEWS.indexOf(v) < 0) v = "brief";
    state.view = v; state.shown = 40;
    var tabKey = REF.indexOf(v) >= 0 ? "insights" : v;
    VIEWS.forEach(function(x){ var t = document.getElementById("t-"+x); if(t) t.setAttribute("aria-selected", String(x === tabKey)); });
    renderRefNav(v); updateTabFade(); setTimeout(refreshFilters, 0);
    document.getElementById("v-brief").hidden = v !== "brief";
    document.getElementById("v-insights").hidden = v !== "insights";
    document.getElementById("v-kisa").hidden = v !== "kisa";
    document.getElementById("v-upd").hidden = v !== "upd";
    document.getElementById("v-pkg").hidden = v !== "pkg";
    if(v === "pkg") renderPkg();
    if(v === "kisa") renderKisa();
    if(v === "upd") renderUpdates();
    document.getElementById("v-list").hidden = !(v === "kev" || v === "critical");
    document.getElementById("v-sources").hidden = v !== "sources";
    document.getElementById("v-routine").hidden = v !== "routine";
    if(push && location.hash !== "#" + v){ try{ history.replaceState(null, "", "#" + v); }catch(e){ location.hash = v; } }
    renderList();
  }
  function renderRefNav(v){
    var nav = document.getElementById("refNav"); nav.hidden = REF.indexOf(v) < 0; if(nav.hidden) return;
    nav.textContent = "";
    [["sources","정보원"],["routine","대응 루틴"],["insights","인사이트"]].forEach(function(r){
      var b = el("button", null, r[1]); b.type = "button"; b.setAttribute("aria-pressed", String(r[0] === v));
      b.addEventListener("click", function(){ setView(r[0], true); }); nav.appendChild(b);
    });
  }
  function updateTabFade(){
    var t = document.querySelector(".tabs"); if(!t) return;
    t.classList.toggle("tfade", t.scrollWidth - t.clientWidth - t.scrollLeft > 6);
    var sel = t.querySelector('[aria-selected="true"]');
    if(sel && t.scrollWidth > t.clientWidth && !updateTabFade.busy){
      var l = sel.offsetLeft - 16, r = sel.offsetLeft + sel.offsetWidth + 16;
      if(l < t.scrollLeft) t.scrollLeft = l; else if(r > t.scrollLeft + t.clientWidth) t.scrollLeft = r - t.clientWidth;
    }
  }
  (function(){ var t = document.querySelector(".tabs"); if(t){ t.addEventListener("scroll", function(){ updateTabFade.busy = true; t.classList.toggle("tfade", t.scrollWidth - t.clientWidth - t.scrollLeft > 6); clearTimeout(updateTabFade.tm); updateTabFade.tm = setTimeout(function(){ updateTabFade.busy = false; }, 200); }, {passive:true}); window.addEventListener("resize", updateTabFade); } })();
  document.querySelectorAll(".tab").forEach(function(t){ t.addEventListener("click", function(){ setView(t.dataset.view, true); }); });
  window.addEventListener("hashchange", function(){ setView(location.hash.slice(1), false); });

  // ---------- filters fold into one button on phones
  var FSECS = ["v-list","v-upd","v-kisa","v-pkg"];
  function refreshFilters(){
    FSECS.forEach(function(id){
      var sec = document.getElementById(id), b = sec && sec.querySelector(".fbtn"); if(!b) return;
      var parts = []; sec.querySelectorAll(".toolbar .seg:not([hidden]) [aria-pressed='true']").forEach(function(x){ parts.push(x.textContent); });
      var open = !sec.classList.contains("fcollapsed");
      b.textContent = "필터" + (parts.length ? " · " + parts.join(" · ") : "") + (open ? "  ▴" : "  ▾");
      b.setAttribute("aria-expanded", String(open));
    });
  }
  FSECS.forEach(function(id){
    var sec = document.getElementById(id), tb = sec && sec.querySelector(".toolbar"); if(!tb) return;
    var b = el("button","btn ghost sm fbtn"); b.type = "button"; sec.classList.add("fcollapsed");
    b.addEventListener("click", function(){ sec.classList.toggle("fcollapsed"); refreshFilters(); });
    tb.insertBefore(b, tb.firstChild);
    sec.addEventListener("click", function(){ setTimeout(refreshFilters, 30); });
  });

  // ---------- toolbar
  var RANGES = { kev:[[7,"7일"],[30,"30일"],[90,"90일"]], critical:[[3,"3일"],[7,"7일"],[14,"14일"],[30,"30일"],[90,"90일"]] };
  var FILTERS = {
    kev:[["rw","랜섬웨어 연관"],["edge","경계 장비"],["fast","공개 7일 내 등재"],["old","1년 넘은 취약점"]],
    critical:[["rce","원격·무인증·무조작"],["sig","PoC·악용·KEV"],["edge","경계 장비"],["auto","SSVC 자동화 가능"]]
  };
  function renderToolbar(){
    var key = state.view, seg = document.getElementById("rangeSeg"); seg.textContent = "";
    RANGES[key].forEach(function(r){
      var b = el("button", null, r[1]); b.type = "button"; b.setAttribute("aria-pressed", String(state.range[key] === r[0]));
      b.addEventListener("click", function(){ state.range[key] = r[0]; state.shown = 40; renderList(); });
      seg.appendChild(b);
    });
    var f = document.getElementById("flt"); f.textContent = "";
    f.appendChild(el("span","lab","조건"));
    var fs = key === "kev" ? state.kf : state.cf;
    FILTERS[key].forEach(function(x){
      var b = el("button","fchip", x[1]); b.type = "button"; b.setAttribute("aria-pressed", String(!!fs[x[0]]));
      b.addEventListener("click", function(){ fs[x[0]] = !fs[x[0]]; state.shown = 40; renderList(); });
      f.appendChild(b);
    });
    document.querySelectorAll("[data-sort]").forEach(function(x){ x.setAttribute("aria-pressed", String(x.dataset.sort === state.sort)); });
  }
  document.querySelectorAll("[data-scope]").forEach(function(b){ b.setAttribute("aria-pressed", String(b.dataset.scope === state.scope)); });
  document.querySelectorAll("[data-scope]").forEach(function(b){
    b.addEventListener("click", function(){
      state.scope = b.dataset.scope; state.shown = 40;
      document.querySelectorAll("[data-scope]").forEach(function(x){ x.setAttribute("aria-pressed", String(x === b)); });
      renderList();
    });
  });
  document.querySelectorAll("[data-sort]").forEach(function(b){ b.addEventListener("click", function(){ state.sort = b.dataset.sort; renderList(); }); });
  var qT; document.getElementById("q").addEventListener("input", function(e){ clearTimeout(qT); qT = setTimeout(function(){ state.q = e.target.value.trim().toLowerCase(); state.shown = 40; renderList(); }, 150); });
  document.getElementById("hideDone").addEventListener("change", function(e){ state.hideDone = e.target.checked; renderList(); });
  document.getElementById("more").addEventListener("click", function(){ state.shown += 40; renderList(); });

  // ---------- list
  function filtered(kind){
    var arr = kind === "kev" ? data.kev : data.critical, from = daysAgo(state.range[kind]);
    var kf = state.kf, cf = state.cf;
    return arr.filter(function(it){
      var d = kind === "kev" ? it.added : it.published;
      if(d < from) return false;
      if(state.scope === "mine" && !it._hits.length) return false;
      if(state.hideDone && done[it.id]) return false;
      if(kind === "kev"){
        if(kf.rw && it.ransomware !== "Known") return false;
        if(kf.edge && !it.edge) return false;
        if(kf.fast && !(it.lagDays != null && it.lagDays <= 7)) return false;
        if(kf.old && !(it.lagDays != null && it.lagDays > 365)) return false;
      } else {
        if(cf.rce && !isRce(it)) return false;
        if(cf.sig && !hasSig(it)) return false;
        if(cf.edge && !it.edge) return false;
        if(cf.auto && it.automatable !== "yes") return false;
      }
      if(state.q){
        var hay = (it.id+" "+it.vendor+" "+it.product+" "+(it.name||"")+" "+(it.summary||"")+" "+(it.cwe||"")+" "+(it.cwes||[]).join(" ")).toLowerCase();
        if(hay.indexOf(state.q) < 0) return false;
      }
      return true;
    }).sort(function(a, b){
      var da = kind === "kev" ? a.added : a.published, db = kind === "kev" ? b.added : b.published;
      if(state.sort === "risk"){
        var r = riskScore(b, kind) - riskScore(a, kind); if(r) return r;
      } else {
        var ha = a._hits.length ? 1 : 0, hb = b._hits.length ? 1 : 0; if(ha !== hb) return hb - ha;
      }
      if(da !== db) return da < db ? 1 : -1;
      return (b.score || 0) - (a.score || 0);
    });
  }

  function enLead(it){
    // Kernel records all open with the same boilerplate; the patch subject line says more.
    return (it.summary || it.name || "").replace(/^In the Linux kernel, the following vulnerability has been resolved:\s*/i, "").split("\n")[0];
  }
  function itemNode(it, kind){
    var li = el("li","item " + (kind === "kev" ? "is-kev" : "is-crit")); if(done[it.id]) li.classList.add("done");
    var sc = el("div","score " + (kind === "kev" ? "kev" : "crit"));
    if(kind === "kev"){ sc.appendChild(el("b", null, "악용")); sc.appendChild(el("span", null, it.score != null ? "CVSS " + Number(it.score).toFixed(1) : "점수 없음")); }
    else { sc.appendChild(el("b", null, Number(it.score).toFixed(1))); sc.appendChild(el("span", null, "CVSS")); }
    li.appendChild(sc);

    var body = el("div","body"), l1 = el("div","line1");
    l1.appendChild(el("span","prod", [it.vendor, it.product].filter(function(x){ return x && x !== "n/a"; }).join(" · ") || it.id));
    l1.appendChild(el("span","date", kind === "kev" ? "등재 " + it.added : "공개 " + it.published));
    body.appendChild(l1);

    // one sentence: Korean when we have it, otherwise the English lead
    var ko = koOf(it.id), en = enLead(it);
    var lead = el("p", ko ? "ko" : "ko-en", ko || en); if(ko && en) lead.title = en; body.appendChild(lead);

    // only the signals that change what you do
    var bd = el("div","badges");
    if(it._hits.length) bd.appendChild(el("span","b mine", "내 제품: " + it._hits.join(", ")));
    if(kind === "kev"){
      if(it.ransomware === "Known") bd.appendChild(el("span","b rw","랜섬웨어에 쓰임"));
      if(it.forensic) bd.appendChild(el("span","b rw","침해 흔적도 점검"));
      if(it.lagDays != null && it.lagDays <= 7) bd.appendChild(el("span","b kev", lagText(it.lagDays)));
    } else {
      if(it.kev) bd.appendChild(el("span","b rw","실제 악용"));
      else if(it.exploitation === "active") bd.appendChild(el("span","b rw","악용 확인"));
      else if(it.exploitation === "poc" || it.exploitation === "public poc") bd.appendChild(el("span","b poc","PoC 공개"));
      if(isRce(it)) bd.appendChild(el("span","b plain","인증 없이 원격"));
    }
    if(it.edge) bd.appendChild(el("span","b plain","경계 장비"));
    if(bd.childNodes.length) body.appendChild(bd);
    var an = actionNode(it); if(an) body.appendChild(an);

    // everything else: original text and detail, folded
    var det = el("details","orig"), sm = el("summary"); sm.appendChild(el("span","mono cid", it.id)); sm.appendChild(document.createTextNode(" 원문·세부 정보")); det.appendChild(sm);
    var dw = el("div","orig-body");
    if(kind === "kev" && it.name) dw.appendChild(el("div","prod small", it.name));
    if(it.summary && (ko || it.summary !== en)) dw.appendChild(el("p","desc", it.summary));
    var meta = el("div","badges");
    if(kind === "kev"){
      var lt = lagText(it.lagDays); if(lt && !(it.lagDays <= 7)) meta.appendChild(el("span","b plain", lt));
      if(it.cwes && it.cwes[0]) meta.appendChild(el("span","b plain", cweName(it.cwes[0])));
      if(it.due) meta.appendChild(el("span","b plain","미 연방기관 조치기한 " + it.due));
    } else {
      if(it.automatable === "yes") meta.appendChild(el("span","b plain","공격 자동화 가능"));
      if(it.cwe) meta.appendChild(el("span","b plain", cweName(it.cwe)));
      if(it.scoreSource && it.scoreSource !== "CNA") meta.appendChild(el("span","b plain","점수 출처: " + it.scoreSource.replace("ADP:", "")));
    }
    if(meta.childNodes.length) dw.appendChild(meta);
    if(kind === "critical" && it.vector) dw.appendChild(el("div","small muted mono vec", it.vector));
    var refs = el("div","foot");
    refs.appendChild(link("https://www.cve.org/CVERecord?id=" + encodeURIComponent(it.id), "CVE 레코드"));
    refs.appendChild(link("https://nvd.nist.gov/vuln/detail/" + encodeURIComponent(it.id), "NVD"));
    refs.appendChild(link("https://api.first.org/data/v1/epss?cve=" + encodeURIComponent(it.id), "EPSS 점수"));
    refs.appendChild(link("https://osv.dev/vulnerability/" + encodeURIComponent(it.id), "OSV"));
    refs.appendChild(link("https://euvd.enisa.europa.eu/search?text=" + encodeURIComponent(it.id), "EUVD"));
    refs.appendChild(link("https://github.com/search?type=code&q=" + encodeURIComponent(it.id), "GitHub PoC 검색"));
    dw.appendChild(refs); det.appendChild(dw);

    var f = el("div","foot item-foot"); f.appendChild(det);
    if(!(it.refs && it.refs.length)) f.appendChild(link("https://www.google.com/search?q=" + encodeURIComponent(it.id + " " + (it.vendor || "") + " advisory"), "벤더 공지 찾기 ↗"));
    var lab = el("label","tog"), cb = el("input"); cb.type = "checkbox"; cb.id = "done-" + it.id; cb.checked = !!done[it.id];
    cb.addEventListener("change", function(){ if(cb.checked) done[it.id] = Date.now(); else delete done[it.id]; LS.set("radar.done", done); li.classList.toggle("done", cb.checked); renderVerdict(); if(state.hideDone) renderList(); });
    lab.appendChild(cb); lab.appendChild(document.createTextNode("확인함"));
    f.appendChild(lab); body.appendChild(f);
    li.appendChild(body);
    return li;
  }

  var current = [];
  function renderList(){
    if(state.view !== "kev" && state.view !== "critical") return;
    renderToolbar();
    var kind = state.view, list = document.getElementById("list"); list.textContent = "";
    document.getElementById("listTitle").textContent = kind === "kev" ? "실제 악용" : "고위험 신규";
    document.getElementById("listTitleDesc").textContent = kind === "kev" ? "미국 CISA가 실제 공격에 쓰였다고 확인한 취약점입니다." : "최근 공개된 CVSS 9.0 이상 취약점입니다. 악용 신호가 있는 것부터 보여 줍니다.";
    if(!data.meta){ list.appendChild(el("li","empty", loadMsg)); document.getElementById("moreWrap").hidden = true; return; }
    var arr = filtered(kind); current = arr;
    var total = (kind === "kev" ? data.kev : data.critical).filter(function(it){ return (kind === "kev" ? it.added : it.published) >= daysAgo(state.range[kind]); }).length;
    document.getElementById("countLine").textContent = "최근 " + state.range[kind] + "일 " + fmt(total) + "건 중 " + fmt(arr.length) + "건 표시";
    if(!arr.length) list.appendChild(el("li","empty", state.scope === "mine" ? "이 기간·조건에서 내 제품과 일치하는 항목이 없습니다." : "조건에 맞는 항목이 없습니다. 조건 칩을 일부 해제해 보세요."));
    arr.slice(0, state.shown).forEach(function(it){ list.appendChild(itemNode(it, kind)); });
    document.getElementById("moreWrap").hidden = arr.length <= state.shown;
    document.getElementById("listNote").textContent = kind === "kev"
      ? "KEV는 실제 공격에 쓰인 것이 확인된 취약점만 모은 목록입니다. 등재일은 최초 악용일이 아니라 CISA가 확인해 올린 날입니다."
      : "CVSS 9.0 이상만 표시합니다. 위험 신호순은 KEV·SSVC 악용 상태·원격 무인증 조건·자동화 가능 여부를 합산해 정렬합니다. SSVC 평가는 CISA가 붙이며, 공개 직후에는 비어 있을 수 있습니다.";
  }

  // ---------- CSV
  function csvCell(v){ v = v == null ? "" : Array.isArray(v) ? v.join(" ") : String(v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }
  function buildCsv(kind, arr){
    var cols = kind === "kev"
      ? [["cve","id"],["vendor","vendor"],["product","product"],["name","name"],["date_added","added"],["due_date","due"],["cve_published","published"],["lag_days","lagDays"],["cvss","score"],["ransomware","ransomware"],["edge_device","edge"],["cwe","cwes"],["my_match","_hits"],["required_action","action"]]
      : [["cve","id"],["published","published"],["cvss","score"],["cvss_version","cvssVersion"],["vector","vector"],["vendor","vendor"],["product","product"],["cwe","cwe"],["ssvc_exploitation","exploitation"],["ssvc_automatable","automatable"],["ssvc_technical_impact","techImpact"],["kev","kev"],["edge_device","edge"],["my_match","_hits"],["summary","summary"]];
    var lines = [cols.map(function(c){ return c[0]; }).join(",")];
    arr.forEach(function(it){ lines.push(cols.map(function(c){ return csvCell(it[c[1]]); }).join(",")); });
    return "﻿" + lines.join("\n");
  }
  var downloadsP = null;
  document.getElementById("csvBtn").addEventListener("click", function(){
    var btn = this, kind = state.view;
    var name = (kind === "kev" ? "kev" : "critical") + "-" + new Date().toISOString().slice(0,10) + ".csv";
    if(!downloadsP){
      // self-hosted: plain browser download
      var url = URL.createObjectURL(new Blob([buildCsv(kind, current)], { type:"text/csv;charset=utf-8" }));
      var a = document.createElement("a"); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
      setTimeout(function(){ URL.revokeObjectURL(url); }, 1000);
      btn.textContent = "저장함"; setTimeout(function(){ btn.textContent = "CSV 내보내기"; }, 2000);
      return;
    }
    downloadsP.then(function(dl){
      if(!dl) return;
      return dl.save({ filename:name, data:buildCsv(kind, current) }).then(function(){ btn.textContent = "저장함"; setTimeout(function(){ btn.textContent = "CSV 내보내기"; }, 2000); });
    }).catch(function(e){
      if(e && e.code === "declined") return;
      btn.textContent = "저장할 수 없음"; setTimeout(function(){ btn.textContent = "CSV 내보내기"; }, 2500);
    });
  });

  // ---------- insights
  function renderInsights(){
    var g = document.getElementById("igrid"), I = data.ins; g.textContent = "";
    if(!I){ var c0 = el("div","card wide"); c0.appendChild(el("p","muted", loadMsg)); g.appendChild(c0); return; }

    // 1. funnel
    var F = I.critFunnel, fAll = F[0].count, fLast = F[F.length-1].count;
    var c1 = card("신규 Critical 중 실제로 먼저 볼 것", ["최근 " + data.meta.windowCveDays + "일 CVSS 9.0+ ", B(fmt(fAll) + "건"), " 중 원격·무인증·무조작이면서 악용 신호까지 있는 건 ", B(fmt(fLast) + "건(" + pct(fLast, fAll) + "%)"), "입니다."],
      "점수만으로 줄 세우면 수백 건이 같은 우선순위가 됩니다. 공격 조건(CVSS 벡터)과 악용 신호(SSVC·KEV)를 겹치면 이번 주에 볼 목록이 한 자릿수~두 자릿수로 줄어듭니다.", "wide");
    var oc = ["var(--o1)","var(--o2)","var(--o3)","var(--o4)","var(--o5)"];
    c1.appendChild(hbars(F.map(function(s, i){ return { label:s.label, count:s.count, color:oc[i] }; }), { total:fAll }));
    var go = el("button","btn sm", "이 " + fLast + "건 목록으로 보기"); go.type = "button"; go.style.width = "max-content";
    go.addEventListener("click", function(){ state.cf = {rce:true, sig:true, edge:false, auto:false}; state.range.critical = 14; state.scope = "all"; state.sort = "risk"; setView("critical", true); window.scrollTo({top:document.querySelector(".tabs").offsetTop - 8}); });
    c1.appendChild(go);
    var S = I.critSsvc;
    c1.appendChild(el("p","src", "SSVC(CISA 평가) 기준: 평가된 " + fmt(S.rated) + "건 중 악용 확인 " + fmt(S.exploitation.active || 0) + " · PoC " + fmt(S.exploitation.poc || 0) + " · 자동화 가능 " + fmt(S.automatableYes) + " · 자동화 가능+완전 장악 " + fmt(S.autoAndTotal) + "건. 평가 전 " + fmt(S.exploitation.unknown || 0) + "건."));
    c1.appendChild(tableView(["단계","건수"], F.map(function(s){ return [s.label, s.count]; })));
    g.appendChild(c1);

    // 2. lag distribution
    var L = I.kevLagDist, lt = L.reduce(function(a, b){ return a + b.count; }, 0);
    var fast = L[0].count + L[1].count, old = L[4].count;
    var c2 = card("공개에서 KEV 등재까지", ["최근 12개월 KEV ", B(fmt(lt) + "건"), " 중 ", B(pct(fast, lt) + "%"), "는 공개 후 7일 안에 등재됐고, ", B(pct(old, lt) + "%"), "는 공개된 지 1년이 넘은 취약점이었습니다."],
      "패치를 빨리 하는 것과 오래된 미패치 자산을 정리하는 것, 둘 다 필요하다는 뜻입니다. 등재일은 최초 악용일보다 늦으므로 실제 여유는 이보다 짧습니다.");
    c2.appendChild(columns(L.map(function(b){ return { x:b.label, xl:b.label, segs:[{v:b.count}] }; })));
    c2.appendChild(el("p","src", "중앙값 " + (I.kevLagMedian != null ? fmt(I.kevLagMedian) + "일" : "–") + " · CVE 레코드 공개일과 KEV 등재일의 차이"));
    c2.appendChild(tableView(["구간","건수","비율"], L.map(function(b){ return [b.label, b.count, pct(b.count, lt) + "%"]; })));
    g.appendChild(c2);

    // 3. severity blind spot
    var SV = I.kevSeverity, st = SV.reduce(function(a, b){ return a + b.count; }, 0), nonCrit = st - SV[0].count;
    var c3 = card("CVSS만 보면 놓치는 KEV", ["최근 12개월 KEV의 ", B(pct(nonCrit, st) + "%"), "는 CVSS Critical(9.0+)이 아니었습니다. High 이하 ", B(fmt(nonCrit) + "건"), "도 실제 공격에 쓰였습니다."],
      "\"Critical만 긴급 패치\" 같은 점수 기준 SLA는 실제 공격의 상당 부분을 뒤로 미룹니다. KEV 등재 자체를 별도 트리거로 두는 게 안전합니다.");
    c3.appendChild(hbars(SV.map(function(s){ return { label:s.label, count:s.count }; }), { total:st }));
    c3.appendChild(tableView(["심각도","건수"], SV.map(function(s){ return [s.label, s.count]; })));
    g.appendChild(c3);

    // 4. monthly
    var M = I.kevMonthly, last12 = M.slice(-12), prev12 = M.slice(0, 12);
    var s12 = last12.reduce(function(a, m){ return a + m.total; }, 0), p12 = prev12.reduce(function(a, m){ return a + m.total; }, 0);
    var r12 = last12.reduce(function(a, m){ return a + m.ransomware; }, 0);
    var c4 = card("월별 KEV 등재 추이", ["최근 12개월 ", B(fmt(s12) + "건"), ", 그 전 12개월은 " + fmt(p12) + "건(" + (s12 >= p12 ? "+" : "") + pct(s12 - p12, p12) + "%). 랜섬웨어 연관은 " + fmt(r12) + "건입니다."],
      "등재 속도가 빨라질수록 \"KEV 전부 즉시 패치\"를 운영으로 감당하기 어려워집니다. 자산 대조로 범위를 좁히는 단계가 필요합니다.", "wide");
    var lg = el("div","legend");
    [["var(--s1)","기타 KEV"],["var(--s2)","랜섬웨어 사용 확인"]].forEach(function(x){ var s = el("span"), i = el("i"); i.style.background = x[0]; s.appendChild(i); s.appendChild(document.createTextNode(x[1])); lg.appendChild(s); });
    c4.appendChild(lg);
    c4.appendChild(columns(M.map(function(m){ return { x:m.month, xl:m.month.slice(2).replace("-", "."), segs:[{v:m.total - m.ransomware, name:"기타"}, {v:m.ransomware, cls:"s2", name:"랜섬웨어"}] }; }), { every:3 }));
    c4.appendChild(el("p","src","이번 달은 집계 중인 부분 월입니다. 랜섬웨어 표시는 CISA가 확인한 경우만 포함하며 나중에 바뀔 수 있습니다."));
    c4.appendChild(tableView(["월","전체","랜섬웨어"], M.map(function(m){ return [m.month, m.total, m.ransomware]; })));
    g.appendChild(c4);

    // 5. vendors
    var kw = I.kevWindowCount;
    var c5 = card("어디가 공격받나: KEV 벤더 Top 10", ["최근 12개월 KEV의 ", B(pct(I.kevEdge, kw) + "%(" + fmt(I.kevEdge) + "건)"), "가 VPN·방화벽·라우터 같은 경계 장비 제품이었습니다."],
      "경계 장비는 인터넷에 직접 노출되고 EDR을 설치할 수 없어 침투 초기 거점으로 자주 쓰입니다. 경계 장비는 벤더·제품명 기반 추정치입니다.");
    c5.appendChild(hbars(I.kevVendors.map(function(v){ return { label:v.label, count:v.count }; })));
    c5.appendChild(tableView(["벤더","건수"], I.kevVendors.map(function(v){ return [v.label, v.count]; })));
    g.appendChild(c5);

    // 6. CWE compare
    var c6 = card("공격 유형: 실제 악용 vs 신규 Critical", null, "왼쪽은 최근 12개월 KEV(실제 악용), 오른쪽은 최근 14일 신규 Critical에서 많이 나온 약점 유형(CWE)입니다. 두 목록이 겹치는 유형은 코드 리뷰·WAF 룰 우선순위로 쓸 수 있습니다.");
    var two = el("div","cols2");
    var a = el("div"); a.appendChild(el("div","eyebrow","KEV · 12개월")); a.appendChild(hbars(I.kevCwe.map(function(v){ return { label:cweName(v.label), count:v.count }; })));
    var b = el("div"); b.appendChild(el("div","eyebrow","신규 Critical · 14일")); b.appendChild(hbars(I.critCwe.map(function(v){ return { label:cweName(v.label), count:v.count }; })));
    two.appendChild(a); two.appendChild(b); c6.appendChild(two);
    c6.appendChild(el("p","src", "CWE가 비어 있는 건 제외: KEV " + fmt(I.kevCweUnclassified || 0) + "건, 신규 Critical " + fmt(I.critCweUnclassified || 0) + "건. CNA가 CWE를 붙이지 않은 경우입니다."));
    g.appendChild(c6);

    // 7. daily + vendor concentration
    var D = I.critDaily, peak = D.reduce(function(m, d){ return d.count > m.count ? d : m; }, D[0]);
    var topV = I.critVendors[0];
    var c7 = card("신규 Critical은 언제, 누구에게서", ["가장 많았던 날은 ", B(peak.date.slice(5).replace("-", "/") + " " + fmt(peak.count) + "건"), ", 가장 많이 낸 곳은 ", B((topV ? topV.label + " " + fmt(topV.count) + "건" : "–")), "입니다."],
      "Critical 공개는 벤더 정기 패치일에 몰립니다. 급증일은 대부분 한 벤더의 일괄 공개라서, 그날 해당 벤더 자산만 따로 보면 됩니다.", "wide");
    c7.appendChild(columns(D.map(function(d){ return { x:d.date, xl:d.date.slice(5).replace("-", "/"), segs:[{v:d.count}] }; }), { every:2 }));
    c7.appendChild(hbars(I.critVendors.map(function(v){ return { label:v.label, count:v.count }; }), { total:fAll }));
    c7.appendChild(tableView(["날짜","건수"], D.map(function(d){ return [d.date, d.count]; })));
    g.appendChild(c7);

    // 8. lag by year
    var c8 = card("연도별 등재 속도", null, "KEV 등재 연도 기준입니다. \"1년 이내 중앙값\"은 공개 1년 안에 등재된 건만 모아 계산해 오래된 취약점의 영향을 뺀 값입니다.");
    c8.appendChild(tableView(["연도","등재","1년 이내 중앙값(일)","7일 이내","1년 초과"], I.kevLagByYear.map(function(y){ return [y.year + (y.year === new Date().getFullYear() ? " (진행 중)" : ""), y.n, y.medianRecent != null ? y.medianRecent : "–", y.within7 + " (" + pct(y.within7, y.n) + "%)", y.over1y + " (" + pct(y.over1y, y.n) + "%)"]; })));
    c8.querySelector("details").open = true;
    g.appendChild(c8);
  }

  // ---------- shared helpers for the action-first views
  function koOf(id){ var k = data.ko[id]; return k && k.t ? k.t : ""; }
  function host(u){ try{ return new URL(u).hostname.replace(/^www\./, ""); }catch(e){ return "공지"; } }
  function fixText(fx){
    return (fx || []).slice(0, 3).map(function(f){
      var p = f.p ? f.p + " " : "";
      return f.lt ? p + f.lt + " 이상으로" : p + f.le + " 이하 영향";
    }).join(" · ");
  }
  function actionNode(it){
    var a = el("div","act"), ft = fixText(it.fix);
    if(ft){ var s = el("span"); s.appendChild(el("b", null, "버전")); s.appendChild(document.createTextNode(ft)); a.appendChild(s); }
    (it.refs || []).slice(0, 2).forEach(function(u){ a.appendChild(link(u, host(u) + " 공지 ↗")); });
    return a.childNodes.length ? a : null;
  }
  function wordRe(t){ return new RegExp("(^|[^\\p{L}\\p{N}])" + esc(t) + "($|[^\\p{L}\\p{N}])", "iu"); }
  function kisaHits(k){
    var hay = k.title + " | " + (k.vendor || ""), out = [];
    matchers.forEach(function(m){ if(m.re.test(hay)) out.push(m.label); });
    return out;
  }
  function kisaRelated(k){
    var from = daysAgo(30), ids = k.cves || [];
    var re = k.vendor ? wordRe(k.vendor) : null;
    var kev = data.kev.filter(function(v){ return v.added >= from && (ids.indexOf(v.id) >= 0 || (re && re.test(v.vendor + " | " + v.product))); });
    var crit = data.critical.filter(function(c){ return c.published >= from && isRce(c) && hasSig(c) && (ids.indexOf(c.id) >= 0 || (re && re.test(c.vendor + " | " + c.product))); });
    return { kev:kev, crit:crit };
  }
  function dayLabel(d){
    var dt = new Date(d + "T00:00:00Z");
    return { md: (dt.getUTCMonth() + 1) + "/" + dt.getUTCDate(), wd: "일월화수목금토".charAt(dt.getUTCDay()) };
  }

  // ---------- product updates tab (major vendors, grouped by vendor and day)
  var updState = { range:30, scope:(watch.length ? "mine" : "all"), sev:"all", shown:30 };
  function doneBox(key, li){
    var lab = el("label","tog"), cb = el("input"); cb.type = "checkbox"; cb.id = "done-" + key.replace(/[^A-Za-z0-9_-]/g, "_"); cb.checked = !!done[key];
    cb.addEventListener("change", function(){ if(cb.checked) done[key] = Date.now(); else delete done[key]; LS.set("radar.done", done); li.classList.toggle("done", cb.checked); renderVerdict(); });
    lab.appendChild(cb); lab.appendChild(document.createTextNode("확인함")); return lab;
  }
  function segButtons(box, opts, cur, onPick){
    box.textContent = "";
    opts.forEach(function(o){ var b = el("button", null, o[1]); b.type = "button"; b.setAttribute("aria-pressed", String(cur === o[0])); b.addEventListener("click", function(){ onPick(o[0]); }); box.appendChild(b); });
  }
  function renderUpdates(){
    segButtons(document.getElementById("updRange"), [[7,"7일"],[30,"30일"],[90,"90일"]], updState.range, function(v){ updState.range = v; updState.shown = 30; renderUpdates(); });
    segButtons(document.getElementById("updScope"), [["all","전체"],["mine","내 제품만"]], updState.scope, function(v){ updState.scope = v; updState.shown = 30; renderUpdates(); });
    segButtons(document.getElementById("updSev"), [["all","7.0 이상 전부"],["urgent","급한 것만"]], updState.sev, function(v){ updState.sev = v; updState.shown = 30; renderUpdates(); });
    var list = document.getElementById("updList"); list.textContent = "";
    if(!data.meta){ list.appendChild(el("li","empty", loadMsg)); return; }
    var from = daysAgo(updState.range);
    var arr = data.updates.filter(function(g){
      if(g.date < from) return false;
      if(updState.scope === "mine" && !g._hits.length) return false;
      if(updState.sev === "urgent" && !(g.kev.length || (g.maxScore >= 9 && g.nRemote) || g.exploited.length)) return false;
      return true;
    }).sort(function(a, b){
      var ha = a._hits.length ? 1 : 0, hb = b._hits.length ? 1 : 0; if(ha !== hb) return hb - ha;
      return a.date < b.date ? 1 : a.date > b.date ? -1 : b.maxScore - a.maxScore;
    });
    document.getElementById("updCount").textContent = "최근 " + updState.range + "일 " + arr.length + "개 업데이트 묶음";
    if(!arr.length){ list.appendChild(el("li","empty", updState.scope === "mine" ? "이 기간에 내 제품과 일치하는 보안 업데이트가 없습니다." : "조건에 맞는 업데이트가 없습니다.")); return; }
    arr.slice(0, updState.shown).forEach(function(g){
      var li = el("li","item"); if(done[g.gid]) li.classList.add("done");
      var sc = el("div","score " + (g.maxScore >= 9 ? "crit" : "kev")); sc.appendChild(el("b", null, g.maxScore.toFixed(1))); sc.appendChild(el("span", null, "최고점")); li.appendChild(sc);
      var body = el("div","body"), l1 = el("div","line1");
      l1.appendChild(el("span","prod", g.vendor + " 보안 업데이트"));
      l1.appendChild(el("span","muted small", (g.products || []).slice(0, 4).join(", ")));
      l1.appendChild(el("span","date", "공개 " + g.date));
      body.appendChild(l1);
      var gt = groupText(g); body.appendChild(el("div", gt.ko ? "ko" : "ko-en", gt.t));
      var bd = el("div","badges");
      if(g._hits.length) bd.appendChild(el("span","b mine","내 제품: " + g._hits.join(", ")));
      if(g.kev.length) bd.appendChild(el("span","b rw","실제 악용 " + g.kev.length + "건"));
      else if(g.exploited.length) bd.appendChild(el("span","b poc","PoC 공개 " + g.exploited.length + "건"));
      bd.appendChild(el("span","b plain","CVE " + (g.count || g.cves.length) + "건"));
      if(g.nCrit) bd.appendChild(el("span","b plain","9.0점 이상 " + g.nCrit + "건"));
      if(g.nRemote) bd.appendChild(el("span","b plain","인증 없이 원격 " + g.nRemote + "건"));
      body.appendChild(bd);
      var ga = groupActNode(g); if(ga) body.appendChild(ga);
      var det = el("details","tbl"); det.appendChild(el("summary", null, "CVE 목록 보기" + ((g.count || 0) > (g.items || []).length ? " (점수 높은 " + g.items.length + "건)" : "")));
      var ul = el("ul","tl-items"); ul.style.marginTop = "8px";
      (g.items || []).forEach(function(c){
        var r = el("li"); r.appendChild(cveLink(c.id)); r.appendChild(el("span","b plain mono", c.score.toFixed(1)));
        r.appendChild(el("span","prod", c.product));
        if(c.av === "N" && c.pr === "N" && (c.ui === "N" || !c.ui)) r.appendChild(el("span","b plain","인증 없이 원격"));
        var k = koOf(c.id); r.appendChild(el("span","muted", k || c.d));
        ul.appendChild(r);
      });
      det.appendChild(ul); body.appendChild(det);
      var f = el("div","foot"); f.appendChild(doneBox(g.gid, li)); body.appendChild(f);
      li.appendChild(body); list.appendChild(li);
    });
    if(arr.length > updState.shown){
      var more = el("li","more"), b = el("button","btn ghost", "더 보기 (" + (arr.length - updState.shown) + "개 남음)"); b.type = "button";
      b.addEventListener("click", function(){ updState.shown += 30; renderUpdates(); }); more.appendChild(b); list.appendChild(more);
    }
  }

  // ---------- product update groups (major vendors)
  function groupHits(g){
    var hay = g.vendor + " | " + (g.products || []).join(" | "), out = [];
    matchers.forEach(function(m){ if(m.re.test(hay)) out.push(m.label); });
    return out;
  }
  function groupText(g){
    var ko = koOf(g.gid); if(ko) return { t:ko, ko:true };
    var prods = (g.products || []).slice(0, 2).join(", ");
    var t = g.vendor + (prods ? " " + prods : "") + " 취약점 " + (g.count || g.cves.length) + "건이 고쳐졌습니다.";
    if(g.nRemote) t += " 그중 " + g.nRemote + "건은 인증 없이 원격 공격이 가능합니다(최고 " + g.maxScore.toFixed(1) + "점).";
    else t += " 최고 " + g.maxScore.toFixed(1) + "점.";
    if(g.kev && g.kev.length) t += " 실제 악용이 확인된 취약점이 포함돼 있습니다.";
    else if(g.exploited && g.exploited.length) t += " 공개된 공격 코드(PoC)가 있는 취약점이 포함돼 있습니다.";
    return { t:t, ko:false };
  }
  function groupFix(g){ return (g.fixes || []).join(" · "); }
  function groupActNode(g){
    var a = el("div","act"), ft = groupFix(g);
    if(ft){ var s = el("span"); s.appendChild(el("b", null, "버전")); s.appendChild(document.createTextNode(ft)); a.appendChild(s); }
    (g.refs || []).slice(0, 2).forEach(function(u){ a.appendChild(link(u, host(u) + " 공지 ↗")); });
    return a.childNodes.length ? a : null;
  }

  // ---------- verdict (today's call)
  var verdictItems = [], verdictHead = "";
  function vRow(list, pillCls, pillText, it, kind){
    var li = el("li"); li.appendChild(el("span","pill " + pillCls, pillText));
    var b = el("div","v-body"), l = el("div","v-line");
    if(kind === "kisa"){
      l.appendChild(link(it.url, it.title));
      l.appendChild(el("span","date", "KISA " + it.date));
      b.appendChild(l);
      var rel = kisaRelated(it);
      b.appendChild(el("div","ko-en", rel.kev.length ? "같은 벤더 KEV(실제 악용) 최근 30일 " + rel.kev.length + "건. KISA 원문에서 해당 버전을 확인하세요." : "KISA 업데이트 권고. 원문에서 해당 제품·버전을 확인하세요."));
    } else if(kind === "update"){
      l.appendChild(el("span","prod", it.vendor + " 보안 업데이트"));
      l.appendChild(el("span","muted small", (it.products || []).slice(0, 3).join(", ")));
      l.appendChild(el("span","date", "공개 " + it.date));
      b.appendChild(l);
      var gt = groupText(it); b.appendChild(el("div", gt.ko ? "ko" : "ko-en", gt.t));
      var ga = groupActNode(it); if(ga) b.appendChild(ga);
    } else {
      l.appendChild(cveLink(it.id));
      l.appendChild(el("span","prod", [it.vendor, it.product].filter(Boolean).join(" · ")));
      l.appendChild(el("span","date", kind === "kev" ? "KEV 등재 " + it.added : "공개 " + it.published));
      b.appendChild(l);
      var ko = koOf(it.id);
      // Kernel records all open with the same boilerplate; show the patch subject line instead.
      var en = (it.name || it.summary || "").replace(/^In the Linux kernel, the following vulnerability has been resolved:\s*/i, "").split("\n")[0];
      b.appendChild(el("div", ko ? "ko" : "ko-en", ko || en));
      var an = actionNode(it); if(an) b.appendChild(an);
    }
    li.appendChild(b); list.appendChild(li);
  }
  function renderVerdict(){
    if(!document.getElementById("vHead")) return;
    var head = document.getElementById("vHead"), sub = document.getElementById("vSub"), list = document.getElementById("vList");
    list.textContent = ""; verdictItems = []; sub.textContent = "";
    head.className = "v-head";
    if(!data.meta){ head.textContent = loadMsg; sub.textContent = ""; return; }
    var gen = new Date(data.meta.generatedAt);
    document.getElementById("vDate").textContent = "오늘의 판정 · " + gen.toLocaleDateString("ko-KR", {month:"long", day:"numeric", weekday:"short"});
    var from7 = daysAgo(7), from14 = daysAgo(14), from30 = daysAgo(30);
    if(!watch.length){
      var k7 = data.kev.filter(function(v){ return v.added >= from7 && !done[v.id]; }).sort(function(a, b){ return riskScore(b,"kev") - riskScore(a,"kev"); });
      var k7ids = k7.map(function(x){ return x.id; });
      var hot = data.critical.filter(function(c){ return c.published >= from14 && isRce(c) && hasSig(c) && !c.kev && !done[c.id] && k7ids.indexOf(c.id) < 0; }).sort(function(a, b){ return riskScore(b,"critical") - riskScore(a,"critical"); });
      var edgeN = k7.filter(function(v){ return v.edge; }).length;
      if(!k7.length && !hot.length){
        head.textContent = "지난 7일 새로 확인된 실제 악용이 없습니다"; head.classList.add("ok");
        sub.textContent = "고위험 신규 목록은 왼쪽 메뉴에서 볼 수 있습니다."; verdictHead = head.textContent; return;
      }
      head.textContent = k7.length ? "지난 7일 실제 악용 " + k7.length + "건이 새로 확인됐습니다" : "즉시 위험한 고위험 취약점 " + hot.length + "건";
      head.classList.add(k7.length ? "p1" : "p2");
      sub.textContent = [k7.length && edgeN ? "그중 VPN·방화벽 같은 경계 장비 " + edgeN + "건" : "",
                         hot.length && k7.length ? "최근 2주 고위험 중 인증 없이 원격 + 공격 코드 공개 " + hot.length + "건" : "",
                         "처리했으면 각 항목의 ‘확인함’을 누르세요"].filter(Boolean).join(" · ");
      verdictHead = head.textContent;
      var shownG = 0, MAXG = 4, moreG = null, moreGS = null, moreGN = 0;
      function addG(pc, pt, it, kind){
        verdictItems.push([pt, it, kind]);
        if(shownG < MAXG){ shownG++; vRow(list, pc, pt, it, kind); return; }
        if(!moreG){ var mli = el("li","v-old"), md = el("details"); moreGS = el("summary"); md.appendChild(moreGS); moreG = el("ul","v-list"); md.appendChild(moreG); mli.appendChild(md); list.appendChild(mli); }
        moreGN++; vRow(moreG, pc, pt, it, kind); moreGS.textContent = moreGN + "건 더 보기";
      }
      k7.slice(0, 20).forEach(function(it){ addG("p1", "실제 악용", it, "kev"); });
      hot.slice(0, 8).forEach(function(it){ addG("p2", "즉시 위험", it, "critical"); });
      return;
    }
    var from90 = daysAgo(90);
    var p1 = data.kev.filter(function(v){ return v._hits.length && v.added >= from30 && !done[v.id]; });
    var p1ids = p1.map(function(v){ return v.id; });
    function urgent(g){ return g.kev.length || g.exploited.length || (g.maxScore >= 9 && g.nRemote > 0); }
    var grpAll = data.updates.filter(function(g){ return g._hits.length && !done[g.gid] && g.date >= from90; });
    var grp = grpAll.filter(urgent), grpCalm = grpAll.length - grp.length;
    var grpNew = grp.filter(function(g){ return g.date >= from30; }), grpOld = grp.filter(function(g){ return g.date < from30; });
    var crit = data.critical.filter(function(c){ return c._hits.length && !c.kev && !c.major && !done[c.id] && c.published >= from90 && isRce(c); });
    var critNew = crit.filter(function(c){ return c.published >= from30; }), critOld = crit.filter(function(c){ return c.published < from30 && hasSig(c); });
    var kisa = data.kisa.filter(function(k){ return k._hits.length && k.date >= from14 && !done["kisa:" + k.ntt]; });
    var p2n = grpNew.length + critNew.length + kisa.length, oldN = grpOld.length + critOld.length;
    var scope = "등록한 제품 " + watch.length + "개 기준";
    if(!p1.length && !p2n && !oldN){
      head.textContent = "오늘은 처리할 일이 없습니다";
      head.classList.add("ok"); sub.textContent = scope + " · 실제 악용·급한 업데이트 없음"; verdictHead = head.textContent;
      return;
    }
    head.textContent = p1.length ? "오늘 처리할 것 " + p1.length + "건" + (p2n ? ", 이번 주에 볼 것 " + p2n + "건" : "")
                     : p2n ? "이번 주에 확인할 것 " + p2n + "건"
                     : "새 항목은 없고, 아직 확인 안 한 이전 업데이트가 " + oldN + "건 있습니다";
    if((p1.length || p2n) && oldN) sub.textContent = "놓친 이전 업데이트 " + oldN + "건 포함 · ";
    head.classList.add(p1.length ? "p1" : "p2"); sub.textContent = (sub.textContent || "") + scope + " · 처리했으면 각 항목의 ‘확인함’을 누르세요"; verdictHead = head.textContent;
    // New items first (up to 7), then up to 4 older updates that are still unchecked, so a missed patch never sinks out of view.
    var shown = 0, MAX = 4, MAXMORE = 16, shownOld = 0, MAXOLD = 10, hidden = 0, oldBox = null, oldSum = null, moreBox = null, moreSum = null, moreN = 0;
    function add(pc, pt, it, kind){
      if(shown < MAX){ shown++; verdictItems.push([pt, it, kind]); vRow(list, pc, pt, it, kind); return; }
      if(moreN >= MAXMORE){ hidden++; return; }
      if(!moreBox){ var mli = el("li","v-old"), md = el("details"); moreSum = el("summary"); md.appendChild(moreSum); moreBox = el("ul","v-list"); md.appendChild(moreBox); mli.appendChild(md); list.appendChild(mli); }
      moreN++; verdictItems.push([pt, it, kind]); vRow(moreBox, pc, pt, it, kind);
      moreSum.textContent = "새 항목 " + moreN + "건 더 보기";
    }
    function addOld(it, kind){
      if(shownOld++ >= MAXOLD){ hidden++; return; }
      if(!oldBox){ var oli = el("li","v-old"), od = el("details"); oldSum = el("summary"); od.appendChild(oldSum); oldBox = el("ul","v-list"); od.appendChild(oldBox); oli.appendChild(od); list.appendChild(oli); }
      verdictItems.push(["이전", it, kind]); vRow(oldBox, "", "놓친 것", it, kind);
      oldSum.textContent = "아직 확인 안 한 이전 업데이트 " + shownOld + "건 보기";
    }
    p1.sort(function(a, b){ return riskScore(b,"kev") - riskScore(a,"kev"); }).forEach(function(it){ add("p1", "오늘 처리", it, "kev"); });
    grpNew.sort(function(a, b){ return (b.kev.length - a.kev.length) || (b.exploited.length - a.exploited.length) || (b.maxScore - a.maxScore); }).forEach(function(g){ add("p2", "이번 주", g, "update"); });
    critNew.sort(function(a, b){ return riskScore(b,"critical") - riskScore(a,"critical"); }).forEach(function(it){ add("p2", "이번 주", it, "critical"); });
    kisa.forEach(function(k){ add("p2", "KISA", k, "kisa"); });
    grpOld.sort(function(a, b){ return (b.kev.length - a.kev.length) || (b.maxScore - a.maxScore); }).forEach(function(g){ addOld(g, "update"); });
    critOld.forEach(function(it){ addOld(it, "critical"); });
    if(hidden){ var more = el("li"); more.appendChild(el("span","pill","+" + hidden)); more.appendChild(el("span","small muted","나머지는 아래 목록에서 ‘내 제품만’을 눌러 확인하세요.")); list.appendChild(more); }
  }

  function flash(btn, msg){ btn.dataset.flash = msg; clearTimeout(btn._ft); btn._ft = setTimeout(function(){ delete btn.dataset.flash; }, 2200); }

  // ---------- report text (copy)
  function reportText(){
    if(!data.meta) return "";
    var L = [], gen = new Date(data.meta.generatedAt).toLocaleDateString("ko-KR");
    L.push("[크리티컬 취약점 레이더] " + gen + " 기준");
    L.push("");
    L.push("■ 오늘 판정: " + verdictHead);
    verdictItems.forEach(function(x){
      var it = x[1];
      if(x[2] === "kisa"){ L.push("- [" + x[0] + "] KISA " + it.date + " " + it.title + " " + it.url); return; }
      if(x[2] === "update"){ var gf = groupFix(it); L.push("- [" + x[0] + "] " + it.vendor + " 보안 업데이트 (" + it.date + "): " + groupText(it).t + (gf ? " (버전: " + gf + ")" : "") + ((it.refs || [])[0] ? " " + it.refs[0] : "")); return; }
      var line = "- [" + x[0] + "] " + it.id + " " + [it.vendor, it.product].filter(Boolean).join(" ") + ": " + (koOf(it.id) || it.name || "");
      var ft = fixText(it.fix); if(ft) line += " (버전: " + ft + ")";
      L.push(line);
    });
    var from7 = daysAgo(7), k7 = data.kev.filter(function(v){ return v.added >= from7; });
    var crit14 = data.critical.filter(function(c){ return c.published >= daysAgo(14); });
    var hot = crit14.filter(function(c){ return isRce(c) && hasSig(c); }).length;
    var kisa7 = data.kisa.filter(function(k){ return k.date >= from7; });
    L.push("");
    L.push("■ 최근 7일");
    L.push("- 실제 악용(KEV) 신규 " + k7.length + "건: 경계 장비 " + k7.filter(function(v){ return v.edge; }).length + "건, 랜섬웨어 연관 " + k7.filter(function(v){ return v.ransomware === "Known"; }).length + "건, 침해 흔적 점검 필요 " + k7.filter(function(v){ return v.forensic; }).length + "건");
    L.push("- 신규 CVSS 9.0+ (14일) " + crit14.length + "건 중 원격·무인증·무조작 + 악용 신호 " + hot + "건");
    if(kisa7.length) L.push("- KISA 권고 " + kisa7.length + "건: " + kisa7.map(function(k){ return k.vendor || k.title; }).filter(function(v, i, a){ return a.indexOf(v) === i; }).join(", "));
    L.push("");
    L.push("출처: CISA KEV, CVE List V5, KISA 보호나라 · " + REPORT_URL);
    return L.join("\n");
  }
  var copyBtnEl = document.getElementById("copyBtn");
  if(copyBtnEl) copyBtnEl.addEventListener("click", function(){
    var btn = this, text = reportText(); if(!text) return;
    var wrap = document.getElementById("copyFallbackWrap"), ta = document.getElementById("copyFallback");
    function fallback(){ ta.value = text; wrap.hidden = false; ta.focus(); ta.select(); flash(btn, "아래에서 복사하세요"); }
    try{
      navigator.clipboard.writeText(text).then(function(){ wrap.hidden = true; flash(btn, "복사했습니다"); }, fallback);
    }catch(e){ fallback(); }
  });

  // ---------- weekly brief as a day-by-day timeline
  function pocGroup(ul, pocs){
    if(!pocs.length) return 0;
    var made = 0, rest = [];
    function line(e, mine){
      var li = el("li"); li.appendChild(el("span","tag2 kev","PoC 새로 공개")); li.appendChild(cveLink(e.id));
      li.appendChild(el("span","prod", [e.vendor, e.product].filter(Boolean).join(" · ")));
      if(mine) li.appendChild(el("span","b mine","내 제품")); ul.appendChild(li); made++;
    }
    pocs.forEach(function(e){ if(hitsFor(e).length) line(e, true); else rest.push(e); });
    if(rest.length <= 3){ rest.forEach(function(e){ line(e, false); }); return made; }
    var byV = {}; rest.forEach(function(e){ var v = e.vendor || "기타"; (byV[v] = byV[v] || []).push(e); });
    var vs = Object.keys(byV).sort(function(a, b){ return byV[b].length - byV[a].length; });
    var li = el("li"), det = el("details","poc"), sm = el("summary");
    sm.appendChild(el("span","tag2 kev","PoC 새로 공개"));
    sm.appendChild(document.createTextNode(" " + rest.length + "건 · " + vs.slice(0, 3).map(function(v){ return v + " " + byV[v].length; }).join(", ") + (vs.length > 3 ? " 외 " + (vs.length - 3) + "곳" : "")));
    det.appendChild(sm);
    vs.forEach(function(v){
      var d = el("div","pocv"); d.appendChild(el("b", null, v + " "));
      var prods = byV[v].map(function(e){ return e.product; }).filter(function(p, i, a){ return p && a.indexOf(p) === i; }).slice(0, 4);
      if(prods.length) d.appendChild(el("span","muted small", prods.join(", ") + " "));
      byV[v].slice(0, 6).forEach(function(e, i){ if(i) d.appendChild(document.createTextNode(" ")); d.appendChild(cveLink(e.id)); });
      if(byV[v].length > 6) d.appendChild(el("span","muted small"," 외 " + (byV[v].length - 6) + "건"));
      det.appendChild(d);
    });
    li.appendChild(det); ul.appendChild(li); made++;
    return made;
  }
  function renderTimeline(){
    var box = document.getElementById("timeline"); box.textContent = "";
    if(!data.meta){ box.appendChild(el("p","muted", loadMsg)); return; }
    var evByDay = {}; (data.changes || []).forEach(function(d){ evByDay[d.date] = d.items || []; });
    var EVL = { crit_active:["악용 새로 확인","hot"], crit_poc:["PoC 새로 공개","kev"], kev_ransomware:["랜섬웨어 사용 확인","hot"] };
    for(var i = 0; i < 7; i++){
      var d = daysAgo(i), lab = dayLabel(d);
      var row = el("div","tl-day"), dd = el("div","tl-date", lab.md); dd.appendChild(el("small", null, (i === 0 ? "오늘 " : i === 1 ? "어제 " : "") + lab.wd + "요일"));
      row.appendChild(dd);
      var ul = el("ul","tl-items"), n = 0;
      data.kev.filter(function(v){ return v.added === d; }).forEach(function(v){
        var li = el("li"); li.appendChild(el("span","tag2 kev","KEV 추가")); li.appendChild(cveLink(v.id));
        li.appendChild(el("span","prod", [v.vendor, v.product].join(" · ")));
        if(v._hits.length) li.appendChild(el("span","b mine","내 제품"));
        var ko = koOf(v.id); if(ko) li.appendChild(el("span","muted", ko));
        ul.appendChild(li); n++;
      });
      var pocs = [];
      (evByDay[d] || []).forEach(function(e){
        var m = EVL[e.type]; if(!m) return;
        if(e.type === "crit_poc"){ pocs.push(e); return; }
        var li = el("li"); li.appendChild(el("span","tag2 " + m[1], m[0])); li.appendChild(cveLink(e.id));
        li.appendChild(el("span","prod", [e.vendor, e.product].filter(Boolean).join(" · ")));
        ul.appendChild(li); n++;
      });
      n += pocGroup(ul, pocs);
      data.kisa.filter(function(k){ return k.date === d; }).forEach(function(k){
        var li = el("li"); li.appendChild(el("span","tag2 kisa","KISA")); li.appendChild(link(k.url, k.title));
        if(k._hits.length) li.appendChild(el("span","b mine","내 제품"));
        var rel = kisaRelated(k); if(rel.kev.length) li.appendChild(el("span","b kev","같은 벤더 KEV " + rel.kev.length + "건"));
        ul.appendChild(li); n++;
      });
      var ud = data.updates.filter(function(g){ return g.date === d; });
      var keyU = ud.filter(function(g){ return g._hits.length || g.kev.length || (g.maxScore >= 9 && g.nRemote) || koOf(g.gid); })
                   .sort(function(a, b){ return (b._hits.length - a._hits.length) || (b.kev.length - a.kev.length) || (b.maxScore - a.maxScore); }).slice(0, 4);
      keyU.forEach(function(g){
        var li = el("li"); li.appendChild(el("span","tag2 " + (g.kev.length ? "hot" : "kisa"), "업데이트"));
        li.appendChild(el("span","prod", g.vendor + " " + (g.products || []).slice(0, 2).join(", ")));
        if(g._hits.length) li.appendChild(el("span","b mine","내 제품"));
        li.appendChild(el("span","muted", groupText(g).t));
        ul.appendChild(li); n++;
      });
      if(ud.length > keyU.length){
        var restV = ud.filter(function(g){ return keyU.indexOf(g) < 0; }).map(function(g){ return g.vendor; });
        var lr = el("li"); lr.appendChild(el("span","tag2","업데이트")); lr.appendChild(el("span","muted", "그 외 " + restV.length + "곳: " + restV.slice(0, 8).join(", ") + (restV.length > 8 ? " 등" : "")));
        ul.appendChild(lr); n++;
      }
      var cd = data.critical.filter(function(c){ return c.published === d; });
      var hotd = cd.filter(function(c){ return isRce(c) && hasSig(c); });
      if(cd.length){
        var li = el("li"); li.appendChild(el("span","tag2" + (hotd.length ? " hot" : ""),"신규 Critical"));
        li.appendChild(document.createTextNode(cd.length + "건 공개" + (hotd.length ? ", 그중 즉시 위험 " + hotd.length + "건: " : "")));
        hotd.slice(0, 2).forEach(function(c, j){ if(j) li.appendChild(document.createTextNode(", ")); li.appendChild(cveLink(c.id)); var nm = [c.product, c.vendor].filter(function(v){ return v && v !== "n/a"; })[0] || ""; if(nm) li.appendChild(document.createTextNode(" " + nm)); });
        if(hotd.length > 2) li.appendChild(document.createTextNode(" 외 " + (hotd.length - 2) + "건"));
        ul.appendChild(li); n++;
      }
      if(!n) ul.appendChild(el("li","tl-quiet","새로 생긴 항목 없음"));
      row.appendChild(ul); box.appendChild(row);
    }
  }

  // ---------- KISA tab
  var kisaState = { range:30, scope:(watch.length ? "mine" : "all") };
  function renderKisa(){
    var rs = document.getElementById("kisaRange"), ss = document.getElementById("kisaScope");
    rs.textContent = ""; ss.textContent = "";
    [[7,"7일"],[30,"30일"],[90,"90일"]].forEach(function(r){
      var b = el("button", null, r[1]); b.type = "button"; b.setAttribute("aria-pressed", String(kisaState.range === r[0]));
      b.addEventListener("click", function(){ kisaState.range = r[0]; renderKisa(); }); rs.appendChild(b);
    });
    [["all","전체"],["mine","내 제품만"]].forEach(function(r){
      var b = el("button", null, r[1]); b.type = "button"; b.setAttribute("aria-pressed", String(kisaState.scope === r[0]));
      b.addEventListener("click", function(){ kisaState.scope = r[0]; renderKisa(); }); ss.appendChild(b);
    });
    var list = document.getElementById("kisaList"); list.textContent = "";
    if(!data.meta){ list.appendChild(el("li","empty", loadMsg)); return; }
    var from = daysAgo(kisaState.range);
    var arr = data.kisa.filter(function(k){ return k.date >= from && (kisaState.scope === "all" || k._hits.length); });
    if(!arr.length){ list.appendChild(el("li","empty", kisaState.scope === "mine" ? "이 기간에 내 제품과 일치하는 KISA 권고가 없습니다." : "이 기간에 KISA 권고가 없습니다.")); return; }
    var KIND = { update:"업데이트 권고", vuln:"취약점 조치 권고", notice:"주의·대응 권고" };
    arr.forEach(function(k){
      var li = el("li","item"), sc = el("div","score kisa"); sc.appendChild(el("b", null, "KISA")); sc.appendChild(el("span", null, k.date.slice(5).replace("-", "/"))); li.appendChild(sc);
      var body = el("div","body"), l1 = el("div","line1");
      l1.appendChild(link(k.url, k.title, "prod")); l1.appendChild(el("span","date", k.date)); body.appendChild(l1);
      var bd = el("div","badges"); bd.appendChild(el("span","b plain", KIND[k.kind] || "권고"));
      if(k._hits.length) bd.appendChild(el("span","b mine","내 제품: " + k._hits.join(", ")));
      var rel = kisaRelated(k);
      if(rel.kev.length) bd.appendChild(el("span","b kev","같은 벤더 KEV(실제 악용) 30일 " + rel.kev.length + "건"));
      if(rel.crit.length) bd.appendChild(el("span","b rw","즉시 위험 Critical " + rel.crit.length + "건"));
      body.appendChild(bd);
      if(rel.kev.length || rel.crit.length){
        var r = el("div","act"); r.appendChild(el("b", null, "관련"));
        rel.kev.concat(rel.crit).slice(0, 5).forEach(function(x){ var s = el("span"); s.appendChild(cveLink(x.id)); s.appendChild(document.createTextNode(" " + x.product)); r.appendChild(s); });
        body.appendChild(r);
      }
      var kf = el("div","foot"); kf.appendChild(doneBox("kisa:" + k.ntt, li)); body.appendChild(kf);
      li.appendChild(body); list.appendChild(li);
    });
  }

  // ---------- packages & supply chain tab
  var pkgState = { kind:"adv", scope:(watch.length ? "mine" : "all"), sev:"all", eco:"", q:"", shown:40 };
  function pkgHits(names){
    var hay = names.join(" | "), out = [];
    matchers.forEach(function(m){ if(m.re.test(hay)) out.push(m.label); });
    return out;
  }
  function pkgCmds(p){
    var out = [], n = p.n;
    if(!/^[@A-Za-z0-9._\/-]{1,120}$/.test(n)) return out;
    (p.fix || []).slice(0, 2).forEach(function(f){
      if(!/^[0-9][0-9A-Za-z.+_-]{0,40}$/.test(f)) return;
      var c = null;
      if(p.e === "npm") c = "npm i " + n + "@" + f;
      else if(p.e === "PyPI") c = 'pip install -U "' + n + ">=" + f + '"';
      else if(p.e === "Go") c = "go get " + n + "@v" + f;
      else if(p.e === "Packagist") c = 'composer require "' + n + ":>=" + f + '"';
      else if(p.e === "NuGet") c = "dotnet add package " + n + " --version " + f;
      else if(p.e === "RubyGems") c = "bundle update " + n;
      else if(p.e === "crates.io") c = "cargo update -p " + n;
      if(c) out.push({ v:f, cmd:c });
    });
    return out;
  }
  function pkgTerm(it){ return (it.p ? it.p.map(function(x){ return x.n; }) : [it.n]).join(" ").toLowerCase(); }
  function renderPkg(){
    var seg = function(id, opts, cur, fn){ segButtons(document.getElementById(id), opts, cur, function(v){ fn(v); pkgState.shown = 40; renderPkg(); }); };
    seg("pkgKind", [["adv","취약점 (High·Critical)"],["mal","악성 패키지"]], pkgState.kind, function(v){ pkgState.kind = v; pkgState.eco = ""; });
    seg("pkgScope", [["all","전체"],["mine","내 제품만"]], pkgState.scope, function(v){ pkgState.scope = v; });
    var sevBox = document.getElementById("pkgSev"); sevBox.hidden = pkgState.kind !== "adv";
    seg("pkgSev", [["all","High+Critical"],["C","Critical만"]], pkgState.sev, function(v){ pkgState.sev = v; });
    var list = document.getElementById("pkgList"), note = document.getElementById("pkgNote"), chips = document.getElementById("pkgEco");
    list.textContent = ""; chips.textContent = "";
    if(!data.meta){ list.appendChild(el("li","empty", loadMsg)); return; }
    var adv = pkgState.kind === "adv", src = adv ? data.pkg.ghsa : data.pkg.mal, q = pkgState.q.trim().toLowerCase();
    var ecoCount = {}; src.forEach(function(it){ var es = adv ? it.p.map(function(x){ return x.e; }) : [it.e]; es.forEach(function(e){ ecoCount[e] = (ecoCount[e] || 0) + 1; }); });
    chips.appendChild(el("span","lab","생태계"));
    Object.keys(ecoCount).sort(function(a, b){ return ecoCount[b] - ecoCount[a]; }).slice(0, 8).forEach(function(e){
      var b = el("button","fchip", e + " " + ecoCount[e]); b.type = "button"; b.setAttribute("aria-pressed", String(pkgState.eco === e));
      b.addEventListener("click", function(){ pkgState.eco = pkgState.eco === e ? "" : e; pkgState.shown = 40; renderPkg(); }); chips.appendChild(b);
    });
    var arr = src.filter(function(it){
      if(adv && pkgState.sev === "C" && it.sev !== "C") return false;
      if(pkgState.eco && (adv ? it.p.every(function(x){ return x.e !== pkgState.eco; }) : it.e !== pkgState.eco)) return false;
      if(q && pkgTerm(it).indexOf(q) < 0 && (it.s || "").toLowerCase().indexOf(q) < 0 && (it.cve || it.id).toLowerCase().indexOf(q) < 0) return false;
      if(pkgState.scope === "mine" && !it._hits.length) return false;
      return true;
    });
    if(!adv) arr.sort(function(a, b){ return (b._hits.length - a._hits.length) || (a.pub < b.pub ? 1 : a.pub > b.pub ? -1 : 0); });
    else arr.sort(function(a, b){ return (b._hits.length - a._hits.length) || ((b.kev ? 1 : 0) - (a.kev ? 1 : 0)) || ((b.sev === "C" ? 1 : 0) - (a.sev === "C" ? 1 : 0)) || (a.pub < b.pub ? 1 : a.pub > b.pub ? -1 : 0); });
    note.textContent = (adv ? "GitHub 검수 보안 권고 중 High·Critical, 최근 " + (data.pkg.ghsaDays || 30) + "일" : "OpenSSF 악성 패키지 DB, 최근 " + (data.pkg.malDays || 14) + "일")
      + " · " + fmt(arr.length) + "건" + (pkgState.scope === "mine" ? " (내 제품 일치)" : "");
    if(!adv){
      var warn = el("li","note", "악성 패키지가 설치돼 있다면 해당 PC나 서버 전체가 침해된 것으로 보고, 패키지를 지운 뒤 거기 저장된 키·토큰·비밀번호를 다른 기기에서 교체하세요. 이름이 비슷한 가짜(타이포스쿼팅)가 대부분이라 목록 전체를 볼 필요는 없고, 내가 쓰는 패키지 이름이 있는지만 확인하면 됩니다.");
      list.appendChild(warn);
    }
    if(!arr.length){
      list.appendChild(el("li","empty", pkgState.scope === "mine" ? (watch.length ? "이 조건에서 내 제품과 일치하는 항목이 없습니다. (패키지 이름으로 찾습니다: next, express, django …)" : "‘내가 쓰는 제품’에 패키지 이름을 등록하면 여기서 바로 걸러 보여줍니다. 예: next, express, django, requests") : "조건에 맞는 항목이 없습니다."));
      return;
    }
    arr.slice(0, pkgState.shown).forEach(function(it){
      var li = el("li","item"), sc = el("div","score " + (adv ? (it.sev === "C" ? "crit" : "kev") : "crit"));
      sc.appendChild(el("b", null, adv ? (it.sev === "C" ? "CRIT" : "HIGH") : "MAL")); sc.appendChild(el("span", null, it.pub.slice(5).replace("-", "/"))); li.appendChild(sc);
      var body = el("div","body"), l1 = el("div","line1");
      if(adv){
        l1.appendChild(link("https://github.com/advisories/" + encodeURIComponent(it.id), it.id, "cve"));
        it.p.forEach(function(x){ var s = el("span","prod", x.n); s.title = x.e; l1.appendChild(s); });
        if(it.np > it.p.length) l1.appendChild(el("span","muted small", "외 " + (it.np - it.p.length) + "개"));
      } else {
        l1.appendChild(link("https://osv.dev/vulnerability/" + encodeURIComponent(it.id), it.n, "prod"));
        l1.appendChild(el("span","muted small", it.id));
      }
      l1.appendChild(el("span","date", it.pub)); body.appendChild(l1);
      if(adv && (koOf(it.id) || it.s)){ var dsc = el("div","desc", koOf(it.id) || it.s); if(koOf(it.id) && it.s) dsc.title = it.s; body.appendChild(dsc); }
      var bd = el("div","badges");
      if(adv){
        if(it.kev) bd.appendChild(el("span","b kev","실제 악용 (KEV)"));
        it.p.map(function(x){ return x.e; }).filter(function(e, i, a){ return a.indexOf(e) === i; }).forEach(function(e){ bd.appendChild(el("span","b plain", e)); });
        var fx = []; it.p.forEach(function(x){ x.fix.forEach(function(f){ fx.push(x.n + " " + f); }); });
        if(fx.length) bd.appendChild(el("span","b plain mono","수정: " + fx.slice(0, 2).join(", ") + (fx.length > 2 ? " …" : "")));
        else bd.appendChild(el("span","b plain","수정 버전 미공개"));
      } else {
        bd.appendChild(el("span","b rw","악성코드 포함")); bd.appendChild(el("span","b plain", it.e));
      }
      if(it._hits.length) bd.appendChild(el("span","b mine","내 제품: " + it._hits.join(", ")));
      body.appendChild(bd);
      if(adv){
        var cmds = []; it.p.forEach(function(x){ pkgCmds(x).forEach(function(k){ if(cmds.length < 2) cmds.push(k); }); });
        if(cmds.length){
          var ac = el("div","act cmdrow");
          cmds.forEach(function(k){
            var w = el("span","cmdw"), code = el("code","cmd", k.cmd), cb = el("button","btn ghost sm","복사"); cb.type = "button";
            cb.addEventListener("click", function(){
              function fb(){ var r = document.createRange(); r.selectNodeContents(code); var s = window.getSelection(); s.removeAllRanges(); s.addRange(r); cb.textContent = "선택됨"; }
              try{ navigator.clipboard.writeText(k.cmd).then(function(){ cb.textContent = "복사됨"; setTimeout(function(){ cb.textContent = "복사"; }, 1500); }, fb); }catch(e){ fb(); }
            });
            w.appendChild(code); w.appendChild(cb); ac.appendChild(w);
          });
          if(cmds.length > 1) ac.appendChild(el("span","muted small","주 버전이 여러 개면 쓰는 쪽에 맞는 줄을 고르세요."));
          body.appendChild(ac);
        }
      }
      var ft = el("div","foot");
      if(adv && it.cve) ft.appendChild(cveLink(it.cve));
      if(!adv && it.g) ft.appendChild(link("https://github.com/advisories/" + encodeURIComponent(it.g), it.g));
      ft.appendChild(doneBox("pkg:" + it.id, li)); body.appendChild(ft);
      li.appendChild(body); list.appendChild(li);
    });
    if(arr.length > pkgState.shown){
      var mo = el("li","more"), mb = el("button","btn ghost","더 보기 (" + fmt(arr.length - pkgState.shown) + "건 남음)"); mb.type = "button";
      mb.addEventListener("click", function(){ pkgState.shown += 40; renderPkg(); }); mo.appendChild(mb); list.appendChild(mo);
    }
  }
  (function(){ var q = document.getElementById("pkgQ"); if(q) q.addEventListener("input", function(){ pkgState.q = q.value; pkgState.shown = 40; if(state.view === "pkg") renderPkg(); }); })();

  function renderStats(){
    if(!data.meta) return;
    document.getElementById("cKev").textContent = data.kev.length;
    document.getElementById("cCrit").textContent = data.critical.filter(function(c){ return c.published >= daysAgo(14); }).length;
    document.getElementById("cUpd").textContent = data.updates.filter(function(g){ return g.date >= daysAgo(30); }).length;
    document.getElementById("cPkg").textContent = data.pkg.ghsa.length || "";
    document.getElementById("cKisa").textContent = data.kisa.filter(function(k){ return k.date >= daysAgo(30); }).length;
  }
  function renderFresh(){
    var m = data.meta; if(!m) return;
    var t = new Date(m.generatedAt), hrs = (Date.now() - t.getTime()) / 36e5;
    var s = t.toLocaleString("ko-KR", {month:"long", day:"numeric", hour:"numeric", minute:"2-digit"});
    var fr = document.getElementById("fresh"); fr.classList.toggle("stale", hrs > 36);
    document.getElementById("freshText").textContent = s + " 기준" + (hrs > 36 ? " · 갱신이 " + Math.floor(hrs / 24) + "일째 멈춰 있습니다" : "");
    var sub = document.getElementById("freshSub");
    if(m.kisaStatus === "ok" || m.kisaStatus === "skipped"){ sub.textContent = ""; sub.hidden = true; }
    else { sub.hidden = false; sub.textContent = "KISA 공지를 이번에 가져오지 못했습니다" + (m.kisaFetchedAt ? " (마지막 성공 " + new Date(m.kisaFetchedAt).toLocaleDateString("ko-KR", {month:"long", day:"numeric"}) + ")" : ""); }
  }
  function renderAll(){
    data.kev.forEach(function(it){ it._hits = hitsFor(it, "kev"); });
    data.critical.forEach(function(it){ it._hits = hitsFor(it, "critical"); });
    data.kisa.forEach(function(it){ it._hits = kisaHits(it); });
    data.updates.forEach(function(g){ g._hits = groupHits(g); });
    data.pkg.ghsa.forEach(function(it){ it._hits = pkgHits(it.p.map(function(x){ return x.n; })); });
    data.pkg.mal.forEach(function(it){ it._hits = pkgHits([it.n]); });
    renderStats(); renderFresh(); renderVerdict(); renderTimeline(); renderInsights(); renderList();
    if(state.view === "kisa") renderKisa();
    if(state.view === "upd") renderUpdates();
    if(state.view === "pkg") renderPkg();
    setTimeout(refreshFilters, 0);
  }

  // ---------- sources
  var SOURCES = [
    { h:"원천 · 가장 먼저 나오는 곳", d:"취약점은 벤더 공지와 CVE 레코드에 먼저 뜹니다. 쓰는 제품은 벤더 페이지를 직접 봅니다.", items:[
      ["CVE List V5 (GitHub)","https://github.com/CVEProject/cvelistV5","CVE 공식 데이터. 약 7분마다 갱신, deltaLog.json으로 신규만 받기 좋음","문서"],
      ["CVE.org","https://www.cve.org/","CVE 번호 검색과 레코드 원문","문서"],
      ["Microsoft 보안 업데이트 가이드","https://msrc.microsoft.com/update-guide","매월 둘째 화요일(한국 수요일 새벽) 정기 패치",""],
      ["Apple 보안 릴리스","https://support.apple.com/ko-kr/100100","iOS·macOS·Safari 패치 내역",""],
      ["Chrome Releases","https://chromereleases.googleblog.com/","Chrome 제로데이 패치가 가장 먼저 공지되는 곳",""],
      ["Android 보안 게시판","https://source.android.com/docs/security/bulletin","매월 첫째 주 공개",""],
      ["Samsung 모바일 보안","https://security.samsungmobile.com/securityUpdate.smsb","갤럭시 월간 보안 업데이트",""],
      ["Fortinet PSIRT","https://www.fortiguard.com/psirt","경계 장비 KEV 최다 벤더 중 하나",""],
      ["Ivanti 보안 권고","https://www.ivanti.com/blog/topics/security-advisory","VPN·EPMM 등 반복 악용 제품",""]
    ]},
    { h:"악용 여부 · 지금 공격받는 것", d:"점수보다 중요한 신호. 여기 있으면 우선순위가 바로 올라갑니다.", items:[
      ["CISA KEV","https://www.cisa.gov/known-exploited-vulnerabilities-catalog","실제 악용이 확인된 취약점. 이 페이지의 1번 데이터","문서"],
      ["CISA KEV (GitHub 미러)","https://github.com/cisagov/kev-data","JSON·CSV를 GitHub에서 바로 받을 수 있음","문서"],
      ["VulnCheck KEV","https://vulncheck.com/kev","CISA KEV보다 범위가 넓고 등재가 빠른 경우가 많음. 무료 커뮤니티 계정","추가"],
      ["EUVD (ENISA)","https://euvd.enisa.europa.eu/","EU 취약점 DB. 악용·크리티컬 목록을 따로 보여줌","추가"],
      ["Shadowserver 대시보드","https://dashboard.shadowserver.org/","인터넷에 노출된 취약 장비 수와 스캔 추이","추가"]
    ]},
    { h:"우선순위 · 점수 보조 지표", d:"CVSS는 얼마나 심각할 수 있는지, EPSS·SSVC는 실제로 터질 가능성을 봅니다.", items:[
      ["FIRST EPSS","https://www.first.org/epss/","향후 30일 내 악용 확률을 매일 계산. 무료 API","추가"],
      ["CISA Vulnrichment","https://github.com/cisagov/vulnrichment","CVE에 붙는 SSVC(악용 상태·자동화 가능·기술 영향)와 보강 CVSS","추가"],
      ["CISA SSVC 가이드","https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc","SSVC 결정 트리로 Track·Attend·Act 판단","추가"],
      ["FIRST CVSS","https://www.first.org/cvss/","0.0~10.0 심각도 기준. 9.0 이상이 Critical","문서"],
      ["NVD","https://nvd.nist.gov/","2026년 4월부터 KEV·핵심 SW 위주로만 보강. 단독 의존은 피할 것","변경"]
    ]},
    { h:"한국어 · 국내 특화", d:"국내에서 많이 쓰는 소프트웨어는 여기가 가장 정확합니다.", items:[
      ["KISA 보호나라 보안공지","https://www.boho.or.kr/kr/bbs/list.do?menuNo=205020&bbsId=B0000133","주요 벤더 보안 업데이트 권고를 한국어로 정리. 국산 SW 취약점 포함","추가"],
      ["보호나라 RSS","https://www.boho.or.kr/kr/subPage.do?menuNo=205121","보안공지를 RSS 리더나 메신저 봇으로 받기","추가"],
      ["보안뉴스","https://www.boannews.com/","국내 침해사고·취약점 뉴스","추가"]
    ]},
    { h:"일본어 · 참고", d:"원문 기사에서 소개한 정보원.", items:[
      ["JPCERT/CC","https://www.jpcert.or.jp/","중대 취약점 주의 환기, RSS 지원","문서"],
      ["JVN","https://jvn.jp/","일본 취약점 DB. 일본 제품 정보가 빠름","추가"]
    ]},
    { h:"오픈소스 · 개발자", d:"라이브러리 취약점은 패키지 생태계 기준으로 봐야 정확합니다.", items:[
      ["GitHub Advisory Database","https://github.com/advisories?query=severity%3Acritical","npm·PyPI·Go·Maven 등 패키지 보안 권고. Dependabot 알림의 원천. 패키지 탭에 High·Critical 반영","반영됨"],
      ["OpenSSF 악성 패키지 DB","https://github.com/ossf/malicious-packages","npm·PyPI 등에 올라온 악성 패키지(MAL-) 목록. 패키지 탭에 반영","반영됨"],
      ["OSV","https://osv.dev/","패키지 단위 취약점 통합 DB. 내 프로젝트 검사는 osv-scanner로","문서"]
    ]},
    { h:"속보 · 커뮤니티", d:"공식 공지 전에 소식이 먼저 도는 경우가 있습니다. 반드시 원천으로 다시 확인하세요.", items:[
      ["BleepingComputer","https://www.bleepingcomputer.com/","제로데이·랜섬웨어 속보",""],
      ["The Hacker News","https://thehackernews.com/","주요 취약점 요약 기사",""],
      ["watchTowr Labs","https://labs.watchtowr.com/","경계 장비 취약점 분석·PoC가 빨리 나오는 곳",""]
    ]}
  ];
  (function renderSources(){
    var box = document.getElementById("srcgroups");
    SOURCES.forEach(function(g){
      var s = el("div","sg"), hd = el("div"); hd.appendChild(el("h3", null, g.h)); hd.appendChild(el("div","muted small", g.d)); s.appendChild(hd);
      var ul = el("ul");
      g.items.forEach(function(x){
        var li = el("li"), t = el("div","t"); t.appendChild(link(x[1], x[0]));
        if(x[3]) t.appendChild(el("span","tag" + (x[3] === "추가" ? " new" : ""), x[3] === "문서" ? "원문 기사" : x[3] === "추가" ? "추가 추천" : x[3]));
        li.appendChild(t); li.appendChild(el("span","muted small", x[2])); ul.appendChild(li);
      });
      s.appendChild(ul); box.appendChild(s);
    });
  })();

  // ---------- data
  var loadMsg = "불러오는 중…";
  buildMatchers();
  setView(location.hash.slice(1) || "brief", false);
  function failAll(msg){ loadMsg = msg; renderVerdict(); renderTimeline(); renderInsights(); renderList(); if(state.view === "kisa") renderKisa(); }

  // Data is published next to the page as data/*.json and refreshed daily by a scheduled task.
  function getJson(name){
    return fetch("data/" + name + ".json", { cache:"no-store" }).then(function(r){
      if(!r.ok) throw new Error(name + " " + r.status); return r.json();
    });
  }
  function optJson(name, dflt){ return getJson(name).catch(function(){ return dflt; }); }
  Promise.all([getJson("meta"), getJson("insights"), getJson("kev"), getJson("critical"),
               optJson("kisa", {items:[]}), optJson("ko", {items:{}}), optJson("changes", {days:[]}), optJson("updates", {items:[]}), optJson("packages", {ghsa:[], mal:[]})]).then(function(res){
    data.meta = res[0]; data.ins = res[1];
    data.kev = (res[2].items || []).map(function(x){ return Object.assign({}, x); });
    data.critical = (res[3].items || []).map(function(x){ return Object.assign({}, x); });
    data.kisa = (res[4].items || []).map(function(x){ return Object.assign({}, x); });
    data.ko = res[5].items || {};
    data.changes = res[6].days || [];
    data.updates = (res[7].items || []).map(function(x){ return Object.assign({}, x); });
    data.pkg = { ghsa:(res[8].ghsa || []).map(function(x){ return Object.assign({}, x); }), mal:(res[8].mal || []).map(function(x){ return Object.assign({}, x); }), ghsaDays:res[8].ghsaDays, malDays:res[8].malDays };
    renderAll();
    // Older (15-90 day) Critical CVEs come in a second, lighter file so the first screen stays fast.
    optJson("archive", {items:[]}).then(function(a){
      var have = {}; data.critical.forEach(function(c){ have[c.id] = 1; });
      (a.items || []).forEach(function(x){ if(!have[x.id]) data.critical.push(Object.assign({}, x)); });
      data.archiveLoaded = true; renderAll();
    });
  }).catch(function(){
    failAll("데이터를 불러오지 못했습니다. 서버를 처음 띄웠다면 첫 수집이 끝날 때까지(수 분~수십 분) 기다린 뒤 새로고침해 주세요.");
  });
  // ---------- AI daily summary (EXAONE)
  var LEVEL = { urgent:["지금","lv-urgent"], watch:["이번 주","lv-watch"], info:["참고","lv-info"] };
  function renderSummary(sm){
    var card = document.getElementById("aiCard");
    if(!sm || sm.status !== "ok" || !sm.headline){ card.hidden = true; return; }
    card.hidden = false;
    var at = new Date(sm.generatedAt);
    var stale = sm.date !== new Date().toLocaleDateString("sv-SE", { timeZone:"Asia/Seoul" });
    document.getElementById("aiMeta").textContent = (stale ? sm.date + " 요약 · " : "") + at.toLocaleTimeString("ko-KR", {hour:"numeric", minute:"2-digit"}) + " 작성";
    document.getElementById("aiHead").textContent = sm.headline;
    var ul = document.getElementById("aiPoints"); ul.textContent = "";
    (sm.points || []).forEach(function(pt){
      var lv = LEVEL[pt.level] || LEVEL.info, li = el("li", lv[1]);
      li.appendChild(el("span","lv", lv[0]));
      var b = el("div","pt-body"); b.appendChild(el("strong", null, pt.title)); b.appendChild(el("p", null, pt.text));
      if(pt.ids && pt.ids.length){ var ids = el("div","pt-ids"); pt.ids.forEach(function(i){ ids.appendChild(cveLink(i)); }); b.appendChild(ids); }
      li.appendChild(b); ul.appendChild(li);
    });
    var aw = document.getElementById("aiActionsWrap"), al = document.getElementById("aiActions"); al.textContent = "";
    aw.hidden = !(sm.actions && sm.actions.length);
    (sm.actions || []).forEach(function(a){ al.appendChild(el("li", null, a)); });
  }
  optJson("summary", null).then(renderSummary);

  // ---------- theme
  (function(){
    var btn = document.getElementById("themeBtn"), root = document.documentElement;
    function cur(){ return root.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"); }
    function paint(){ btn.querySelector("use").setAttribute("href", cur() === "dark" ? "#i-sun" : "#i-moon"); }
    btn.addEventListener("click", function(){ root.dataset.theme = cur() === "dark" ? "light" : "dark"; LS.set("radar.theme", root.dataset.theme); paint(); });
    paint();
  })();

  // ---------- top search: KEV first, then 90-day Critical
  document.getElementById("topSearch").addEventListener("submit", function(e){
    e.preventDefault();
    var q = document.getElementById("topQ").value.trim().toLowerCase(); if(!q || !data.meta) return;
    state.q = q; document.getElementById("q").value = q; state.scope = "all"; state.hideDone = false;
    document.querySelectorAll("[data-scope]").forEach(function(x){ x.setAttribute("aria-pressed", String(x.dataset.scope === "all")); });
    state.kf = {rw:false, edge:false, fast:false, old:false}; state.cf = {rce:false, sig:false, edge:false, auto:false};
    state.range.kev = 90; state.range.critical = 90;
    var hitK = filtered("kev").length;
    setView(hitK ? "kev" : "critical", true);
    document.getElementById("main").scrollIntoView({ block:"start" });
  });

  if(window.claude && window.claude.use){
    downloadsP = window.claude.use("downloads").then(function(dl){ if(dl) document.getElementById("csvBtn").hidden = false; return dl; }).catch(function(){ return null; });
  } else {
    document.getElementById("csvBtn").hidden = false;
  }
})();
