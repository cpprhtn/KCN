import { ExtLink, PageHead } from "../components/common.jsx";

export const SOURCES = [
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
      ["KNVD 보안취약점 정보포털","https://knvd.krcert.or.kr/","KISA 보안공지·국내 공개 취약점. RSS를 30분마다 읽어 KNVD 탭에 쌓음","반영됨"],
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

const tagLabel = (t) => (t === "문서" ? "원문 기사" : t === "추가" ? "추가 추천" : t);

export default function Sources() {
  return (
    <section id="v-sources">
      <PageHead title="자료">취약점을 처음 확인할 수 있는 곳과 악용 여부를 알려 주는 곳입니다.</PageHead>
      <div className="note">
        <b>먼저 알아둘 변화.</b> 2026년 4월 15일부터 NIST NVD는 모든 CVE를 분석하지 않습니다. KEV 등재 CVE, 연방정부 사용 소프트웨어, 핵심 소프트웨어만 우선 보강하고, 나머지는 CVE를 등록한 CNA(주로 벤더)의 점수를 그대로 씁니다. 그래서 이 페이지는 NVD가 아니라 CVE 원본 레코드의 CNA 점수와 CISA 보강 데이터(Vulnrichment)를 읽습니다.
      </div>
      <div className="srcgroups">
        {SOURCES.map((g) => (
          <div className="sg" key={g.h}>
            <div><h3>{g.h}</h3><div className="muted small">{g.d}</div></div>
            <ul>
              {g.items.map((x) => (
                <li key={x[1]}>
                  <div className="t">
                    <ExtLink href={x[1]}>{x[0]}</ExtLink>
                    {x[3] && <span className={"tag" + (x[3] === "추가" ? " new" : "")}>{tagLabel(x[3])}</span>}
                  </div>
                  <span className="muted small">{x[2]}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </section>
  );
}
