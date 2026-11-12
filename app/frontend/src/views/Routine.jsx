// Static guide, unchanged from the original page.
export default function Routine() {
  return (
      <section id="v-routine">
          <div className="page-head"><h1>대응 루틴</h1><p>매일·매주 무엇을 보면 되는지 정리했습니다.</p></div>
          <div className="cols2">
            <div className="sg">
              <h3>보안 담당자용</h3>
              <ol className="steps">
                <li><div><h3>SLA를 점수가 아니라 악용 여부로</h3><p>KEV 등재는 CVSS와 상관없이 최우선. 인사이트 탭의 "CVSS만 보면 놓치는 KEV" 비율이 그 근거입니다. 예: KEV+외부 노출 72시간, KEV 내부 7일, 그 외 Critical은 EPSS·SSVC로 차등.</p></div></li>
                <li><div><h3>경계 장비는 따로 관리</h3><p>VPN·방화벽·게이트웨이 취약점은 공개 직후 대량 스캔이 시작됩니다. 패치와 함께 벤더가 낸 침해지표(IoC) 점검, 관리 인터페이스 외부 노출 차단까지 한 묶음으로.</p></div></li>
                <li><div><h3>자산 인벤토리와 자동 대조</h3><p>CPE·SBOM 기준 자산 목록을 KEV JSON과 매일 대조합니다. 이 페이지의 실제 악용 목록이 같은 역할을 합니다.</p></div></li>
                <li><div><h3>레거시 백로그를 버리지 않기</h3><p>KEV 등재의 상당수는 공개된 지 1년이 넘은 취약점입니다. 오래된 미패치 자산이 계속 공격 대상이 됩니다.</p></div></li>
                <li><div><h3>정기 패치일에 대비</h3><p>MS 패치 화요일(한국 수요일 새벽), Oracle CPU(1·4·7·10월), Chrome 주간 릴리스, Android·삼성 월간 게시판. 신규 Critical 일별 그래프의 급증일이 대부분 이런 날입니다.</p></div></li>
              </ol>
            </div>
            <div className="sg">
              <h3>개인용</h3>
              <ol className="steps">
                <li><div><h3>자동 업데이트부터 켜기</h3><p>Windows, macOS·iOS, Android·갤럭시, Chrome·Edge. 브라우저는 업데이트 후 재시작해야 적용돼요.</p></div></li>
                <li><div><h3>매일 아침 1분</h3><p>"오늘" 화면의 판정을 봅니다. 0건이면 끝, 있으면 벤더 공지에서 버전을 맞춥니다.</p></div></li>
                <li><div><h3>집 안의 잊힌 장비</h3><p>공유기, NAS(Synology·QNAP), IP카메라, VPN 앱. 상단 검색에 모델명을 넣어 확인하세요.</p></div></li>
                <li><div><h3>국산 소프트웨어는 KISA로</h3><p>보안 플러그인, 한컴오피스, 국산 백신은 보호나라 보안공지가 가장 빠르고 정확합니다.</p></div></li>
              </ol>
            </div>
          </div>
          <div className="cols2">
            <div className="sg"><h3>KEV 신규 항목만 뽑기</h3>
      <pre>{"# 최근 7일 추가된 KEV\ncurl -s https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json \\\n| jq -r --arg d \"$(date -d '-7 day' +%F)\" \\\n  '.vulnerabilities[] | select(.dateAdded >= $d)\n   | \"\\(.dateAdded) \\(.cveID) \\(.vendorProject) \\(.product)\"'"}</pre>
            </div>
            <div className="sg"><h3>EPSS 점수 조회 · OSV 스캔</h3>
      <pre>{"# EPSS (30일 내 악용 확률)\ncurl -s \"https://api.first.org/data/v1/epss?cve=CVE-2026-48356\"\n# 프로젝트 의존성 검사\nosv-scanner scan -r ."}</pre>
            </div>
          </div>
        </section>
  );
}
