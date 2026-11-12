# KCN — 취약점 모니터링 서버 (React + FastAPI + PostgreSQL + LibreTranslate)

아티팩트로 돌던 "크리티컬 취약점 레이더"를 자체 서버에 올리는 버전입니다.
화면(HTML/JS/CSS)과 수집 로직은 원본과 같고, 바뀐 부분은 다음과 같습니다.

| 원본 (아티팩트) | 서버판 |
|---|---|
| 상태를 `data/*.json` 파일로 보관 | **PostgreSQL** 테이블에 보관 |
| 한국어 한 줄 요약을 사람이(Claude가) 작성 | **LibreTranslate**(en→ko) 기계 번역, 백그라운드 큐 |
| KISA 공지를 외부에서 가져와 넘겨줌 | worker가 boho.or.kr 목록을 **직접 수집** |
| 예약 작업으로 하루 한 번 | worker 컨테이너 안 cron (`COLLECT_CRON`) |
| CSV는 아티팩트 다운로드 기능 | 브라우저 일반 다운로드 |
| 바닐라 JS 한 파일 | **React(Vite)** 화면, Docker 빌드 때 함께 빌드 |
| — | **KNVD RSS**(보안공지·공개 취약점)를 30분마다 읽어 DB에 계속 쌓음 |
| AI 요약 하루 1번, 최신 것만 | **하루 3번(7·12·19시)**, 모든 요약을 기록으로 보관 |

## 구성

```
┌────────┐  /data/*.json   ┌─────┐
│ 브라우저 │ ─────────────▶ │ web │ ──┐
└────────┘                 └─────┘   │ snapshots 읽기
                                     ▼
                     ┌──────────────────────┐
                     │  db (PostgreSQL 16)  │
                     └──────────────────────┘
                                     ▲ 상태·스냅샷·번역 쓰기
┌──────────────────┐  /translate  ┌────────┐   CISA KEV, cvelistV5,
│ libretranslate   │ ◀─────────── │ worker │ ─ GitHub Advisory, OpenSSF,
│ (en,ko 모델)      │              └────────┘   KISA 보호나라
└──────────────────┘
```

- **web**: FastAPI. `/`에 정적 페이지, `/data/<name>.json`은 DB의 `snapshots` 테이블에서 바로 내려줍니다(gzip·ETag 캐시).
- **worker**: `COLLECT_CRON`마다 수집 → 스냅샷 갱신 → 번역 대기열 정리. 사이사이 번역 대기열을 LibreTranslate로 처리합니다.
- **libretranslate**: 내부망 전용(포트 비공개). 첫 기동 때 en↔ko 모델을 받습니다.

## 빠르게 시작

```bash
cp .env.example .env
# POSTGRES_PASSWORD를 꼭 바꾸세요 (URL에 들어가므로 영문·숫자 권장)
openssl rand -hex 24      # 예시 비밀번호

docker compose up -d --build
docker compose logs -f worker
```

브라우저에서 `http://<서버>:8080` 을 엽니다.

### 첫 기동 때 일어나는 일

1. **seed/** 폴더에 원본 아티팩트의 마지막 데이터가 들어 있습니다. DB가 비어 있으면 worker가 이걸 먼저 넣습니다.
   - seed의 커서가 CVE deltaLog 보관 기간(약 30일) 안이면 **증분 수집**(1~2분)으로 바로 최신화됩니다.
   - 30일이 지났거나 seed를 지우면 **전체 재구축**: 최근 90일치 일별 CVE 압축본을 받아 다시 만듭니다(네트워크에 따라 10~30분, 메모리 1GB 안팎).
   - seed의 한국어 요약(약 400건, 사람이 쓴 문장)은 `seed` 엔진으로 들어가며 기계 번역이 덮어쓰지 않습니다. 전부 LibreTranslate로 바꾸고 싶으면 `ko-reset --seed`.
2. **LibreTranslate**는 모델을 내려받는 동안 응답하지 않습니다. worker는 1분마다 확인하다가 준비되면 번역을 시작합니다.
3. 번역 대기열은 처음에 수천 건(KEV 90일 → 최근 Critical → 제품 업데이트 → 패키지 권고 → 15~90일 Critical 순)입니다. CPU에 따라 첫 소진에 1~3시간 걸릴 수 있고, 그동안 페이지는 영문 원문/한국어 템플릿 문장으로 보입니다. 이후에는 하루 수십~수백 건만 새로 번역합니다.

## 화면 (React)

`app/frontend`에 있는 React(Vite) 앱입니다. `docker compose up --build` 때 Dockerfile 첫 단계에서 빌드되어 web 컨테이너의 `/app/static`으로 들어가므로 따로 할 일은 없습니다.

```bash
# 화면만 고치며 개발할 때 (서버는 이미 떠 있는 web을 씀)
cd app/frontend
npm install
KCN_API=http://localhost:8080 npm run dev     # http://localhost:5173
```

## KNVD RSS (보안공지·공개 취약점)

worker가 `RSS_INTERVAL_MIN`(기본 30분)마다 아래 피드를 읽습니다.

- 보안공지: https://knvd.krcert.or.kr/rss/security/notice
- 공개 취약점: https://knvd.krcert.or.kr/rss/security/info

피드에는 최신 10건 정도만 나오기 때문에, 읽은 글은 모두 `rss_items` 테이블에 쌓고 지우지 않습니다. 화면의 **KNVD** 탭은 최근 180일을 바로 보여 주고, 더 오래된 글은 "이전 기록 더 불러오기"로 DB에서 가져옵니다(`/api/rss`).

- 다른 사이트의 RSS/Atom도 `RSS_FEEDS`에 `이름|표시 이름|URL`을 `;`로 이어 붙이면 같이 쌓입니다.
- 글이 영어면(본문 대부분이 영문) 제목과 본문 앞부분을 LibreTranslate 번역 대기열에 넣고, 번역이 끝나면 화면에 한국어로 보여 줍니다("기계 번역" 표시, 원문은 마우스를 올리거나 본문에서 확인). KEV·CVE 등 다른 출처의 영어 설명도 원래대로 번역됩니다.
- KNVD 글의 CVE가 KEV에 있으면 "실제 악용" 배지가 붙고, "오늘" 화면의 주간 타임라인과 AI 요약 입력에도 들어갑니다.

```bash
docker compose exec worker python -m radar rss      # 지금 바로 한 번 읽기
curl -s "http://localhost:8080/api/rss?feed=knvd-vuln&q=지니언스" | jq '.items[].title'
```

## 오늘의 AI 요약 (ChatGPT)

`.env`에 `OPENAI_API_KEY`를 넣으면 매일 **오전 7시, 낮 12시, 저녁 7시**(`SUMMARY_CRON`)에 요약을 쓰고, "오늘" 화면에 최신 요약 카드가 생깁니다. 요약 시각에 데이터가 `SUMMARY_FRESH_HOURS`(기본 3시간)보다 오래됐으면 먼저 증분 수집을 돌립니다.

- 쓴 요약은 모두 `summary_history` 테이블에 남고, 화면의 **AI 요약 기록** 탭에서 날짜·시각별로 볼 수 있습니다(`/api/summaries`).

- OpenAI Chat Completions API(`https://api.openai.com/v1/chat/completions`)를 쓰고, 기본 모델은 `gpt-5-mini`(`OPENAI_MODEL`)입니다. 응답은 `response_format: json_object`로 받습니다.
- 추론 모델은 `OPENAI_REASONING_EFFORT`(`minimal`/`low`/`medium`/`high`, 기본 `low`)로 추론 양을 조절합니다. 추론 토큰도 `SUMMARY_MAX_TOKENS`(기본 8000, `max_completion_tokens`)에 포함됩니다. `gpt-4o`·`gpt-4.1`처럼 추론하지 않는 모델이면 `OPENAI_REASONING_EFFORT=`(비움)로 두세요.
- OpenAI 호환 엔드포인트(Azure 프록시, vLLM 등)도 `OPENAI_BASE_URL`만 바꾸면 됩니다.

### 지금 바로 요약 쓰기 (`POST /api/summarize`)

예약 시각을 기다리지 않고 요청으로 요약을 쓰게 할 수 있습니다. 서버 `.env`에는 **Ed25519 개인키**를 두고, 요청에는 그 **공개키**를 보냅니다. 서버가 개인키에서 공개키를 계산해 보낸 값과 같을 때만 ChatGPT를 부릅니다.

**1) 키 쌍 만들기 — 내 PC에서** (서버·컨테이너 안에서 실행할 필요 없음, OpenSSL만 있으면 됨)

```bash
sh scripts/summary-keygen.sh
# SUMMARY_PRIVATE_KEY=Wm3k...=   ← PaaS 환경변수에 넣을 값 (한 줄짜리 base64)
# public_key=gwQ2...=            ← 호출하는 쪽에 보관
```

OpenSSL로 직접 만들어도 같습니다(Windows는 Git Bash에서):

```bash
openssl genpkey -algorithm ed25519 -out summary.pem
openssl pkey -in summary.pem -outform DER | tail -c 32 | base64          # SUMMARY_PRIVATE_KEY
openssl pkey -in summary.pem -pubout -outform DER | tail -c 32 | base64  # public_key
rm summary.pem
```

`SUMMARY_PRIVATE_KEY`에는 PEM(`-----BEGIN PRIVATE KEY-----...`)을 그대로 넣어도 되고, 환경변수 칸이 한 줄만 받으면 줄바꿈을 `\n`으로 바꿔 넣어도 됩니다. 컨테이너에 접속할 수 있으면 `python -m radar keygen`으로 만들어도 됩니다.

**2) 서버 환경변수**에 `SUMMARY_PRIVATE_KEY`와 `OPENAI_API_KEY`를 넣고 재배포합니다. 공개키는 서버에 넣지 않습니다(개인키에서 계산함).

**3) 호출** (base64 공개키 또는 PEM 공개키 모두 됨; 헤더 `X-Public-Key`로 보내도 됨)

```bash
curl -s -X POST https://<서비스 주소>/api/summarize \
  -H 'Content-Type: application/json' \
  -d '{"public_key":"<공개키>"}'
```

| 응답 | 뜻 |
|---|---|
| `200` `{"ok":true,"points":4,"headline":"..."}` | 요약 저장 완료 (화면·기록에 바로 반영) |
| `401` | 공개키 불일치 |
| `409` | 이미 요약을 쓰는 중 |
| `502` `{"failed":"..."}` | OpenAI 호출 실패 (이전 요약은 그대로 남음) |
| `503` | `SUMMARY_PRIVATE_KEY` 또는 `OPENAI_API_KEY` 미설정 |

- 요약은 요청을 받은 web 컨테이너가 바로 쓰고(수십 초~1분 걸릴 수 있음), 그 시점에 DB에 있는 데이터를 씁니다. 수집을 먼저 돌리지는 않습니다.
- 공개키는 이 엔드포인트의 **호출 권한** 역할을 합니다. 아는 사람은 누구나 요약(=OpenAI 과금)을 일으킬 수 있으니 공개 저장소·프런트엔드 코드에 넣지 마세요. 새 키 쌍을 만들어 `.env`만 바꾸면 이전 공개키는 바로 무효가 됩니다.
- 모델에는 최근 2일치 수집 결과(새 KEV, 악용 새로 확인, 원격·무인증 + PoC Critical, 주요 벤더 업데이트, KISA 권고)만 보냅니다. 모델이 입력에 없던 CVE 번호를 쓰면 화면에 나오기 전에 지웁니다.
- 실패하면 이전 요약이 그대로 남고, 카드에 작성 날짜가 함께 보입니다. 실패 사유는 `radar status` 또는 `/api/status`에서 확인합니다.
- 키가 없으면 요약 카드만 안 보이고 나머지 기능은 그대로입니다.

```bash
# 모델에 보낼 입력만 미리 보기
docker compose exec worker python -m radar summarize --dry-run
# 지금 바로 다시 생성
docker compose exec worker python -m radar summarize --force
```

## 운영 명령

```bash
# 지금 바로 수집 (증분)
docker compose exec worker python -m radar collect
# 전체 재구축
docker compose exec worker python -m radar collect --full
# 번역 대기열 한 번에 다 처리 / 실패 건 재시도
docker compose exec worker python -m radar translate --all
docker compose exec worker python -m radar translate --retry-failed --all
# 최근 실행 기록과 번역 현황
docker compose exec worker python -m radar status
curl -s http://localhost:8080/api/status | jq

# 기계 번역이 어색한 항목을 직접 고치기 (이후 수집·번역이 덮어쓰지 않음)
docker compose exec worker python -m radar ko-set CVE-2026-12345 "로그인 없이 원격 코드 실행이 가능한 취약점"
# 다시 기계 번역에 맡기기
docker compose exec worker python -m radar ko-reset CVE-2026-12345
# seed의 사람이 쓴 요약을 모두 기계 번역으로 교체
docker compose exec worker python -m radar ko-reset --seed
```

같은 수집이 겹치지 않도록 PostgreSQL advisory lock을 씁니다. 수동 `collect`가 예약 수집과 겹치면 뒤에 온 쪽이 "이미 실행 중"으로 끝납니다.

## 설정 (.env)

| 변수 | 기본값 | 설명 |
|---|---|---|
| `COLLECT_CRON` | `40 8 * * *` | 수집 일정, `TZ` 기준. 증분이라 가벼우니 `40 */6 * * *`(6시간마다)도 괜찮습니다 |
| `COLLECT_ON_START` | `false` | worker 재시작 때마다 바로 한 번 수집 |
| `WEB_BIND` / `WEB_PORT` | `0.0.0.0` / `8080` | 리버스 프록시 뒤라면 `127.0.0.1` |
| `KISA_ENABLED` / `KISA_PAGES` | `true` / `3` | 보호나라 목록 몇 페이지(페이지당 10건)를 읽을지 |
| `LT_IMAGE` | `libretranslate/libretranslate:latest` | 버전 고정하려면 `libretranslate/libretranslate:v1.9.6` 같은 태그로 |
| `LT_THREADS` | `4` | LibreTranslate 번역 스레드 |
| `LT_BATCH` / `LT_CONCURRENCY` | `8` / `2` | 한 요청에 묶는 문장 수 / 동시 요청 수 |
| `LT_API_KEY` | 빈 값 | LibreTranslate에 API 키를 켰을 때만 |
| `TRANSLATE_ARCHIVE` | `true` | 15~90일 지난 Critical까지 번역 (끄면 대기열이 약 절반) |
| `TRANSLATE_PACKAGES` | `true` | GitHub 패키지 권고 요약 번역 |
| `RSS_FEEDS` | KNVD 보안공지·공개 취약점 | `이름\|표시 이름\|URL` 을 `;`로 구분 |
| `RSS_INTERVAL_MIN` | `30` | RSS 읽는 간격(분) |
| `SUMMARY_CRON` | `0 7,12,19 * * *` | AI 요약 시각, `TZ` 기준 |
| `OPENAI_MODEL` / `OPENAI_REASONING_EFFORT` | `gpt-5-mini` / `low` | 요약 모델과 추론 양 |
| `SUMMARY_PRIVATE_KEY` | 빈 값 | `POST /api/summarize` 인증용 Ed25519 개인키 |

## 리버스 프록시 예시 (Caddy)

```caddyfile
radar.example.com {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8080
}
```

`/data/*.json`은 이미 gzip으로 내려가므로 프록시에서 다시 압축하지 않아도 됩니다.

## DB 테이블

| 테이블 | 내용 |
|---|---|
| `snapshots` | 브라우저가 읽는 JSON (meta, kev, critical, archive, updates, packages, kisa, changes, insights, ko) |
| `cve_store` | 90일 보관 CVE (9.0 이상, 주요 벤더는 7.0 이상) |
| `kev_cache` | KEV CVE 보강 정보 캐시 |
| `kisa_notices` | KISA 공지 90일 |
| `change_days` | 실행 간 변화(PoC 공개, 실제 악용 전환 등) 14일 |
| `translations` | 한국어 문장. `engine` = libretranslate / manual / seed, `status` = pending / done / failed |
| `runs` | 수집 실행 기록 (최근 500건) |
| `kv_state` | RSS 피드별 마지막 수집 상태 |
| `rss_items` | KNVD 등 RSS 글 전체 (지우지 않음) |
| `summary_history` | ChatGPT 요약 전체 (지우지 않음) |
| `cve_history` / `kisa_history` | 지금까지 수집한 CVE·KISA 공지 전체 (`cve_store`·`kisa_notices`는 90일만 유지) |

백업은 `docker compose exec db pg_dump -U radar radar > radar.sql` 하나면 됩니다. 사라져도 전체 재구축으로 다시 만들 수 있고, 잃는 건 `ko-set`으로 직접 고친 문장뿐입니다.

## 나가는 네트워크

worker가 접속하는 곳: `raw.githubusercontent.com`, `github.com`(cvelistV5 릴리스 zip, advisory-database·malicious-packages git), `www.boho.or.kr`, `knvd.krcert.or.kr`(RSS), OpenAI API(`api.openai.com`, web 컨테이너도 `POST /api/summarize` 때 접속).
LibreTranslate는 첫 기동 때 모델 저장소(argos-net.com 등)에서 모델을 받습니다.
브라우저는 Google Fonts를 불러옵니다(막혀 있으면 시스템 글꼴로 표시).

## 참고

- 한국어 문장은 기계 번역이라 어색할 수 있습니다. 판단은 원문과 벤더 공지로 하세요.
- "확인함" 표시는 각 브라우저의 localStorage에 저장됩니다(서버에 올라가지 않음). 이전 화면에서 체크한 것은 그대로 옮겨집니다.
- 원본 페이지 하단의 제작자 표기(GitHub · cpprhtn)는 그대로 두었습니다. 공개 서비스로 올린다면 원작자에게 한 번 알리는 것을 권합니다.
