# 스케줄 정보
- 이름: 취약점 레이더 매일 갱신
- cron: CRON_TZ=Asia/Seoul 40 8 * * *  (매일 08:40 KST)
- 1회성 추가 갱신(11/11 13:20 KST)은 일회성이므로 이전 불필요.

# 서버 이전 시 참고
- collector.py: `python3 collector.py --state state --out out [--kisa kisa.json]` 로 실행. out/data/*.json 이 site/data/ 로 가면 됨 (state/ 는 이전 실행 결과 = 증분 수집용).
- KISA 목록(boho.or.kr)은 LLM(WebFetch) 으로 JSON 변환해 --kisa 로 넘겼음. 직접 크롤링 스크립트로 대체 필요.
- 한국어 요약은 out/ko_todo.json 항목을 LLM 이 작성 -> ko_new.json -> `collector.py --out out --merge-ko ko_new.json`. LLM 없이 돌리면 이 단계는 생략 가능(요약만 비어 있음).
- collector.py sha256: 4222c4097646aacdf172bbb80edf9280f996dfc2424aa01d917df41f6445e066
- 아래는 스케줄에 걸려 있는 원본 프롬프트(참고용).

## 일일 갱신 프롬프트 (요약 원문)
1. 작업 폴더 RUN 생성
2. 현재 게시본 확인, 이전 상태(data/meta,store,kevcache,kisa,ko,changes,packages.json)와 collector.py 다운로드 -> RUN/state
3. collector.py sha256 검증 (위 해시와 불일치 시 중단)
4. KISA 보호나라 목록(https://www.boho.or.kr/kr/bbs/list.do?menuNo=205020&bbsId=B0000133) -> [{"title","date","url"}] JSON 배열로 RUN/kisa.json 저장 (실패 시 --kisa 생략)
5. python3 -I RUN/state/collector.py --state RUN/state/data --out RUN/out --kisa RUN/kisa.json  (20분 타임아웃, 증분 약 1분 / 전체 재구축 수 분)
6. RUN/out/ko_todo.json 항목(kind: kev/critical/update)마다 한국어 요약 1개(50~150자) 작성 -> RUN/ko_new.json {"id":"요약"} -> collector.py --out RUN/out --merge-ko RUN/ko_new.json
   스타일: ~습니다/~하세요 체, 번역투 금지("~에 의해", "임의의", "해당 취약점은" 등), "인증 없이/원격에서/실제 공격에 쓰였습니다/공격 코드가 공개됐습니다/침해 흔적도 점검하세요" 사용.
   구조: 공격자가 할 수 있는 것 -> 영향 범위/심각도 -> 조치. 상태: exploitation이 active(KEV)/kev 있음=실제 공격, poc/exploited 있음=공격 코드 공개, forensicTriage=침해 흔적 점검.
   조치: fix 중 "lt" 값만 버전으로 언급("X 이상으로 올리세요"), 없으면 "벤더 공지대로 업데이트하세요", 공유기/어플라이언스는 "관리 페이지 외부 노출부터 막으세요". count>50 이면 건수·원격 무인증 건수·악용 건수 + 조치 한 줄. 없는 사실 지어내기 금지.
7. out/data/*.json 12개 파일을 사이트의 data/ 로 게시 (app.js, app.css, index.html 은 그대로)
8. 결과 보고(모드, 확인 레코드 수, KEV 7일 신규, CVSS 9+ 신규/hot, 업데이트 묶음 수, KISA 상태, 패키지 탭 수치, 요약 작성 수, 실패, 게시 성공 여부)
