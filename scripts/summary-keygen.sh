#!/bin/sh
# POST /api/summarize 용 Ed25519 키 쌍을 내 PC에서 만듭니다 (OpenSSL 1.1.1 이상만 있으면 됨, 서버 불필요).
#   sh scripts/summary-keygen.sh
# 출력된 SUMMARY_PRIVATE_KEY 값은 PaaS 환경변수에, public_key 값은 호출하는 쪽에 보관하세요.
set -eu
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
openssl genpkey -algorithm ed25519 -out "$tmp" 2>/dev/null
priv=$(openssl pkey -in "$tmp" -outform DER | tail -c 32 | base64 | tr -d '\n')
pub=$(openssl pkey -in "$tmp" -pubout -outform DER | tail -c 32 | base64 | tr -d '\n')
echo "# 서버(PaaS) 환경변수 — 남에게 보여 주지 마세요"
echo "SUMMARY_PRIVATE_KEY=$priv"
echo
echo "# POST /api/summarize 에 보낼 공개키"
echo "public_key=$pub"
