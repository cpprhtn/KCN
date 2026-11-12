# ---- 1) React 화면 빌드 (app/frontend -> dist)
FROM node:22-alpine AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- 2) Python 서버 (FastAPI web + worker)
FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# git: GitHub Advisory DB / OpenSSF malicious-packages are read with sparse/shallow clones
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 radar \
 && useradd --system --uid 10001 --gid radar --home-dir /app --shell /usr/sbin/nologin radar

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY radar ./radar
COPY --from=web /web/dist ./static
RUN mkdir -p /tmp/radar-work && chown radar:radar /tmp/radar-work

USER radar
EXPOSE 8080
CMD ["python", "-m", "radar", "web"]
