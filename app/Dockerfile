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
COPY static ./static
RUN mkdir -p /tmp/radar-work && chown radar:radar /tmp/radar-work

USER radar
EXPOSE 8080
CMD ["python", "-m", "radar", "web"]
