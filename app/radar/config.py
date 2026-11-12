"""Runtime settings, all read from environment variables."""
import os


def _int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _bool(name, default):
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://radar:radar@db:5432/radar")

# scheduler
TZ = os.environ.get("TZ", "Asia/Seoul")
COLLECT_CRON = os.environ.get("COLLECT_CRON", "40 8 * * *")          # in TZ
COLLECT_ON_START = _bool("COLLECT_ON_START", False)                 # run once right after the worker starts
TRANSLATE_INTERVAL_MIN = _int("TRANSLATE_INTERVAL_MIN", 10)
SEED_DIR = os.environ.get("SEED_DIR", "/seed")
WORK_DIR = os.environ.get("WORK_DIR", "/tmp/radar-work")

# LibreTranslate
LT_URL = os.environ.get("LT_URL", "http://libretranslate:5000").rstrip("/")
LT_API_KEY = os.environ.get("LT_API_KEY", "")
LT_SOURCE = os.environ.get("LT_SOURCE", "en")
LT_TARGET = os.environ.get("LT_TARGET", "ko")
LT_BATCH = max(1, _int("LT_BATCH", 8))
LT_CONCURRENCY = max(1, _int("LT_CONCURRENCY", 2))
LT_TIMEOUT = _int("LT_TIMEOUT", 180)
TRANSLATE_CHUNK = max(10, _int("TRANSLATE_CHUNK", 200))            # items per scheduler slice
TRANSLATE_MAX_CHARS = _int("TRANSLATE_MAX_CHARS", 420)
TRANSLATE_ARCHIVE = _bool("TRANSLATE_ARCHIVE", True)                # 15-90 day Critical too
TRANSLATE_PACKAGES = _bool("TRANSLATE_PACKAGES", True)              # GitHub advisory summaries

# Daily summary by ChatGPT (OpenAI Chat Completions API)
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-5-mini")
# reasoning models (gpt-5 family, o-series): minimal|low|medium|high. Empty = not sent (e.g. gpt-4o / gpt-4.1).
OPENAI_REASONING_EFFORT = os.environ.get("OPENAI_REASONING_EFFORT", "low").strip().lower()
# only sent when set; reasoning models accept the default only
OPENAI_TEMPERATURE = os.environ.get("OPENAI_TEMPERATURE", "").strip()
# Ed25519 private key (base64 raw 32 bytes or PEM). POST /api/summarize runs a briefing only when the
# public key in the request matches this one. Empty = the endpoint is off. Make a pair: python -m radar keygen
SUMMARY_PRIVATE_KEY = os.environ.get("SUMMARY_PRIVATE_KEY", "").strip()
SUMMARY_ENABLED = _bool("SUMMARY_ENABLED", True)
SUMMARY_MAX_TOKENS = _int("SUMMARY_MAX_TOKENS", 8000)   # max_completion_tokens, includes reasoning tokens
SUMMARY_TIMEOUT = _int("SUMMARY_TIMEOUT", 300)
SUMMARY_CRON = os.environ.get("SUMMARY_CRON", "0 7,12,19 * * *")    # in TZ: 07:00, 12:00, 19:00
SUMMARY_FRESH_HOURS = _int("SUMMARY_FRESH_HOURS", 3)               # collect first when data is older than this

# KISA (boho.or.kr) list pages to read each run (10 posts per page)
KISA_PAGES = max(1, _int("KISA_PAGES", 3))
KISA_ENABLED = _bool("KISA_ENABLED", True)

# RSS/Atom feeds: "name|표시 이름|url" separated by ';'. Entries are kept forever in rss_items.
RSS_FEEDS = os.environ.get(
    "RSS_FEEDS",
    "knvd-notice|KNVD 보안공지|https://knvd.krcert.or.kr/rss/security/notice;"
    "knvd-vuln|KNVD 공개 취약점|https://knvd.krcert.or.kr/rss/security/info",
)
RSS_ENABLED = _bool("RSS_ENABLED", True)
RSS_INTERVAL_MIN = max(5, _int("RSS_INTERVAL_MIN", 30))
RSS_SNAPSHOT_DAYS = max(7, _int("RSS_SNAPSHOT_DAYS", 180))      # what the page loads up front; older via /api/rss
RSS_SNAPSHOT_MAX = max(50, _int("RSS_SNAPSHOT_MAX", 600))       # per feed
RSS_BODY_MAX = max(1000, _int("RSS_BODY_MAX", 20000))

# web
WEB_HOST = os.environ.get("WEB_HOST", "0.0.0.0")
WEB_PORT = _int("WEB_PORT", 8080)
STATIC_DIR = os.environ.get("STATIC_DIR", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static"))

USER_AGENT = os.environ.get(
    "HTTP_USER_AGENT",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36 KCN/1.0",
)
