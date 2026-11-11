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

# Daily summary by EXAONE (OpenAI-compatible endpoint; default FriendliAI serverless)
EXAONE_API_KEY = os.environ.get("EXAONE_API_KEY", "")
EXAONE_BASE_URL = os.environ.get("EXAONE_BASE_URL", "https://api.friendli.ai/serverless/v1")
EXAONE_MODEL = os.environ.get("EXAONE_MODEL", "LGAI-EXAONE/K-EXAONE-236B-A23B")
EXAONE_THINKING = _bool("EXAONE_THINKING", False)
SUMMARY_ENABLED = _bool("SUMMARY_ENABLED", True)
SUMMARY_MAX_TOKENS = _int("SUMMARY_MAX_TOKENS", 1500)
SUMMARY_TIMEOUT = _int("SUMMARY_TIMEOUT", 180)

# KISA (boho.or.kr) list pages to read each run (10 posts per page)
KISA_PAGES = max(1, _int("KISA_PAGES", 3))
KISA_ENABLED = _bool("KISA_ENABLED", True)

# web
WEB_HOST = os.environ.get("WEB_HOST", "0.0.0.0")
WEB_PORT = _int("WEB_PORT", 8080)
STATIC_DIR = os.environ.get("STATIC_DIR", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static"))

USER_AGENT = os.environ.get(
    "HTTP_USER_AGENT",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36 vuln-radar/1.0",
)
