import os
import re
import sys
import json
import time
import signal
import random
import hashlib
import threading
import urllib.robotparser
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse
from collections import deque, defaultdict

import requests
import trafilatura
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import orjson
except ImportError:
    orjson = None

# =========================
# CONFIG
# =========================
OUTPUT_FILE = "cyber_wide_data.jsonl"
STATE_FILE = "crawler_state.json"
RUNTIME_CONFIG_FILE = "crawler_runtime_config.json"
SEEDS_FILE = "seeds.txt"

USER_AGENT = "CyberWideCrawler/1.0 (public research crawler; +https://github.com/100-Academics/OSIRIS)"
REQUEST_TIMEOUT = 20
MAX_RETRIES = 3
MAX_PAGES_TOTAL = 200000
MAX_QUEUE_SIZE = 120000
CRAWLER_THREADS = 16
CONNECTION_POOL_SIZE = 200

AUTOSAVE_SECONDS = 20
FLUSH_EVERY_N_RECORDS = 100
SAVE_STATE_EVERY_N_PAGES = 250
SLEEP_RANGE_SECONDS = (0.02, 0.08)
OUTPUT_FSYNC_EVERY_N_FLUSHES = 20
STATE_REPLACE_RETRIES_FAST = 8
STATE_REPLACE_RETRY_SECONDS_FAST = 0.05
STATE_REPLACE_RETRIES_SYNC = 80
STATE_REPLACE_RETRY_SECONDS_SYNC = 0.1
STATE_WARNING_THROTTLE_SECONDS = 5.0

# Environment overrides for runtime tuning
ENV_THREADS = "OSIRIS_THREADS"
ENV_CONN_POOL = "OSIRIS_CONN_POOL"
ENV_SLEEP_MIN_MS = "OSIRIS_SLEEP_MIN_MS"
ENV_SLEEP_MAX_MS = "OSIRIS_SLEEP_MAX_MS"
ENV_RUNTIME_CONFIG = "OSIRIS_RUNTIME_CONFIG_FILE"
ENV_MAX_PAGES_TOTAL = "OSIRIS_MAX_PAGES_TOTAL"
ENV_MAX_QUEUE_SIZE = "OSIRIS_MAX_QUEUE_SIZE"

RUNTIME_SPEED_AUTO = "auto"
RUNTIME_SPEED_MAX = "max"
RUNTIME_SPEED_CUSTOM = "custom"
RUNTIME_SPEED_VALUES = {RUNTIME_SPEED_AUTO, RUNTIME_SPEED_MAX, RUNTIME_SPEED_CUSTOM}

MAX_CONTENT_CHARS = 50000   # full cleaned body text stored in the output
MAX_LINKS_PER_PAGE = 200
MAX_PAGES_PER_DOMAIN = 320
MAX_CONSECUTIVE_LOW_RELEVANCE_PER_DOMAIN = 35
MIN_CONTENT_LENGTH = 200    # skip stub / redirect / error pages

# Code-block extraction limits (for the code_blocks field)
MAX_CODE_BLOCKS = 100
MAX_CODE_BLOCK_CHARS = 200000

ROBOTS_CACHE_TTL = 3600     # seconds to cache robots.txt per domain

# Search engines and major aggregators to exclude (avoid crawling them like a search engine)
BLOCKED_DOMAINS = {
    "google.com", "www.google.com",
    "duckduckgo.com", "www.duckduckgo.com",
    "bing.com", "www.bing.com",
    "search.yahoo.com", "yahoo.com", "www.yahoo.com",
    "yandex.com", "www.yandex.com",
    "baidu.com", "www.baidu.com",
    "ecosia.org", "www.ecosia.org",
}

# Cybersecurity relevance keywords used for scoring
CYBER_KEYWORDS = [
    # CVE / vulnerability basics
    "cve-", "vulnerability", "vulnerabilities", "exploit", "exploited",
    "advisory", "security advisory", "security update", "patch",
    # Malware / threat categories
    "ransomware", "malware", "phishing", "botnet", "threat actor",
    "rootkit", "backdoor", "trojan", "worm", "spyware", "adware", "dropper",
    # Threat intel
    "ioc", "indicator of compromise", "zero-day", "0day", "cvss",
    "apt", "threat intelligence", "ttp", "tactics techniques procedures",
    "incident response", "iocs", "yara", "sigma", "snort",
    # Standards / frameworks
    "cybersecurity", "infosec", "mitre", "nist", "kev",
    "mitre att&ck", "capec", "cwe", "owasp",
    # Web / injection attacks
    "remote code execution", "rce", "privilege escalation", "xss",
    "sql injection", "command injection", "path traversal",
    "directory traversal", "ssrf", "csrf", "xxe", "idor",
    "deserialization", "nosql injection", "ldap injection",
    "open redirect", "template injection", "server-side template",
    # Memory corruption
    "buffer overflow", "heap spray", "use-after-free",
    "memory corruption", "stack overflow", "integer overflow",
    "format string", "type confusion",
    # Network / infrastructure attacks
    "supply chain", "firmware", "lateral movement",
    "c2", "command and control", "network pivot", "pivoting",
    "port scan", "network scan", "nmap",
    # Auth attacks
    "brute force", "credential stuffing", "password spray",
    "authentication bypass", "authorization bypass",
    "token hijacking", "session fixation", "replay attack",
    # Tools / tradecraft
    "shellcode", "payload", "metasploit", "burpsuite", "wireshark",
    "cobalt strike", "empire", "msfvenom", "netcat", "mimikatz",
    "hydra", "hashcat", "john the ripper", "aircrack",
    # Research / education
    "penetration test", "pentest", "red team", "blue team", "purple team",
    "ctf", "capture the flag", "writeup", "proof of concept", "poc",
    "reverse engineering", "binary analysis", "fuzzing", "afl",
    "static analysis", "dynamic analysis", "sandbox",
    # Windows privilege escalation / admin elevation
    "uac bypass", "user account control", "uac",
    "token impersonation", "access token manipulation",
    "seimpersonateprivilege", "sedebugprivilege", "seassignprimarytokenprivilege",
    "printspoofer", "juicy potato", "rogue potato", "sweet potato", "hot potato",
    "runas", "psexec",
    "local privilege escalation", "lpe",
    "dll hijacking", "dll injection", "dll side-loading",
    "process injection", "process hollowing",
    "alwaysinstallelevated", "unquoted service path",
    "weak service permissions", "named pipe impersonation",
    "pass-the-hash", "pass-the-ticket", "overpass-the-hash",
    "kerberoasting", "asreproasting", "golden ticket", "silver ticket",
    "applocker bypass", "amsi bypass", "windows defender bypass",
    "lsass dump", "lsass", "ntlm relay", "ntlm hash",
    "scheduled task abuse", "registry run key", "autorun persistence",
    # Linux sudo / SUID privilege escalation
    "sudo -l", "sudoers", "sudo misconfiguration", "sudo abuse",
    "suid binary", "suid exploitation", "sgid",
    "setuid", "setgid", "capabilities abuse", "cap_setuid",
    "linux privilege escalation", "linux lpe",
    "cron job abuse", "world-writable", "weak file permissions",
    "path hijacking", "ld_preload", "ld_library_path hijack",
    "pkexec", "polkit", "pwnkit",
    "dirtycow", "dirty cow", "dirty pipe",
    "kernel exploit", "kernel module injection",
    "docker escape", "container escape", "namespace escape",
    "nfs no_root_squash", "lxd privilege escalation",
    "/etc/passwd writable", "/etc/shadow", "passwd file",
]

# Pre-compiled patterns — built once at import time for fast repeated matching.
# _KEYWORD_RE uses alternation over every keyword so a single regex pass replaces
# the O(k) loop of individual `in` checks.
_CVE_RE = re.compile(r"\bcve-\d{4}-\d{4,7}\b", re.IGNORECASE)
_KEYWORD_RE = re.compile(
    "|".join(re.escape(kw) for kw in CYBER_KEYWORDS),
    re.IGNORECASE,
)

# Pre-compiled priority-link pattern — avoids rebuilding a list on every call.
_PRIORITY_RE = re.compile(
    r"advisory|security|cve|vuln|vulnerability|exploit|incident|threat|malware|ransomware|patch",
    re.IGNORECASE,
)

# File extensions that are never HTML pages; skip them in extract_links to avoid
# wasting a request slot on binary downloads.
_SKIP_EXTS = frozenset([
    ".pdf", ".zip", ".gz", ".tar", ".exe", ".msi", ".dmg", ".pkg",
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".mp4", ".mp3", ".avi", ".mov", ".wmv", ".flac", ".ogg",
    ".css", ".js", ".xml", ".rss", ".atom", ".json", ".csv",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf",
    ".iso", ".bin", ".rar", ".7z",
])

# Use lxml when available (trafilatura already depends on it) — roughly 3× faster
# than html.parser for large pages; fall back transparently if not installed.
try:
    import lxml  # noqa: F401
    _HTML_PARSER = "lxml"
except ImportError:
    _HTML_PARSER = "html.parser"

# Fallback seeds used only if seeds.txt is missing
DEFAULT_SEEDS = [
    "https://nvd.nist.gov/",
    "https://www.cisa.gov/",
    "https://www.exploit-db.com/",
    "https://www.bleepingcomputer.com/news/security/",
    "https://krebsonsecurity.com/",
    "https://en.wikipedia.org/wiki/Computer_security",
]

# =========================
# GLOBAL STATE
# =========================
stop_event = threading.Event()
save_lock = threading.Lock()
state_warning_lock = threading.Lock()
shutdown_once_lock = threading.Lock()

queue = deque()
queued_set = set()
visited = set()
seen_records = set()

domain_page_count = defaultdict(int)
domain_lowrel_streak = defaultdict(int)

records_buffer = []
pages_processed = 0
rows_saved = 0
flush_count = 0

shutdown_started = False
final_state_saved = False
last_state_warning = {"message": "", "at": 0.0}

# robots.txt: domain -> (RobotFileParser, expiry_timestamp)
robots_cache: dict = {}
robots_lock = threading.Lock()
robots_inflight: dict = {}

# Per-thread HTTP session so workers reuse keep-alive connections safely.
thread_local = threading.local()


# =========================
# HELPERS
# =========================
def _clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))


def _env_int(name: str, default: int, low: int = 1, high: int = 1_000_000_000) -> int:
    try:
        raw = os.getenv(name)
        if raw is None or raw == "":
            return default
        return _clamp(int(raw), low, high)
    except (TypeError, ValueError):
        return default


def _log_state_warning(message: str):
    now = time.time()
    with state_warning_lock:
        same_message = message == last_state_warning["message"]
        if same_message and (now - last_state_warning["at"]) < STATE_WARNING_THROTTLE_SECONDS:
            return
        last_state_warning["message"] = message
        last_state_warning["at"] = now
    print(message, file=sys.stderr)


def runtime_config_path() -> str:
    return os.getenv(ENV_RUNTIME_CONFIG, RUNTIME_CONFIG_FILE)


def _default_runtime_config() -> dict:
    return {
        "version": 1,
        "speed_profile": RUNTIME_SPEED_AUTO,
        "custom": {
            "threads": None,
            "connection_pool": None,
            "sleep_min_ms": None,
            "sleep_max_ms": None,
        },
        "created_at": now_iso(),
    }


def _validate_runtime_config(raw: dict) -> dict:
    cfg = _default_runtime_config()
    if not isinstance(raw, dict):
        return cfg

    profile = str(raw.get("speed_profile", RUNTIME_SPEED_AUTO)).strip().lower()
    if profile not in RUNTIME_SPEED_VALUES:
        profile = RUNTIME_SPEED_AUTO
    cfg["speed_profile"] = profile

    custom = raw.get("custom") if isinstance(raw.get("custom"), dict) else {}
    out_custom = cfg["custom"]
    for key in ("threads", "connection_pool"):
        val = custom.get(key)
        if isinstance(val, int) and val > 0:
            out_custom[key] = val
    for key in ("sleep_min_ms", "sleep_max_ms"):
        val = custom.get(key)
        if isinstance(val, (int, float)) and val >= 0:
            out_custom[key] = float(val)
    return cfg


def load_or_create_runtime_config(path: str = None) -> tuple[dict, bool]:
    cfg_path = path or runtime_config_path()
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                return _validate_runtime_config(json.load(f)), False
        except Exception:
            # If config is corrupted, recreate it with safe defaults.
            pass

    cfg = _default_runtime_config()
    tmp = cfg_path + ".tmp"
    if orjson is not None:
        with open(tmp, "wb") as f:
            f.write(orjson.dumps(cfg, option=orjson.OPT_INDENT_2))
            f.flush()
            os.fsync(f.fileno())
    else:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
    os.replace(tmp, cfg_path)
    return cfg, True


def auto_tune_runtime(runtime_config: dict = None):
    """Tune runtime concurrency knobs for this machine on every start."""
    global CRAWLER_THREADS, CONNECTION_POOL_SIZE, SLEEP_RANGE_SECONDS

    cpu_count = os.cpu_count() or 4
    # This crawler is mostly network-bound, so higher concurrency than CPU count helps.
    tuned_threads = _clamp(cpu_count * 8, 32, 128)
    tuned_pool = _clamp(tuned_threads * 4, 128, 1024)

    if tuned_threads >= 96:
        tuned_sleep = (0.0, 0.004)
    elif tuned_threads >= 64:
        tuned_sleep = (0.0, 0.008)
    else:
        tuned_sleep = (0.002, 0.012)

    cfg = _validate_runtime_config(runtime_config or {})
    profile = cfg["speed_profile"]

    if profile == RUNTIME_SPEED_MAX:
        tuned_threads = _clamp(cpu_count * 16, 64, 256)
        tuned_pool = _clamp(tuned_threads * 4, 256, 2048)
        tuned_sleep = (0.0, 0.001)
    elif profile == RUNTIME_SPEED_CUSTOM:
        custom = cfg["custom"]
        if custom["threads"] is not None:
            tuned_threads = _clamp(int(custom["threads"]), 1, 512)
        if custom["connection_pool"] is not None:
            tuned_pool = _clamp(int(custom["connection_pool"]), 1, 2048)
        if custom["sleep_min_ms"] is not None or custom["sleep_max_ms"] is not None:
            lo = custom["sleep_min_ms"] if custom["sleep_min_ms"] is not None else (tuned_sleep[0] * 1000.0)
            hi = custom["sleep_max_ms"] if custom["sleep_max_ms"] is not None else (tuned_sleep[1] * 1000.0)
            lo = max(0.0, float(lo))
            hi = max(lo, float(hi))
            tuned_sleep = (lo / 1000.0, hi / 1000.0)

    # Optional runtime overrides for operator control without code edits.
    try:
        threads_override = os.getenv(ENV_THREADS)
        if threads_override:
            tuned_threads = _clamp(int(threads_override), 1, 512)
    except ValueError:
        pass

    try:
        pool_override = os.getenv(ENV_CONN_POOL)
        if pool_override:
            tuned_pool = _clamp(int(pool_override), 1, 2048)
    except ValueError:
        pass

    try:
        sleep_min_ms = os.getenv(ENV_SLEEP_MIN_MS)
        sleep_max_ms = os.getenv(ENV_SLEEP_MAX_MS)
        if sleep_min_ms is not None or sleep_max_ms is not None:
            lo = float(sleep_min_ms) if sleep_min_ms is not None else (tuned_sleep[0] * 1000.0)
            hi = float(sleep_max_ms) if sleep_max_ms is not None else (tuned_sleep[1] * 1000.0)
            lo = max(0.0, lo)
            hi = max(lo, hi)
            tuned_sleep = (lo / 1000.0, hi / 1000.0)
    except ValueError:
        pass

    CRAWLER_THREADS = tuned_threads
    CONNECTION_POOL_SIZE = tuned_pool
    SLEEP_RANGE_SECONDS = tuned_sleep


def apply_runtime_page_limit():
    """Allow the total crawl cap to be overridden at startup."""
    global MAX_PAGES_TOTAL
    MAX_PAGES_TOTAL = _env_int(ENV_MAX_PAGES_TOTAL, MAX_PAGES_TOTAL)


def apply_runtime_queue_limit():
    """Allow the in-memory queue cap to be overridden at startup."""
    global MAX_QUEUE_SIZE
    MAX_QUEUE_SIZE = _env_int(ENV_MAX_QUEUE_SIZE, MAX_QUEUE_SIZE)


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def normalize_url(url: str) -> str:
    try:
        p = urlparse(url)
        scheme = p.scheme.lower()
        netloc = p.netloc.lower()
        # Return the original string when the URL is not a valid absolute URL
        # (no scheme or no host) to avoid producing garbage like "://...".
        if not scheme or not netloc:
            return url
        path = p.path or "/"
        query = p.query
        out = f"{scheme}://{netloc}{path}"
        if query:
            out += f"?{query}"
        return out
    except Exception:
        return url


def host(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def is_http(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")


def is_blocked(url: str) -> bool:
    h = host(url)
    if not h:
        return True
    for b in BLOCKED_DOMAINS:
        if h == b or h.endswith("." + b):
            return True
    return False


def setup_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=MAX_RETRIES,
        connect=MAX_RETRIES,
        read=MAX_RETRIES,
        backoff_factor=0.25,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["GET", "HEAD"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=CONNECTION_POOL_SIZE,
        pool_maxsize=CONNECTION_POOL_SIZE,
    )
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({"User-Agent": USER_AGENT})
    return s


def get_thread_session() -> requests.Session:
    s = getattr(thread_local, "session", None)
    if s is None:
        s = setup_session()
        thread_local.session = s
    return s


def relevance_score(title: str, text: str) -> int:
    blob = f"{title} {text}"
    # Each distinct keyword matched counts once; CVE IDs get an extra +2 each.
    score = len({m.lower() for m in _KEYWORD_RE.findall(blob)})
    score += len(_CVE_RE.findall(blob)) * 2
    return score


def extract_cves(title: str, text: str) -> list:
    blob = f"{title} {text}"
    return sorted({m.upper() for m in _CVE_RE.findall(blob)})


def extract_code_blocks(soup: BeautifulSoup) -> list:
    """Return a deduplicated list of code snippets from <pre> and <code> tags."""
    blocks = []
    seen_hashes: set = set()
    for tag in soup.find_all(["pre", "code"]):
        code = tag.get_text(" ", strip=True)
        code = re.sub(r"\s+", " ", code).strip()
        if len(code) < 10:
            continue
        # Deduplicate — nested <pre><code> pairs produce the same text twice
        h = hashlib.sha256(code[:200].encode("utf-8", errors="ignore")).hexdigest()
        if h in seen_hashes:
            continue
        seen_hashes.add(h)
        if len(code) > MAX_CODE_BLOCK_CHARS:
            code = code[:MAX_CODE_BLOCK_CHARS]
        blocks.append(code)
        if len(blocks) >= MAX_CODE_BLOCKS:
            break
    return blocks


def extract_text_and_title(html: str, url: str = ""):
    soup = BeautifulSoup(html, _HTML_PARSER)
    for t in soup(["script", "style", "noscript", "svg"]):
        t.decompose()

    title = ""
    if soup.title and soup.title.string:
        title = soup.title.string.strip()
    else:
        h1 = soup.find("h1")
        if h1:
            title = h1.get_text(" ", strip=True)

    # Extract code blocks before trafilatura drops them
    code_blocks = extract_code_blocks(soup)

    # trafilatura extracts the main article body, stripping nav/sidebar/footer/ads.
    # This produces far cleaner text for ML training than soup.get_text().
    text = trafilatura.extract(
        html,
        url=url or None,
        include_comments=False,
        include_tables=True,
        no_fallback=False,
        favor_precision=False,
    )
    if not text:
        # Fallback: use BeautifulSoup full-page text
        text = soup.get_text(" ", strip=True)

    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > MAX_CONTENT_CHARS:
        text = text[:MAX_CONTENT_CHARS]

    return soup, title, text, code_blocks


def robots_allowed(session: requests.Session, url: str) -> bool:
    """Return True if USER_AGENT is permitted to fetch *url* per the site's robots.txt."""
    parsed = urlparse(url)
    h = parsed.netloc.lower()
    robots_url = f"{parsed.scheme}://{h}/robots.txt"

    now = time.time()
    do_fetch = False
    waiter = None

    # Fast path: return cached result without doing any I/O.
    with robots_lock:
        entry = robots_cache.get(h)
        if entry and now < entry[1]:
            return entry[0].can_fetch(USER_AGENT, url)

        waiter = robots_inflight.get(h)
        if waiter is None:
            waiter = threading.Event()
            robots_inflight[h] = waiter
            do_fetch = True

    if not do_fetch:
        # Another thread is fetching this domain's robots.txt right now.
        waiter.wait(timeout=3)
        with robots_lock:
            entry = robots_cache.get(h)
            if entry and time.time() < entry[1]:
                return entry[0].can_fetch(USER_AGENT, url)
        return True

    # Cache miss — fetch robots.txt *outside* the lock so other threads are not blocked.
    rp = urllib.robotparser.RobotFileParser()
    rp.set_url(robots_url)
    try:
        resp = session.get(robots_url, timeout=10, allow_redirects=True)
        if resp.status_code == 200:
            rp.parse(resp.text.splitlines())
        # 404 / other -> treat as no restrictions (rp stays unparsed -> can_fetch returns True)
    except Exception:
        pass

    with robots_lock:
        # Another call may have populated the cache while we were fetching; keep the
        # fresher entry to avoid redundant re-fetches.
        entry = robots_cache.get(h)
        if not entry or now >= entry[1]:
            robots_cache[h] = (rp, time.time() + ROBOTS_CACHE_TTL)
        else:
            rp = entry[0]
        in_flight = robots_inflight.pop(h, None)
        if in_flight is not None:
            in_flight.set()

    return rp.can_fetch(USER_AGENT, url)


def enqueue(url: str, priority=False):
    if len(queue) >= MAX_QUEUE_SIZE:
        return
    u = normalize_url(url)
    if not is_http(u):
        return
    if is_blocked(u):
        return
    if u in visited or u in queued_set:
        return

    h = host(u)
    if domain_page_count[h] >= MAX_PAGES_PER_DOMAIN:
        return
    if domain_lowrel_streak[h] >= MAX_CONSECUTIVE_LOW_RELEVANCE_PER_DOMAIN:
        return

    if priority:
        queue.appendleft(u)
    else:
        queue.append(u)
    queued_set.add(u)


def extract_links(base_url: str, soup: BeautifulSoup):
    links = []
    for a in soup.find_all("a", href=True):
        href = (a.get("href") or "").strip()
        if not href:
            continue
        if href.startswith(("javascript:", "mailto:", "tel:")):
            continue
        full = normalize_url(urljoin(base_url, href))
        if not is_http(full):
            continue
        # Skip binary / non-HTML resources to avoid wasting request slots
        ext = os.path.splitext(urlparse(full).path)[1].lower()
        if ext in _SKIP_EXTS:
            continue
        links.append(full)
        if len(links) >= MAX_LINKS_PER_PAGE:
            break
    return links


def flush_records():
    global records_buffer, rows_saved, flush_count
    with save_lock:
        if not records_buffer:
            return
        # Swap buffer atomically so new appends go to a fresh list while we write the old one
        to_write = records_buffer
        records_buffer = []
        rows_saved += len(to_write)
        flush_count += 1
        should_fsync = (flush_count % OUTPUT_FSYNC_EVERY_N_FLUSHES) == 0
    if orjson is not None:
        payload = b"".join(orjson.dumps(r) + b"\n" for r in to_write)
        with open(OUTPUT_FILE, "ab") as f:
            f.write(payload)
            f.flush()
            if should_fsync:
                os.fsync(f.fileno())
    else:
        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            f.write("\n".join(json.dumps(r, ensure_ascii=False) for r in to_write) + "\n")
            f.flush()
            if should_fsync:
                os.fsync(f.fileno())


def save_state(sync: bool = True) -> bool:
    if stop_event.is_set() and not sync:
        return False

    with save_lock:
        state = {
            "queue": list(queue),
            "queued_set": list(queued_set),
            "visited": list(visited),
            "seen_records": list(seen_records),
            "domain_page_count": dict(domain_page_count),
            "domain_lowrel_streak": dict(domain_lowrel_streak),
            "pages_processed": pages_processed,
            "rows_saved": rows_saved,
            "timestamp": now_iso(),
        }
        tmp = STATE_FILE + ".tmp"
        if orjson is not None:
            with open(tmp, "wb") as f:
                f.write(orjson.dumps(state))
                if sync:
                    f.flush()
                    os.fsync(f.fileno())
        else:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(state, f)
                if sync:
                    f.flush()
                    os.fsync(f.fileno())

        retries = STATE_REPLACE_RETRIES_SYNC if sync else STATE_REPLACE_RETRIES_FAST
        retry_seconds = STATE_REPLACE_RETRY_SECONDS_SYNC if sync else STATE_REPLACE_RETRY_SECONDS_FAST

        for attempt in range(retries + 1):
            try:
                os.replace(tmp, STATE_FILE)
                return True
            except PermissionError as exc:
                # Windows can transiently lock files (AV/indexing/backup); retry briefly.
                if attempt >= retries:
                    _log_state_warning(
                        f"[state] warning: failed to replace {tmp} -> {STATE_FILE}: {exc}"
                    )
                    return False
                time.sleep(retry_seconds)
            except Exception as exc:
                _log_state_warning(
                    f"[state] warning: failed to save state {STATE_FILE}: {exc}"
                )
                return False


def load_state():
    global pages_processed, rows_saved
    candidates = [STATE_FILE, STATE_FILE + ".tmp"]
    valid_states = []

    for path in candidates:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                state = json.load(f)

            ts = state.get("timestamp")
            ts_epoch = 0.0
            if isinstance(ts, str):
                try:
                    ts_epoch = datetime.fromisoformat(ts).timestamp()
                except Exception:
                    ts_epoch = 0.0
            mtime = os.path.getmtime(path)
            valid_states.append((ts_epoch, mtime, path, state))
        except Exception:
            continue

    if not valid_states:
        return False

    # Prefer freshest valid state; if equal, prefer main STATE_FILE for determinism.
    valid_states.sort(key=lambda x: (x[0], x[1], 1 if x[2] == STATE_FILE else 0), reverse=True)
    _, _, loaded_from, state = valid_states[0]

    queue.extend(state.get("queue", []))
    queued_set.update(state.get("queued_set", []))
    visited.update(state.get("visited", []))
    seen_records.update(state.get("seen_records", []))

    for k, v in state.get("domain_page_count", {}).items():
        domain_page_count[k] = v
    for k, v in state.get("domain_lowrel_streak", {}).items():
        domain_lowrel_streak[k] = v

    pages_processed = int(state.get("pages_processed", 0))
    rows_saved = int(state.get("rows_saved", 0))

    if loaded_from != STATE_FILE:
        print(f"[resume] recovered state from {loaded_from}")
    return True


def load_seeds_from_file(path: str = SEEDS_FILE):
    """Load seeds from an external file (one URL per line; # comments supported)."""
    seeds = []
    if not os.path.exists(path):
        return seeds
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            u = line.strip()
            if u and not u.startswith("#"):
                seeds.append(u)
    return seeds


def autosave_loop():
    while not stop_event.is_set():
        stop_event.wait(AUTOSAVE_SECONDS)
        if stop_event.is_set():
            break
        try:
            flush_records()
            save_state(sync=False)
        except Exception as e:
            print(f"[autosave] warning: {e}", file=sys.stderr)


def graceful_shutdown(signum=None, frame=None):
    global shutdown_started, final_state_saved
    with shutdown_once_lock:
        if shutdown_started:
            return
        shutdown_started = True

    print("\n[shutdown] Stopping safely...")
    stop_event.set()

    # Avoid doing heavy I/O directly from an async signal handler.
    # The normal shutdown path in main()/crawl() will flush buffered rows
    # and persist crawler_state.json once the loop unwinds.
    if signum is not None:
        return

    try:
        flush_records()
        final_state_saved = save_state(sync=True)
    finally:
        print(
            f"[shutdown] pages_processed={pages_processed}, "
            f"rows_saved={rows_saved}, queue={len(queue)}"
        )


def should_prioritize_link(link: str) -> bool:
    return bool(_PRIORITY_RE.search(link))


def record_if_relevant(url: str, title: str, text: str, code_blocks: list):
    # Skip pages with almost no content (login redirects, 404s, etc.)
    if len(text) < MIN_CONTENT_LENGTH:
        return

    score = relevance_score(title, text)

    h = host(url)
    if score <= 0:
        domain_lowrel_streak[h] += 1
        return
    domain_lowrel_streak[h] = 0

    cves = extract_cves(title, text)

    # Content-based dedup so the same article republished on multiple URLs
    # is only stored once.
    content_hash = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
    if content_hash in seen_records:
        return
    seen_records.add(content_hash)

    record = {
        "scraped_at_utc": now_iso(),
        "url": url,
        "domain": h,
        "title": title,
        "relevance_score": score,
        "cves_found": cves,
        "content_hash": content_hash,
        "word_count": len(text.split()),
        "code_block_count": len(code_blocks),
        "content": text,
        "content_snippet": text[:1200],
        "code_blocks": code_blocks,
    }
    records_buffer.append(record)

    if len(records_buffer) >= FLUSH_EVERY_N_RECORDS:
        flush_records()


def seed_initial(seeds):
    for u in seeds:
        enqueue(u, priority=True)


def fetch_page(url: str):
    """Fetch and parse a page; return extracted fields or None when skipped/failed."""
    session = get_thread_session()
    try:
        if not robots_allowed(session, url):
            return None

        r = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        final_url = normalize_url(r.url)

        if r.status_code < 200 or r.status_code >= 300:
            return None

        if is_blocked(final_url):
            return None

        ctype = (r.headers.get("Content-Type") or "").lower()
        if "text/html" not in ctype and "application/xhtml+xml" not in ctype:
            return None

        soup, title, text, code_blocks = extract_text_and_title(r.text, url=final_url)
        links = extract_links(final_url, soup)
        random.shuffle(links)

        # Keep a small per-request delay for politeness while allowing concurrency.
        time.sleep(random.uniform(*SLEEP_RANGE_SECONDS))
        return final_url, title, text, code_blocks, links
    except requests.RequestException as exc:
        print(f"[warn] request failed {url}: {exc}", file=sys.stderr)
        return None
    except Exception as exc:
        print(f"[warn] unexpected error {url}: {exc}", file=sys.stderr)
        return None


def crawl(seeds):
    global pages_processed

    if not queue:
        seed_initial(seeds)

    in_flight = {}
    with ThreadPoolExecutor(max_workers=CRAWLER_THREADS) as executor:
        while not stop_event.is_set() and pages_processed < MAX_PAGES_TOTAL:
            while (
                len(in_flight) < CRAWLER_THREADS
                and queue
                and (pages_processed + len(in_flight)) < MAX_PAGES_TOTAL
            ):
                url = queue.popleft()
                queued_set.discard(url)

                if url in visited:
                    continue
                if is_blocked(url):
                    continue

                h = host(url)
                if domain_page_count[h] >= MAX_PAGES_PER_DOMAIN:
                    continue
                if domain_lowrel_streak[h] >= MAX_CONSECUTIVE_LOW_RELEVANCE_PER_DOMAIN:
                    continue

                visited.add(url)
                domain_page_count[h] += 1
                in_flight[executor.submit(fetch_page, url)] = url

            if not in_flight:
                if not queue:
                    break
                continue

            done, _ = wait(in_flight.keys(), return_when=FIRST_COMPLETED)
            for fut in done:
                in_flight.pop(fut, None)
                result = fut.result()
                if not result:
                    continue

                final_url, title, text, code_blocks, links = result
                record_if_relevant(final_url, title, text, code_blocks)

                for lk in links:
                    enqueue(lk, priority=should_prioritize_link(lk))

                pages_processed += 1
                if pages_processed % SAVE_STATE_EVERY_N_PAGES == 0:
                    flush_records()
                    save_state(sync=False)

                if pages_processed % 50 == 0:
                    print(
                        f"[progress] pages={pages_processed} rows_saved={rows_saved} "
                        f"queue={len(queue)} domains={len(domain_page_count)}"
                    )


    flush_records()
    save_state()


def main():
    global final_state_saved
    runtime_cfg_path = runtime_config_path()
    runtime_cfg, was_created = load_or_create_runtime_config(runtime_cfg_path)
    auto_tune_runtime(runtime_cfg)
    apply_runtime_page_limit()
    apply_runtime_queue_limit()

    print("[start] OSIRIS — Open Security Intelligence Recursive Internet Scraper")
    print("[start] Dynamic domain discovery enabled. Search engines excluded.")
    print(f"[start] Output JSONL: {OUTPUT_FILE}")
    if was_created:
        print(f"[start] Created runtime config: {runtime_cfg_path}")
    print(
        f"[start] Runtime profile={runtime_cfg.get('speed_profile', RUNTIME_SPEED_AUTO)} "
        f"config={runtime_cfg_path}"
    )
    print(
        f"[start] Runtime tuning: threads={CRAWLER_THREADS} "
        f"connection_pool={CONNECTION_POOL_SIZE} sleep_range={SLEEP_RANGE_SECONDS} "
        f"max_pages={MAX_PAGES_TOTAL} max_queue={MAX_QUEUE_SIZE}"
    )
    print("[start] Press Ctrl+C anytime for safe save and exit.")

    signal.signal(signal.SIGINT, graceful_shutdown)
    signal.signal(signal.SIGTERM, graceful_shutdown)

    # Load seeds: prefer seeds.txt; fall back to built-in defaults
    seeds = load_seeds_from_file(SEEDS_FILE)
    if seeds:
        print(f"[seeds] Loaded {len(seeds)} seeds from {SEEDS_FILE}")
    else:
        seeds = DEFAULT_SEEDS
        print(f"[seeds] {SEEDS_FILE} not found; using {len(seeds)} built-in default seeds")

    resumed = load_state()
    if resumed:
        print(f"[resume] Loaded state. queue={len(queue)} visited={len(visited)}")
    else:
        seed_initial(seeds)
        print(f"[seed] Queued {len(seeds)} seeds for crawl start")

    autosave_thread = threading.Thread(target=autosave_loop, daemon=True)
    autosave_thread.start()

    started = time.time()
    try:
        crawl(seeds)
    except KeyboardInterrupt:
        graceful_shutdown()
    finally:
        stop_event.set()
        autosave_thread.join(timeout=2)
        if not final_state_saved:
            flush_records()
            final_state_saved = save_state(sync=True)

    elapsed = time.time() - started
    print(f"[done] pages_processed={pages_processed}, rows_saved={rows_saved}, elapsed={elapsed:.1f}s")
    print(f"[done] JSONL={OUTPUT_FILE}  STATE={STATE_FILE}")


if __name__ == "__main__":
    main()
