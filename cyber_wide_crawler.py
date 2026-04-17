import os
import re
import sys
import json
import time
import signal
import random
import hashlib
import threading
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse
from collections import deque, defaultdict

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# =========================
# CONFIG
# =========================
OUTPUT_FILE = "cyber_wide_data.jsonl"
STATE_FILE = "crawler_state.json"
SEEDS_FILE = "seeds.txt"

USER_AGENT = "CyberWideCrawler/1.0 (public research crawler)"
REQUEST_TIMEOUT = 20
MAX_RETRIES = 3
MAX_PAGES_TOTAL = 20000
MAX_QUEUE_SIZE = 120000

AUTOSAVE_SECONDS = 20
FLUSH_EVERY_N_RECORDS = 25
SAVE_STATE_EVERY_N_PAGES = 50
SLEEP_RANGE_SECONDS = (0.2, 0.8)

MAX_TEXT_CHARS = 5000
MAX_LINKS_PER_PAGE = 200
MAX_PAGES_PER_DOMAIN = 120
MAX_CONSECUTIVE_LOW_RELEVANCE_PER_DOMAIN = 35

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
    "cve-", "vulnerability", "vulnerabilities", "exploit", "exploited",
    "advisory", "security advisory", "security update", "patch",
    "ransomware", "malware", "phishing", "botnet", "threat actor",
    "ioc", "indicator of compromise", "zero-day", "0day", "cvss",
    "remote code execution", "rce", "privilege escalation", "xss",
    "sql injection", "supply chain", "firmware", "kev", "mitre", "nist",
    "cybersecurity", "infosec", "apt", "incident response",
]

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

queue = deque()
queued_set = set()
visited = set()
seen_records = set()

domain_page_count = defaultdict(int)
domain_lowrel_streak = defaultdict(int)

records_buffer = []
pages_processed = 0
rows_saved = 0


# =========================
# HELPERS
# =========================
def now_iso():
    return datetime.now(timezone.utc).isoformat()


def normalize_url(url: str) -> str:
    try:
        p = urlparse(url)
        scheme = p.scheme.lower()
        netloc = p.netloc.lower()
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


def text_hash(*parts) -> str:
    x = hashlib.sha256()
    for p in parts:
        x.update((p or "").encode("utf-8", errors="ignore"))
        x.update(b"\x1e")
    return x.hexdigest()


def setup_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=MAX_RETRIES,
        connect=MAX_RETRIES,
        read=MAX_RETRIES,
        backoff_factor=0.7,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["GET", "HEAD"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=60, pool_maxsize=60)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({"User-Agent": USER_AGENT})
    return s



def relevance_score(title: str, text: str) -> int:
    blob = f"{title} {text}".lower()
    score = 0
    for kw in CYBER_KEYWORDS:
        if kw in blob:
            score += 1
    score += len(re.findall(r"\bcve-\d{4}-\d{4,7}\b", blob)) * 2
    return score


def extract_cves(title: str, text: str):
    blob = f"{title} {text}".lower()
    return sorted(set(m.upper() for m in re.findall(r"\bcve-\d{4}-\d{4,7}\b", blob)))


def extract_text_and_title(html: str):
    soup = BeautifulSoup(html, "html.parser")
    for t in soup(["script", "style", "noscript", "svg"]):
        t.decompose()

    title = ""
    if soup.title and soup.title.string:
        title = soup.title.string.strip()
    else:
        h1 = soup.find("h1")
        if h1:
            title = h1.get_text(" ", strip=True)

    text = soup.get_text(" ", strip=True)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > MAX_TEXT_CHARS:
        text = text[:MAX_TEXT_CHARS]

    return soup, title, text


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
        if is_http(full):
            links.append(full)
        if len(links) >= MAX_LINKS_PER_PAGE:
            break
    return links


def flush_records():
    global records_buffer, rows_saved
    with save_lock:
        if not records_buffer:
            return
        # Swap buffer atomically so new appends go to a fresh list while we write the old one
        to_write = records_buffer
        records_buffer = []
        rows_saved += len(to_write)
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        for record in to_write:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())


def save_state():
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
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, STATE_FILE)


def load_state():
    global pages_processed, rows_saved
    if not os.path.exists(STATE_FILE):
        return False
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            state = json.load(f)

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
        return True
    except Exception:
        return False


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
        try:
            flush_records()
            save_state()
        except Exception as e:
            print(f"[autosave] warning: {e}", file=sys.stderr)


def graceful_shutdown(signum=None, frame=None):
    print("\n[shutdown] Stopping safely...")
    stop_event.set()
    try:
        flush_records()
        save_state()
    finally:
        print(
            f"[shutdown] pages_processed={pages_processed}, "
            f"rows_saved={rows_saved}, queue={len(queue)}"
        )
        if signum is not None:
            sys.exit(0)


def should_prioritize_link(link: str) -> bool:
    l = link.lower()
    priority_markers = [
        "advisory", "security", "cve", "vuln", "vulnerability", "exploit",
        "incident", "threat", "malware", "ransomware", "patch",
    ]
    return any(m in l for m in priority_markers)


def record_if_relevant(url: str, title: str, text: str):
    score = relevance_score(title, text)

    h = host(url)
    if score <= 0:
        domain_lowrel_streak[h] += 1
        return
    domain_lowrel_streak[h] = 0

    cves = extract_cves(title, text)
    rid = text_hash(url, title, text[:800])
    if rid in seen_records:
        return
    seen_records.add(rid)

    record = {
        "scraped_at_utc": now_iso(),
        "url": url,
        "domain": h,
        "title": title,
        "relevance_score": score,
        "cves_found": cves,
        "content_snippet": text[:1200],
    }
    records_buffer.append(record)

    if len(records_buffer) >= FLUSH_EVERY_N_RECORDS:
        flush_records()


def seed_initial(seeds):
    for u in seeds:
        enqueue(u, priority=True)


def crawl(seeds):
    global pages_processed

    session = setup_session()

    if not queue:
        seed_initial(seeds)

    while queue and not stop_event.is_set() and pages_processed < MAX_PAGES_TOTAL:
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

        try:
            r = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            final_url = normalize_url(r.url)

            if is_blocked(final_url):
                continue

            ctype = (r.headers.get("Content-Type") or "").lower()
            if "text/html" not in ctype and "application/xhtml+xml" not in ctype:
                continue

            soup, title, text = extract_text_and_title(r.text)
            record_if_relevant(final_url, title, text)

            links = extract_links(final_url, soup)

            # Randomize traversal for wider internet spread
            random.shuffle(links)

            for lk in links:
                enqueue(lk, priority=should_prioritize_link(lk))

            pages_processed += 1
            if pages_processed % SAVE_STATE_EVERY_N_PAGES == 0:
                flush_records()
                save_state()

            if pages_processed % 50 == 0:
                print(
                    f"[progress] pages={pages_processed} rows_saved={rows_saved} "
                    f"queue={len(queue)} domains={len(domain_page_count)}"
                )

            time.sleep(random.uniform(*SLEEP_RANGE_SECONDS))

        except requests.RequestException:
            continue
        except Exception:
            continue

    flush_records()
    save_state()


def main():
    print("[start] OSIRIS — Open-Source Security Intel Recursive Internet Scraper")
    print("[start] Dynamic domain discovery enabled. Search engines excluded.")
    print(f"[start] Output JSONL: {OUTPUT_FILE}")
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
        flush_records()
        save_state()

    elapsed = time.time() - started
    print(f"[done] pages_processed={pages_processed}, rows_saved={rows_saved}, elapsed={elapsed:.1f}s")
    print(f"[done] JSONL={OUTPUT_FILE}  STATE={STATE_FILE}")


if __name__ == "__main__":
    main()
