# OSIRIS

**O**pen **S**ecurity **I**ntelligence **R**ecursive **I**nternet **S**craper

A wide cybersecurity crawler that starts from a large seed list and dynamically discovers new domains across the internet — without relying on search engines. It scores pages for cybersecurity relevance, extracts CVE IDs, and writes all results to a JSONL file suitable for ML/AI training and security research.

---

## Features

- **Dynamic domain discovery** — follows outbound links to reach new domains continuously; not limited to the seed list
- **Clean body extraction** — uses [trafilatura](https://trafilatura.readthedocs.io/) to extract the article body, stripping navigation, sidebars, ads, and boilerplate before storage
- **Relevance scoring** — ranks pages using 190+ cybersecurity keywords (CVE, exploit, shellcode, buffer overflow, ssrf, pentest, ctf, metasploit, UAC bypass, sudo abuse, etc.); CVE mentions add extra weight
- **CVE extraction** — finds all `CVE-YYYY-NNNNN` identifiers per page and stores them as a proper JSON array
- **Code block extraction** — separately captures `<pre>` / `<code>` snippets (PoC exploits, shellcode, YARA rules, config examples) in a dedicated field
- **Dataset discovery logging** — captures dataset-style links discovered on crawled pages and writes them to a separate JSONL file
- **Content deduplication** — SHA-256 of the cleaned body text prevents the same article (syndicated on multiple sites) from appearing twice in the dataset
- **JSONL output** — one JSON record per line, ideal for ML training pipelines (HuggingFace `datasets`, OpenAI fine-tuning, PyTorch DataLoader)
- **robots.txt compliance** — fetches and caches each domain's `robots.txt` (TTL 1 hour); skips disallowed URLs
- **Autosave** — flushes data and saves crawler state every 20 seconds
- **Graceful shutdown** — `Ctrl+C` or `SIGTERM` safely flushes all buffered data before exit
- **Resume** — state is persisted to `crawler_state.json`; re-running continues from where it left off
- **No search engines** — Google, Bing, DuckDuckGo, Baidu, etc. are blocked to avoid scraping aggregators

---

## Output format

Each line of `cyber_wide_data.jsonl` is a JSON object:

```json
{
  "scraped_at_utc": "2024-06-01T12:00:00.000000+00:00",
  "url": "https://example.com/advisory/CVE-2024-1234",
  "domain": "example.com",
  "title": "Critical RCE in Example Product",
  "relevance_score": 9,
  "cves_found": ["CVE-2024-1234", "CVE-2024-5678"],
  "content_hash": "a3f1c8...",
  "word_count": 842,
  "code_block_count": 2,
  "content": "A critical remote code execution vulnerability was discovered in...",
  "content_snippet": "A critical remote code execution vulnerability...",
  "code_blocks": ["#!/usr/bin/env python3\nimport socket\n..."]
}
```

| Field | Description |
|---|---|
| `scraped_at_utc` | ISO 8601 UTC timestamp of when the page was scraped |
| `url` | Final URL after any redirects |
| `domain` | Hostname extracted from the URL |
| `title` | Page `<title>` or first `<h1>` |
| `relevance_score` | Integer score based on cybersecurity keyword matches; higher = more relevant |
| `cves_found` | JSON array of CVE IDs found on the page |
| `content_hash` | SHA-256 of the full cleaned body text; use for near-duplicate removal at training time |
| `word_count` | Number of words in the cleaned body text |
| `code_block_count` | Number of code snippets extracted from this page |
| `content` | Full cleaned article body (up to 50 000 characters); boilerplate stripped by trafilatura |
| `content_snippet` | First 1200 characters of `content`; convenience field for quick inspection |
| `code_blocks` | Array of code snippets extracted from `<pre>`/`<code>` tags (PoC, shellcode, scripts, rules) |

Dataset links found during crawling are written to `cyber_wide_datasets.jsonl` as JSONL records with:
- `discovered_at_utc`
- `source_url` / `source_domain`
- `dataset_url` / `dataset_domain`
- `dataset_ext`

---

## Installation

```bash
# Clone the repo
git clone https://github.com/afterglow79/OSIRIS.git
cd OSIRIS

# Create and activate a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

```bash
python cyber_wide_crawler.py
```

The crawler will:
1. Load seeds from `seeds.txt`
2. Begin crawling and scoring pages
3. Write results continuously to `cyber_wide_data.jsonl`
4. Print progress every 50 pages

---

## Safe quit and resume

Press **`Ctrl+C`** at any time (or send `SIGTERM`). The crawler will:
- Stop accepting new pages
- Flush all buffered records to `cyber_wide_data.jsonl`
- Save the full crawler state (queue, visited set, domain budgets) to `crawler_state.json`

To **resume**, simply run the crawler again:

```bash
python cyber_wide_crawler.py
```

It automatically detects `crawler_state.json` and picks up from where it left off.

### Windows note: `state.json` / `crawler_state.json` locked

On Windows, antivirus/indexers/backup tools can briefly lock the state file during autosave.
When this happens, OSIRIS writes a fallback snapshot to `crawler_state.json.pending`
and resumes from the freshest valid state file on next start.

If you keep seeing lock messages for a long time, usually one of these fixes it:

```powershell
# 1) Stop all running crawler processes first
Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force

# 2) Check for stale state files (from the project root)
Get-ChildItem .\crawler_state.json*

# 3) Start again (resume logic will pick the newest valid state)
python .\cyber_wide_crawler.py
```

If needed, you can keep only the newest state artifacts manually:

```powershell
Get-ChildItem .\crawler_state.json* | Sort-Object LastWriteTime -Descending
```

---

## Customising seeds

Seeds are stored in `seeds.txt` — one URL per line. Lines beginning with `#` are comments.

```
# My extra seeds
https://www.example-security-blog.com/
https://nvd.nist.gov/
```

If `seeds.txt` is missing, the crawler falls back to a small built-in default set and continues running.

The crawler discovers new domains beyond the seed list automatically — seeds are just starting points.

---

## Configuration

Key settings at the top of `cyber_wide_crawler.py`:

| Variable | Default | Description |
|---|---|---|
| `MAX_PAGES_TOTAL` | 200000 | Stop after this many pages |
| `MAX_PAGES_PER_DOMAIN` | 320 | Max pages crawled per domain |
| `MAX_QUEUE_SIZE` | 120000 | Max URLs held in memory queue |
| `OSIRIS_MAX_RSS_MB` | Auto by RAM tier | Soft memory ceiling before aggressive memory protection kicks in |
| `AUTOSAVE_SECONDS` | 20 | How often to flush and save state |
| `SLEEP_RANGE_SECONDS` | Auto-tuned | Random delay between requests |
| `MAX_CONTENT_CHARS` | 50000 | Max chars of cleaned body text stored per page |
| `MIN_CONTENT_LENGTH` | 200 | Skip pages with fewer than this many content characters |
| `MAX_CODE_BLOCKS` | 100 | Max code snippets extracted per page |
| `ROBOTS_CACHE_TTL` | 3600 | Seconds to cache a domain's robots.txt |

Throughput defaults are now auto-tuned at startup for network-bound crawling:
- threads: `cpu_count * 8` (clamped to `32..128`)
- connection pool: `threads * 4` (clamped to `128..1024`)
- short per-request jitter for politeness (also auto-tuned)

Memory defaults are auto-tuned by host RAM:
- <= 16GB RAM -> soft cap `6144 MB`, queue cap `40000`, tighter in-memory dedupe indexes
- 17-32GB RAM -> soft cap `12288 MB`, queue cap `80000`
- > 32GB RAM -> soft cap `min(24576 MB, 60% of RAM)` with larger index budgets

On first run, OSIRIS creates `crawler_runtime_config.json` (machine-local speed profile file).
Edit this once and it will be used on every run.

```json
{
  "version": 1,
  "speed_profile": "auto",
  "custom": {
    "threads": null,
    "connection_pool": null,
    "sleep_min_ms": null,
    "sleep_max_ms": null,
    "max_pages_total": null,
    "max_queue_size": null,
    "max_rss_mb": null,
    "hard_limit_ratio": null,
    "hard_limit_consecutive_hits": null,
    "request_timeout_sec": null,
    "robots_timeout_sec": null,
    "auto_restart": null,
    "max_auto_restarts": null,
    "max_visited_urls_tracked": null,
    "max_seen_content_hashes": null
  }
}
```

Memory guard tuning fields:
- `max_rss_mb`: soft memory cap in MB.
- `hard_limit_ratio`: hard cap multiplier relative to soft cap (example `1.33`).
- `hard_limit_consecutive_hits`: how many consecutive hard-cap checks before shutdown.
- `request_timeout_sec` / `robots_timeout_sec`: skip slow pages/domains faster.
- `auto_restart` + `max_auto_restarts`: restart process after memory stop events.

`speed_profile` values:
- `auto` -> auto-tuned per machine (default)
- `balanced` -> faster than `auto`, but less risky than `max`
- `max` -> aggressive max-speed tuning for that machine
- `ultra_max` -> ultra-aggressive tuning with minimal retry overhead (1 retry, no backoff)

Quick profile switching (no file edits):
- `OSIRIS_SPEED_PROFILE=balanced|max|ultra_max|custom`

You can override at runtime without editing code:

```powershell
$env:OSIRIS_THREADS = "128"
$env:OSIRIS_CONN_POOL = "1024"
$env:OSIRIS_MAX_PAGES_TOTAL = "3000000"
$env:OSIRIS_MAX_QUEUE_SIZE = "3000000"
$env:OSIRIS_SLEEP_MIN_MS = "0"
$env:OSIRIS_SLEEP_MAX_MS = "2"
python cyber_wide_crawler.py
```

```bash
export OSIRIS_MAX_PAGES_TOTAL=3000000
export OSIRIS_MAX_QUEUE_SIZE=3000000
export OSIRIS_MAX_RSS_MB=8192
export OSIRIS_SPEED_PROFILE=balanced
export OSIRIS_REQUEST_TIMEOUT_SEC=10
export OSIRIS_AUTO_RESTART=1
export OSIRIS_MAX_RESTARTS=3
python cyber_wide_crawler.py
```

If you want to keep one profile per machine and never type env vars, set `speed_profile` in `crawler_runtime_config.json` and run normally.

---

## Using the data for training

The `cyber_wide_data.jsonl` file is a standard newline-delimited JSON (NDJSON) file — one record per line — ready to drop into any ML pipeline.

### Load with HuggingFace `datasets`

```python
from datasets import load_dataset

ds = load_dataset("json", data_files="cyber_wide_data.jsonl", split="train")
print(ds)
# Dataset({features: ['scraped_at_utc', 'url', 'domain', 'title',
#                      'relevance_score', 'cves_found', 'content_hash',
#                      'word_count', 'code_block_count',
#                      'content', 'content_snippet', 'code_blocks'],
#          num_rows: ...})
```

### Filter and select columns

```python
# Keep only high-relevance pages with at least 100 words
ds = ds.filter(lambda x: x["relevance_score"] >= 3 and x["word_count"] >= 100)

# For plain text pretraining use the 'content' field
texts = ds["content"]

# For instruction / chat fine-tuning, combine title + content
def to_prompt(example):
    return {"text": f"Title: {example['title']}\n\n{example['content']}"}

ds = ds.map(to_prompt)
```

### Load with plain Python (no extra libraries)

```python
import json

records = []
with open("cyber_wide_data.jsonl", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line:
            records.append(json.loads(line))

print(f"Loaded {len(records)} records")
```

---

## Running the tests

```bash
python -m pytest test_crawler.py -v
```

The test suite covers relevance scoring, CVE extraction, HTML parsing, link filtering, the JSONL write/read round-trip, content deduplication, and state save/load — without making any real network requests.

## Running benchmarks

`test_benchmark.py` provides opt-in micro-benchmarks for crawler hot paths:
- `extract_text_and_title`
- `relevance_score`
- `record_if_relevant` + `flush_records`

Fastest Windows options (no env var setup needed):

```powershell
python .\run_benchmarks.py
```

or directly:

```powershell
python .\test_benchmark.py
```

PowerShell:

```powershell
$env:OSIRIS_RUN_BENCH = "1"
python -m unittest -v test_benchmark.py
Remove-Item Env:OSIRIS_RUN_BENCH
```

The benchmark tests print average latency, median latency, best latency, and operations/second for each benchmark case.
They run in a temporary sandbox and redirect writes away from the default `cyber_wide_data.jsonl` and `crawler_state.json` files.

## Count stored tokens

Use `count_stored_tokens.py` to estimate how many tokens are currently stored in your JSONL output:

```powershell
python .\count_stored_tokens.py
python .\count_stored_tokens.py --file .\cyber_wide_data.jsonl --fields title content code_blocks
```

The script prints row count, total approximate tokens, and average tokens per row.

---

OSIRIS is a research and training-data tool. When running it:

- It sends `User-Agent: CyberWideCrawler/1.0 (public research crawler)` with every request
- It respects per-domain page budgets and inserts random delays between requests
- It fetches and honours each domain's `robots.txt` before crawling any page on that domain
- Do not use this tool against systems you do not have permission to crawl

---

## Dependencies

- [`requests`](https://pypi.org/project/requests/) — HTTP client
- [`beautifulsoup4`](https://pypi.org/project/beautifulsoup4/) — HTML parsing
- [`trafilatura`](https://trafilatura.readthedocs.io/) — main-content extraction (strips nav/footer/ads)
- [`urllib3`](https://pypi.org/project/urllib3/) — HTTP connection pooling (used by requests)