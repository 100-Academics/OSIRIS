# OSIRIS

**O**pen-**S**ource **S**ecurity **I**ntel **R**ecursive **I**nternet **S**craper

A wide cybersecurity crawler that starts from a large seed list and dynamically discovers new domains across the internet — without relying on search engines. It scores pages for cybersecurity relevance, extracts CVE IDs, and writes all results to a JSONL file suitable for ML/AI training and security research.

---

## Features

- **Dynamic domain discovery** — follows outbound links to reach new domains continuously; not limited to the seed list
- **Relevance scoring** — ranks pages using cybersecurity keywords (CVE, exploit, advisory, ransomware, etc.); CVE mentions add extra weight
- **CVE extraction** — finds all `CVE-YYYY-NNNNN` identifiers per page and stores them as a proper JSON array
- **JSONL output** — one JSON record per line, ideal for ML training pipelines (HuggingFace `datasets`, OpenAI fine-tuning, PyTorch DataLoader)
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
  "content_snippet": "A critical remote code execution vulnerability..."
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
| `content_snippet` | First 1200 characters of visible page text |

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
| `MAX_PAGES_TOTAL` | 20000 | Stop after this many pages |
| `MAX_PAGES_PER_DOMAIN` | 120 | Max pages crawled per domain |
| `MAX_QUEUE_SIZE` | 120000 | Max URLs held in memory queue |
| `AUTOSAVE_SECONDS` | 20 | How often to flush and save state |
| `SLEEP_RANGE_SECONDS` | (0.2, 0.8) | Random delay between requests |
| `MAX_TEXT_CHARS` | 5000 | Max chars of text parsed per page |

---

## Scope and responsible use

OSIRIS is a research and training-data tool. When running it:

- It sends `User-Agent: CyberWideCrawler/1.0 (public research crawler)` with every request
- It respects per-domain page budgets and inserts random delays between requests
- It does **not** bypass authentication, robots.txt enforcement, or rate-limit controls
- Do not use this tool against systems you do not have permission to crawl

---

## Dependencies

- [`requests`](https://pypi.org/project/requests/) — HTTP client
- [`beautifulsoup4`](https://pypi.org/project/beautifulsoup4/) — HTML parsing
- [`urllib3`](https://pypi.org/project/urllib3/) — HTTP connection pooling (used by requests)
