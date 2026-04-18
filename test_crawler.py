"""
Integration and unit tests for cyber_wide_crawler.py

Verifies that the crawler correctly:
  1. Scores and extracts cybersecurity-relevant content from HTML
  2. Extracts CVE identifiers
  3. Parses titles, body text, and code blocks from HTML
  4. Filters links (binary extensions, blocked domains, javascript: hrefs)
  5. Normalises URLs
  6. Writes valid JSONL output with all required fields and correct types
  7. Deduplicates records by content hash
  8. Discards irrelevant or too-short pages
  9. Saves and reloads crawler state faithfully (resume support)
 10. Produces JSONL that round-trips through json.loads and is loadable
     the same way a HuggingFace / plain-Python training pipeline would

No real network requests are made by any test.
"""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

import cyber_wide_crawler as cwc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_soup(html: str):
    from bs4 import BeautifulSoup
    return BeautifulSoup(html, cwc._HTML_PARSER)


def _clear_global_state():
    """Reset all mutable module-level state between tests."""
    cwc.queue.clear()
    cwc.queued_set.clear()
    cwc.visited.clear()
    cwc.seen_records.clear()
    cwc.domain_page_count.clear()
    cwc.domain_lowrel_streak.clear()
    cwc.records_buffer.clear()
    cwc.pages_processed = 0
    cwc.rows_saved = 0
    cwc.flush_count = 0
    cwc.shutdown_started = False
    cwc.final_state_saved = False
    cwc.last_state_warning["message"] = ""
    cwc.last_state_warning["at"] = 0.0


# ---------------------------------------------------------------------------
# Relevance scoring
# ---------------------------------------------------------------------------

class TestRelevanceScoring(unittest.TestCase):

    def test_known_keywords_score_positive(self):
        score = cwc.relevance_score(
            "CVE-2024-1234 UAC bypass advisory",
            "rootkit ransomware exploit phishing buffer overflow",
        )
        self.assertGreater(score, 0)

    def test_irrelevant_text_scores_zero(self):
        score = cwc.relevance_score(
            "Chocolate chip cookie recipe",
            "Mix flour and sugar together in a bowl with butter.",
        )
        self.assertEqual(score, 0)

    def test_each_distinct_keyword_counted_once(self):
        # "exploit" repeated many times should still count as 1 keyword hit
        score_single = cwc.relevance_score("", "exploit")
        score_many = cwc.relevance_score("", "exploit exploit exploit exploit")
        self.assertEqual(score_single, score_many)

    def test_cve_bonus_on_top_of_keywords(self):
        base = cwc.relevance_score("", "vulnerability")
        with_cve = cwc.relevance_score("", "vulnerability CVE-2024-9999")
        self.assertGreater(with_cve, base)

    def test_windows_elevation_keywords(self):
        score = cwc.relevance_score("", "uac bypass printspoofer seimpersonateprivilege lsass dump")
        self.assertGreater(score, 0)

    def test_linux_elevation_keywords(self):
        score = cwc.relevance_score("", "sudo -l suid binary pkexec dirty pipe pwnkit")
        self.assertGreater(score, 0)

    def test_score_is_integer(self):
        score = cwc.relevance_score("exploit", "vulnerability CVE-2024-1")
        self.assertIsInstance(score, int)


# ---------------------------------------------------------------------------
# CVE extraction
# ---------------------------------------------------------------------------

class TestCveExtraction(unittest.TestCase):

    def test_extracts_multiple_cves(self):
        cves = cwc.extract_cves("", "CVE-2024-1234 and cve-2023-9999 and CVE-2021-44228")
        self.assertEqual(cves, ["CVE-2021-44228", "CVE-2023-9999", "CVE-2024-1234"])

    def test_result_is_uppercased(self):
        cves = cwc.extract_cves("", "cve-2024-1234")
        self.assertEqual(cves, ["CVE-2024-1234"])

    def test_deduplicates_same_cve(self):
        cves = cwc.extract_cves("CVE-2024-1234", "CVE-2024-1234 appears twice CVE-2024-1234")
        self.assertEqual(cves.count("CVE-2024-1234"), 1)

    def test_returns_sorted_list(self):
        cves = cwc.extract_cves("", "CVE-2024-9999 CVE-2023-0001")
        self.assertEqual(cves, sorted(cves))

    def test_no_cves_returns_empty_list(self):
        self.assertEqual(cwc.extract_cves("hello", "world"), [])

    def test_result_is_list(self):
        self.assertIsInstance(cwc.extract_cves("", ""), list)


# ---------------------------------------------------------------------------
# HTML extraction (title, text, code blocks)
# ---------------------------------------------------------------------------

SAMPLE_HTML = """
<html>
<head><title>Critical RCE in Example App</title></head>
<body>
  <nav>Nav boilerplate</nav>
  <h1>Critical Vulnerability</h1>
  <article>
    <p>A remote code execution vulnerability was found. Attackers can exploit
    this to run arbitrary code via buffer overflow techniques.</p>
    <pre><code>#!/usr/bin/env python3
import socket
s = socket.socket()
s.connect(("10.0.0.1", 4444))</code></pre>
  </article>
  <script>alert("should be stripped")</script>
  <style>.nav { color: red; }</style>
</body>
</html>
"""


class TestExtractTextAndTitle(unittest.TestCase):

    def test_title_from_title_tag(self):
        _, title, _, _ = cwc.extract_text_and_title(SAMPLE_HTML)
        self.assertEqual(title, "Critical RCE in Example App")

    def test_title_falls_back_to_h1(self):
        html = "<html><body><h1>Security Advisory</h1><p>details here about vulnerability</p></body></html>"
        _, title, _, _ = cwc.extract_text_and_title(html)
        self.assertEqual(title, "Security Advisory")

    def test_empty_title_when_none_present(self):
        html = "<html><body><p>just a paragraph</p></body></html>"
        _, title, _, _ = cwc.extract_text_and_title(html)
        self.assertIsInstance(title, str)

    def test_script_and_style_stripped(self):
        _, _, text, _ = cwc.extract_text_and_title(SAMPLE_HTML)
        self.assertNotIn("alert(", text)
        self.assertNotIn(".nav {", text)

    def test_text_has_no_double_spaces(self):
        _, _, text, _ = cwc.extract_text_and_title(SAMPLE_HTML)
        self.assertNotIn("  ", text)

    def test_text_is_stripped(self):
        _, _, text, _ = cwc.extract_text_and_title(SAMPLE_HTML)
        self.assertEqual(text, text.strip())

    def test_code_blocks_extracted(self):
        _, _, _, code_blocks = cwc.extract_text_and_title(SAMPLE_HTML)
        self.assertGreater(len(code_blocks), 0)
        self.assertTrue(any("socket" in cb for cb in code_blocks))

    def test_code_blocks_deduplicated(self):
        # nested <pre><code> should not produce two identical entries
        html = "<html><body><pre><code>exploit_code()</code></pre></body></html>"
        _, _, _, code_blocks = cwc.extract_text_and_title(html)
        self.assertEqual(len(code_blocks), len(set(code_blocks)))

    def test_code_blocks_is_list(self):
        _, _, _, code_blocks = cwc.extract_text_and_title(SAMPLE_HTML)
        self.assertIsInstance(code_blocks, list)

    def test_text_truncated_at_max_chars(self):
        long_html = f"<html><body><p>{'exploit ' * 20000}</p></body></html>"
        _, _, text, _ = cwc.extract_text_and_title(long_html)
        self.assertLessEqual(len(text), cwc.MAX_CONTENT_CHARS)

    def test_returns_soup_for_link_extraction(self):
        from bs4 import BeautifulSoup
        soup, _, _, _ = cwc.extract_text_and_title(SAMPLE_HTML)
        self.assertIsInstance(soup, BeautifulSoup)


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

class TestNormalizeUrl(unittest.TestCase):

    def test_lowercase_scheme_and_host(self):
        self.assertEqual(
            cwc.normalize_url("HTTP://Example.COM/path"),
            "http://example.com/path",
        )

    def test_adds_slash_when_path_empty(self):
        self.assertEqual(cwc.normalize_url("https://example.com"), "https://example.com/")

    def test_preserves_query_string(self):
        u = "https://example.com/search?q=exploit&page=2"
        self.assertEqual(cwc.normalize_url(u), u)

    def test_invalid_url_returned_unchanged(self):
        bad = "not a url at all"
        self.assertEqual(cwc.normalize_url(bad), bad)


class TestIsBlocked(unittest.TestCase):

    def test_blocked_root_domain(self):
        self.assertTrue(cwc.is_blocked("https://google.com/search?q=test"))

    def test_blocked_explicit_www(self):
        self.assertTrue(cwc.is_blocked("https://www.bing.com/"))

    def test_blocked_subdomain_of_blocked_root(self):
        self.assertTrue(cwc.is_blocked("https://mail.google.com/"))

    def test_allowed_domain(self):
        self.assertFalse(cwc.is_blocked("https://nvd.nist.gov/vuln/detail/CVE-2024-1"))

    def test_empty_host_blocked(self):
        self.assertTrue(cwc.is_blocked("javascript:void(0)"))


# ---------------------------------------------------------------------------
# Link extraction
# ---------------------------------------------------------------------------

class TestExtractLinks(unittest.TestCase):

    def test_resolves_relative_links(self):
        soup = _make_soup('<a href="/advisory/1">link</a>')
        links = cwc.extract_links("https://example.com/", soup)
        self.assertIn("https://example.com/advisory/1", links)

    def test_skips_javascript_hrefs(self):
        soup = _make_soup('<a href="javascript:void(0)">bad</a>')
        self.assertEqual(cwc.extract_links("https://example.com/", soup), [])

    def test_skips_mailto(self):
        soup = _make_soup('<a href="mailto:user@example.com">email</a>')
        self.assertEqual(cwc.extract_links("https://example.com/", soup), [])

    def test_skips_pdf(self):
        soup = _make_soup('<a href="/report.pdf">report</a>')
        links = cwc.extract_links("https://example.com/", soup)
        self.assertFalse(any(l.endswith(".pdf") for l in links))

    def test_skips_exe(self):
        soup = _make_soup('<a href="/tool.exe">tool</a>')
        links = cwc.extract_links("https://example.com/", soup)
        self.assertFalse(any(l.endswith(".exe") for l in links))

    def test_skips_image_extensions(self):
        for ext in (".jpg", ".png", ".gif", ".svg"):
            soup = _make_soup(f'<a href="/img{ext}">img</a>')
            links = cwc.extract_links("https://example.com/", soup)
            self.assertFalse(any(l.endswith(ext) for l in links), f"{ext} should be skipped")

    def test_html_page_not_skipped(self):
        soup = _make_soup('<a href="/advisory/CVE-2024-1.html">advisory</a>')
        links = cwc.extract_links("https://example.com/", soup)
        self.assertTrue(any("CVE-2024-1.html" in l for l in links))

    def test_max_links_per_page_respected(self):
        hrefs = "".join(f'<a href="/page{i}">x</a>' for i in range(300))
        soup = _make_soup(hrefs)
        links = cwc.extract_links("https://example.com/", soup)
        self.assertLessEqual(len(links), cwc.MAX_LINKS_PER_PAGE)

    def test_returns_list(self):
        soup = _make_soup("")
        self.assertIsInstance(cwc.extract_links("https://example.com/", soup), list)


# ---------------------------------------------------------------------------
# Priority link detection
# ---------------------------------------------------------------------------

class TestShouldPrioritizeLink(unittest.TestCase):

    def test_advisory_in_path(self):
        self.assertTrue(cwc.should_prioritize_link("https://example.com/advisory/2024"))

    def test_cve_in_path(self):
        self.assertTrue(cwc.should_prioritize_link("https://nvd.nist.gov/vuln/detail/CVE-2024-1"))

    def test_non_priority_link(self):
        self.assertFalse(cwc.should_prioritize_link("https://example.com/about-us"))

    def test_returns_bool(self):
        self.assertIsInstance(cwc.should_prioritize_link("https://x.com/"), bool)


# ---------------------------------------------------------------------------
# Runtime speed config (first-run file + profiles)
# ---------------------------------------------------------------------------

class TestRuntimeSpeedConfig(unittest.TestCase):

    def setUp(self):
        self._orig_threads = cwc.CRAWLER_THREADS
        self._orig_pool = cwc.CONNECTION_POOL_SIZE
        self._orig_sleep = cwc.SLEEP_RANGE_SECONDS
        self._tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        cwc.CRAWLER_THREADS = self._orig_threads
        cwc.CONNECTION_POOL_SIZE = self._orig_pool
        cwc.SLEEP_RANGE_SECONDS = self._orig_sleep

    def test_runtime_config_created_on_first_run(self):
        path = os.path.join(self._tmpdir, "runtime_config.json")
        cfg, created = cwc.load_or_create_runtime_config(path)
        self.assertTrue(created)
        self.assertTrue(os.path.exists(path))
        self.assertEqual(cfg["speed_profile"], cwc.RUNTIME_SPEED_AUTO)

    def test_max_profile_is_more_aggressive_than_auto(self):
        cwc.auto_tune_runtime({"speed_profile": cwc.RUNTIME_SPEED_AUTO})
        auto_threads = cwc.CRAWLER_THREADS
        auto_pool = cwc.CONNECTION_POOL_SIZE
        auto_sleep = cwc.SLEEP_RANGE_SECONDS

        cwc.auto_tune_runtime({"speed_profile": cwc.RUNTIME_SPEED_MAX})
        self.assertGreaterEqual(cwc.CRAWLER_THREADS, auto_threads)
        self.assertGreaterEqual(cwc.CONNECTION_POOL_SIZE, auto_pool)
        self.assertLessEqual(cwc.SLEEP_RANGE_SECONDS[1], auto_sleep[1])

    def test_custom_profile_respects_values(self):
        cwc.auto_tune_runtime(
            {
                "speed_profile": cwc.RUNTIME_SPEED_CUSTOM,
                "custom": {
                    "threads": 21,
                    "connection_pool": 333,
                    "sleep_min_ms": 1.0,
                    "sleep_max_ms": 3.0,
                },
            }
        )
        self.assertEqual(cwc.CRAWLER_THREADS, 21)
        self.assertEqual(cwc.CONNECTION_POOL_SIZE, 333)
        self.assertAlmostEqual(cwc.SLEEP_RANGE_SECONDS[0], 0.001)
        self.assertAlmostEqual(cwc.SLEEP_RANGE_SECONDS[1], 0.003)


class TestPageLimitConfig(unittest.TestCase):

    def setUp(self):
        self._orig_limit = cwc.MAX_PAGES_TOTAL
        self._orig_env = os.environ.get(cwc.ENV_MAX_PAGES_TOTAL)

    def tearDown(self):
        cwc.MAX_PAGES_TOTAL = self._orig_limit
        if self._orig_env is None:
            os.environ.pop(cwc.ENV_MAX_PAGES_TOTAL, None)
        else:
            os.environ[cwc.ENV_MAX_PAGES_TOTAL] = self._orig_env

    def test_page_limit_can_be_overridden_via_env(self):
        os.environ[cwc.ENV_MAX_PAGES_TOTAL] = "3000000"
        cwc.apply_runtime_page_limit()
        self.assertEqual(cwc.MAX_PAGES_TOTAL, 3000000)

    def test_invalid_page_limit_falls_back_to_default(self):
        os.environ[cwc.ENV_MAX_PAGES_TOTAL] = "not-a-number"
        cwc.apply_runtime_page_limit()
        self.assertEqual(cwc.MAX_PAGES_TOTAL, self._orig_limit)


class TestQueueLimitConfig(unittest.TestCase):

    def setUp(self):
        self._orig_limit = cwc.MAX_QUEUE_SIZE
        self._orig_env = os.environ.get(cwc.ENV_MAX_QUEUE_SIZE)
        _clear_global_state()

    def tearDown(self):
        cwc.MAX_QUEUE_SIZE = self._orig_limit
        if self._orig_env is None:
            os.environ.pop(cwc.ENV_MAX_QUEUE_SIZE, None)
        else:
            os.environ[cwc.ENV_MAX_QUEUE_SIZE] = self._orig_env
        _clear_global_state()

    def test_queue_limit_can_be_overridden_via_env(self):
        os.environ[cwc.ENV_MAX_QUEUE_SIZE] = "3000000"
        cwc.apply_runtime_queue_limit()
        self.assertEqual(cwc.MAX_QUEUE_SIZE, 3000000)

    def test_invalid_queue_limit_falls_back_to_default(self):
        os.environ[cwc.ENV_MAX_QUEUE_SIZE] = "not-a-number"
        cwc.apply_runtime_queue_limit()
        self.assertEqual(cwc.MAX_QUEUE_SIZE, self._orig_limit)

    def test_enqueue_respects_queue_cap(self):
        cwc.MAX_QUEUE_SIZE = 2
        cwc.enqueue("https://example.com/one")
        cwc.enqueue("https://example.com/two")
        cwc.enqueue("https://example.com/three")
        self.assertEqual(len(cwc.queued_set), 2)
        self.assertNotIn("https://example.com/three", cwc.queued_set)


# ---------------------------------------------------------------------------
# record_if_relevant + flush_records → valid JSONL
# ---------------------------------------------------------------------------

RELEVANT_TITLE = "Critical RCE exploit advisory"
RELEVANT_TEXT = (
    "A remote code execution vulnerability was discovered and exploited in the wild. "
    "CVE-2024-1234 allows attackers to perform privilege escalation via buffer overflow. "
    "Ransomware groups are actively using this phishing vector. "
    "Incident response teams should patch immediately. " * 4
)


class TestRecordAndFlush(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._orig_output = cwc.OUTPUT_FILE
        cwc.OUTPUT_FILE = os.path.join(self._tmpdir, "output.jsonl")
        _clear_global_state()

    def tearDown(self):
        cwc.OUTPUT_FILE = self._orig_output
        _clear_global_state()

    # ---- basic buffering / filtering ----

    def test_relevant_page_buffered(self):
        cwc.record_if_relevant("https://nvd.nist.gov/vuln/1", RELEVANT_TITLE, RELEVANT_TEXT, [])
        self.assertEqual(len(cwc.records_buffer), 1)

    def test_irrelevant_page_not_buffered(self):
        cwc.record_if_relevant(
            "https://example.com/", "Cookie recipe",
            "Mix flour and butter together with sugar.", [],
        )
        self.assertEqual(len(cwc.records_buffer), 0)

    def test_too_short_page_not_buffered(self):
        cwc.record_if_relevant("https://example.com/", "Exploit", "short", [])
        self.assertEqual(len(cwc.records_buffer), 0)

    def test_duplicate_content_not_buffered_twice(self):
        cwc.record_if_relevant("https://site1.com/", RELEVANT_TITLE, RELEVANT_TEXT, [])
        cwc.record_if_relevant("https://site2.com/", RELEVANT_TITLE, RELEVANT_TEXT, [])
        self.assertEqual(len(cwc.records_buffer), 1)

    # ---- JSONL output correctness ----

    def _flush_and_load(self) -> list:
        cwc.flush_records()
        records = []
        with open(cwc.OUTPUT_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    def test_flush_empties_buffer(self):
        cwc.record_if_relevant("https://nvd.nist.gov/1", RELEVANT_TITLE, RELEVANT_TEXT, [])
        cwc.flush_records()
        self.assertEqual(cwc.records_buffer, [])

    def test_flush_increments_rows_saved(self):
        cwc.record_if_relevant("https://nvd.nist.gov/1", RELEVANT_TITLE, RELEVANT_TEXT, [])
        cwc.flush_records()
        self.assertEqual(cwc.rows_saved, 1)

    def test_output_file_contains_valid_json_lines(self):
        cwc.record_if_relevant("https://nvd.nist.gov/1", RELEVANT_TITLE, RELEVANT_TEXT, ["code()"])
        records = self._flush_and_load()
        self.assertGreater(len(records), 0)
        for r in records:
            self.assertIsInstance(r, dict)

    def test_required_fields_present(self):
        cwc.record_if_relevant("https://nvd.nist.gov/1", RELEVANT_TITLE, RELEVANT_TEXT, ["code()"])
        records = self._flush_and_load()
        self.assertEqual(len(records), 1)
        required = {
            "scraped_at_utc", "url", "domain", "title",
            "relevance_score", "cves_found", "content_hash",
            "word_count", "code_block_count",
            "content", "content_snippet", "code_blocks",
        }
        for field in required:
            self.assertIn(field, records[0], f"Missing field: {field}")

    def test_field_types(self):
        cwc.record_if_relevant("https://nvd.nist.gov/1", RELEVANT_TITLE, RELEVANT_TEXT, ["code()"])
        records = self._flush_and_load()
        r = records[0]
        self.assertIsInstance(r["scraped_at_utc"], str)
        self.assertIsInstance(r["url"], str)
        self.assertIsInstance(r["domain"], str)
        self.assertIsInstance(r["title"], str)
        self.assertIsInstance(r["relevance_score"], int)
        self.assertIsInstance(r["cves_found"], list)
        self.assertIsInstance(r["content_hash"], str)
        self.assertIsInstance(r["word_count"], int)
        self.assertIsInstance(r["code_block_count"], int)
        self.assertIsInstance(r["content"], str)
        self.assertIsInstance(r["content_snippet"], str)
        self.assertIsInstance(r["code_blocks"], list)

    def test_field_values_are_sensible(self):
        code = ["import socket; s = socket.socket()"]
        cwc.record_if_relevant("https://nvd.nist.gov/1", RELEVANT_TITLE, RELEVANT_TEXT, code)
        records = self._flush_and_load()
        r = records[0]
        self.assertGreater(r["relevance_score"], 0)
        self.assertGreater(r["word_count"], 0)
        self.assertEqual(r["code_block_count"], 1)
        self.assertEqual(r["code_blocks"], code)
        self.assertEqual(r["url"], "https://nvd.nist.gov/1")
        self.assertEqual(r["domain"], "nvd.nist.gov")
        self.assertTrue(r["content_snippet"])
        self.assertLessEqual(len(r["content_snippet"]), 1200)

    def test_cves_extracted_into_output(self):
        text_with_cves = RELEVANT_TEXT + " CVE-2024-9999 cve-2023-0001"
        cwc.record_if_relevant("https://nvd.nist.gov/1", RELEVANT_TITLE, text_with_cves, [])
        records = self._flush_and_load()
        cves = records[0]["cves_found"]
        self.assertIn("CVE-2024-9999", cves)
        self.assertIn("CVE-2023-0001", cves)

    def test_content_hash_is_sha256_hex(self):
        cwc.record_if_relevant("https://nvd.nist.gov/1", RELEVANT_TITLE, RELEVANT_TEXT, [])
        records = self._flush_and_load()
        h = records[0]["content_hash"]
        self.assertEqual(len(h), 64)
        self.assertRegex(h, r"^[0-9a-f]{64}$")

    def test_multiple_records_each_on_own_line(self):
        for i in range(3):
            cwc.record_if_relevant(
                f"https://nvd.nist.gov/vuln/{i}",
                f"{RELEVANT_TITLE} {i}",
                RELEVANT_TEXT + f" unique_{i}_" * 10,
                [],
            )
        cwc.flush_records()
        with open(cwc.OUTPUT_FILE, encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
        self.assertEqual(len(lines), 3)
        for line in lines:
            json.loads(line)  # must not raise

    def test_content_does_not_exceed_max_chars(self):
        long_text = "vulnerability exploit ransomware " * 2000
        cwc.record_if_relevant("https://nvd.nist.gov/1", RELEVANT_TITLE, long_text[:cwc.MAX_CONTENT_CHARS], [])
        records = self._flush_and_load()
        self.assertLessEqual(len(records[0]["content"]), cwc.MAX_CONTENT_CHARS)

    # ---- training-data round-trip ----

    def test_jsonl_round_trip_for_training(self):
        """
        Simulates the full scrape → save → load pipeline a training job uses.
        All records must survive a json.loads round-trip with correct types.
        """
        for i in range(5):
            cwc.record_if_relevant(
                f"https://nvd.nist.gov/vuln/{i}",
                f"RCE vulnerability {i} exploit advisory",
                f"Remote code execution {i} buffer overflow ransomware phishing CVE-2024-{1000 + i}. " * 6,
                [f"poc_{i}()"],
            )
        cwc.flush_records()

        loaded = []
        with open(cwc.OUTPUT_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    loaded.append(json.loads(line))

        self.assertEqual(len(loaded), 5)
        for r in loaded:
            self.assertGreater(len(r["content"]), 0)
            self.assertGreater(r["relevance_score"], 0)
            self.assertGreater(r["word_count"], 0)
            # Confirm it can be re-serialised (full round-trip safety)
            json.dumps(r, ensure_ascii=False)

    def test_unicode_content_survives_round_trip(self):
        """Non-ASCII characters must be preserved faithfully."""
        unicode_text = (
            "Schwachstelle exploit Sicherheitslücke vulnerability "
            "漏洞 利用 安全 CVE-2024-1234 ransomware malware phishing. " * 5
        )
        cwc.record_if_relevant("https://example.com/", "CVE exploit 漏洞", unicode_text, [])
        records = self._flush_and_load()
        self.assertGreater(len(records), 0)
        self.assertIn("漏洞", records[0]["content"])


# ---------------------------------------------------------------------------
# State persistence (save / load)
# ---------------------------------------------------------------------------

class TestStatePersistence(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._orig_state = cwc.STATE_FILE
        cwc.STATE_FILE = os.path.join(self._tmpdir, "state.json")
        _clear_global_state()

    def tearDown(self):
        cwc.STATE_FILE = self._orig_state
        _clear_global_state()

    def test_save_and_load_round_trip(self):
        cwc.queue.append("https://example.com/advisory/1")
        cwc.visited.add("https://visited.com/page")
        cwc.pages_processed = 42
        cwc.rows_saved = 7

        cwc.save_state()

        # Wipe in-memory state before loading
        _clear_global_state()

        result = cwc.load_state()
        self.assertTrue(result)
        self.assertIn("https://example.com/advisory/1", cwc.queue)
        self.assertIn("https://visited.com/page", cwc.visited)
        self.assertEqual(cwc.pages_processed, 42)
        self.assertEqual(cwc.rows_saved, 7)

    def test_load_state_missing_file_returns_false(self):
        self.assertFalse(cwc.load_state())

    def test_state_file_is_valid_json(self):
        cwc.queue.append("https://example.com/")
        cwc.save_state()
        with open(cwc.STATE_FILE, encoding="utf-8") as f:
            state = json.load(f)
        for key in ("queue", "queued_set", "visited", "seen_records",
                    "domain_page_count", "domain_lowrel_streak",
                    "pages_processed", "rows_saved", "timestamp"):
            self.assertIn(key, state)

    def test_corrupted_state_file_returns_false(self):
        with open(cwc.STATE_FILE, "w") as f:
            f.write("{ not valid json !!!")
        self.assertFalse(cwc.load_state())

    def test_load_state_recovers_from_tmp_when_main_is_corrupt(self):
        with open(cwc.STATE_FILE, "w", encoding="utf-8") as f:
            f.write("{ broken")
        with open(cwc.STATE_FILE + ".tmp", "w", encoding="utf-8") as f:
            json.dump({
                "queue": ["https://example.com/recovered"],
                "queued_set": [],
                "visited": [],
                "seen_records": [],
                "domain_page_count": {},
                "domain_lowrel_streak": {},
                "pages_processed": 123,
                "rows_saved": 9,
            }, f)

        self.assertTrue(cwc.load_state())
        self.assertIn("https://example.com/recovered", cwc.queue)
        self.assertEqual(cwc.pages_processed, 123)

    def test_load_state_prefers_newer_tmp_when_both_valid(self):
        with open(cwc.STATE_FILE, "w", encoding="utf-8") as f:
            json.dump({
                "queue": ["https://example.com/old"],
                "queued_set": [],
                "visited": [],
                "seen_records": [],
                "domain_page_count": {},
                "domain_lowrel_streak": {},
                "pages_processed": 10,
                "rows_saved": 1,
                "timestamp": "2026-01-01T00:00:00+00:00",
            }, f)

        with open(cwc.STATE_FILE + ".tmp", "w", encoding="utf-8") as f:
            json.dump({
                "queue": ["https://example.com/new"],
                "queued_set": [],
                "visited": [],
                "seen_records": [],
                "domain_page_count": {},
                "domain_lowrel_streak": {},
                "pages_processed": 20,
                "rows_saved": 2,
                "timestamp": "2026-01-01T00:00:01+00:00",
            }, f)

        self.assertTrue(cwc.load_state())
        self.assertIn("https://example.com/new", cwc.queue)
        self.assertNotIn("https://example.com/old", cwc.queue)
        self.assertEqual(cwc.pages_processed, 20)

    def test_state_written_atomically(self):
        """State is written to a .tmp file then renamed — the final file must be complete."""
        cwc.pages_processed = 99
        cwc.save_state()
        # .tmp file must not exist after save
        self.assertFalse(os.path.exists(cwc.STATE_FILE + ".tmp"))
        # final file must be readable
        with open(cwc.STATE_FILE, encoding="utf-8") as f:
            state = json.load(f)
        self.assertEqual(state["pages_processed"], 99)

    def test_permission_error_on_replace_keeps_previous_state(self):
        cwc.pages_processed = 1
        cwc.queue.append("https://example.com/old")
        self.assertTrue(cwc.save_state())

        cwc.pages_processed = 2
        cwc.queue.append("https://example.com/new")

        with patch("cyber_wide_crawler.time.sleep", return_value=None):
            with patch("cyber_wide_crawler.os.replace", side_effect=PermissionError("locked")):
                self.assertFalse(cwc.save_state(sync=False))

        # Existing on-disk state remains valid and unchanged.
        with open(cwc.STATE_FILE, encoding="utf-8") as f:
            state = json.load(f)
        self.assertEqual(state["pages_processed"], 1)
        self.assertIn("https://example.com/old", state["queue"])
        self.assertNotIn("https://example.com/new", state["queue"])

        # In-memory queue/state is preserved; failure does not clear progress.
        self.assertEqual(cwc.pages_processed, 2)
        self.assertIn("https://example.com/new", cwc.queue)

    def test_graceful_shutdown_is_idempotent(self):
        _clear_global_state()
        with patch("cyber_wide_crawler.flush_records") as mock_flush:
            with patch("cyber_wide_crawler.save_state", return_value=True) as mock_save:
                cwc.graceful_shutdown()
                cwc.graceful_shutdown()

        self.assertEqual(mock_flush.call_count, 1)
        self.assertEqual(mock_save.call_count, 1)


# ---------------------------------------------------------------------------
# Enqueue / domain budgeting
# ---------------------------------------------------------------------------

class TestEnqueue(unittest.TestCase):

    def setUp(self):
        _clear_global_state()

    def tearDown(self):
        _clear_global_state()

    def test_valid_url_enqueued(self):
        cwc.enqueue("https://nvd.nist.gov/vuln/1")
        self.assertIn("https://nvd.nist.gov/vuln/1", cwc.queued_set)

    def test_already_visited_not_enqueued(self):
        cwc.visited.add("https://nvd.nist.gov/vuln/1")
        cwc.enqueue("https://nvd.nist.gov/vuln/1")
        self.assertNotIn("https://nvd.nist.gov/vuln/1", cwc.queued_set)

    def test_blocked_domain_not_enqueued(self):
        cwc.enqueue("https://google.com/search?q=exploit")
        self.assertEqual(len(cwc.queued_set), 0)

    def test_non_http_not_enqueued(self):
        cwc.enqueue("ftp://example.com/file")
        self.assertEqual(len(cwc.queued_set), 0)

    def test_priority_url_at_front_of_queue(self):
        cwc.enqueue("https://nvd.nist.gov/normal")
        cwc.enqueue("https://nvd.nist.gov/priority", priority=True)
        self.assertEqual(cwc.queue[0], "https://nvd.nist.gov/priority")

    def test_domain_budget_respected(self):
        h = "nvd.nist.gov"
        cwc.domain_page_count[h] = cwc.MAX_PAGES_PER_DOMAIN
        cwc.enqueue("https://nvd.nist.gov/vuln/new")
        self.assertNotIn("https://nvd.nist.gov/vuln/new", cwc.queued_set)

    def test_low_relevance_streak_blocks_enqueue(self):
        h = "noisy.example.com"
        cwc.domain_lowrel_streak[h] = cwc.MAX_CONSECUTIVE_LOW_RELEVANCE_PER_DOMAIN
        cwc.enqueue("https://noisy.example.com/page")
        self.assertNotIn("https://noisy.example.com/page", cwc.queued_set)


if __name__ == "__main__":
    unittest.main(verbosity=2)
