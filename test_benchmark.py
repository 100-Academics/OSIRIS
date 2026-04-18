"""Micro-benchmarks for crawler hot paths.

These benchmarks are opt-in to keep normal test runs fast and deterministic.
Run with:
    OSIRIS_RUN_BENCH=1 python -m unittest -v test_benchmark.py
"""

import os
import tempfile
import unittest
from statistics import mean, median
from time import perf_counter

import cyber_wide_crawler as cwc


def _clear_global_state():
    """Reset mutable module-level state between benchmark tests."""
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


def _snapshot_global_state():
    """Capture crawler globals so benchmark runs can restore exact prior state."""
    return {
        "OUTPUT_FILE": cwc.OUTPUT_FILE,
        "STATE_FILE": cwc.STATE_FILE,
        "queue": list(cwc.queue),
        "queued_set": set(cwc.queued_set),
        "visited": set(cwc.visited),
        "seen_records": set(cwc.seen_records),
        "domain_page_count": dict(cwc.domain_page_count),
        "domain_lowrel_streak": dict(cwc.domain_lowrel_streak),
        "records_buffer": list(cwc.records_buffer),
        "pages_processed": cwc.pages_processed,
        "rows_saved": cwc.rows_saved,
        "flush_count": cwc.flush_count,
        "stop_event_set": cwc.stop_event.is_set(),
    }


def _restore_global_state(snapshot):
    cwc.OUTPUT_FILE = snapshot["OUTPUT_FILE"]
    cwc.STATE_FILE = snapshot["STATE_FILE"]

    cwc.queue.clear()
    cwc.queue.extend(snapshot["queue"])
    cwc.queued_set.clear()
    cwc.queued_set.update(snapshot["queued_set"])
    cwc.visited.clear()
    cwc.visited.update(snapshot["visited"])
    cwc.seen_records.clear()
    cwc.seen_records.update(snapshot["seen_records"])
    cwc.domain_page_count.clear()
    cwc.domain_page_count.update(snapshot["domain_page_count"])
    cwc.domain_lowrel_streak.clear()
    cwc.domain_lowrel_streak.update(snapshot["domain_lowrel_streak"])

    cwc.records_buffer.clear()
    cwc.records_buffer.extend(snapshot["records_buffer"])
    cwc.pages_processed = snapshot["pages_processed"]
    cwc.rows_saved = snapshot["rows_saved"]
    cwc.flush_count = snapshot["flush_count"]

    if snapshot["stop_event_set"]:
        cwc.stop_event.set()
    else:
        cwc.stop_event.clear()


def _run_benchmark(name: str, iterations: int, fn):
    durations = []
    for _ in range(iterations):
        start = perf_counter()
        fn()
        durations.append(perf_counter() - start)

    avg = mean(durations)
    med = median(durations)
    best = min(durations)
    ops_per_sec = (1.0 / avg) if avg > 0 else float("inf")

    # Kept as print output so `unittest -v` shows quick perf snapshots.
    print(
        f"[bench] {name}: n={iterations} avg={avg:.6f}s "
        f"p50={med:.6f}s best={best:.6f}s ops/s={ops_per_sec:.2f}"
    )


BENCH_ENABLED = os.getenv("OSIRIS_RUN_BENCH") == "1"


@unittest.skipUnless(BENCH_ENABLED, "Set OSIRIS_RUN_BENCH=1 to run benchmark tests")
class TestCrawlerBenchmarks(unittest.TestCase):

    def setUp(self):
        self._snapshot = _snapshot_global_state()
        self.addCleanup(_restore_global_state, self._snapshot)

        self._tmpdir = tempfile.mkdtemp()
        cwc.OUTPUT_FILE = os.path.join(self._tmpdir, "bench_output.jsonl")
        cwc.STATE_FILE = os.path.join(self._tmpdir, "bench_state.json")
        _clear_global_state()
        cwc.stop_event.clear()

        # Guardrail: benchmark writes must stay in sandbox paths.
        self.assertTrue(os.path.abspath(cwc.OUTPUT_FILE).startswith(os.path.abspath(self._tmpdir)))
        self.assertTrue(os.path.abspath(cwc.STATE_FILE).startswith(os.path.abspath(self._tmpdir)))

    def test_benchmark_extract_text_and_title(self):
        payload = " ".join(
            [
                "remote code execution vulnerability",
                "CVE-2026-12345",
                "buffer overflow exploit",
                "incident response patch advisory",
            ]
            * 500
        )
        html = f"""
        <html>
          <head><title>Security Advisory Benchmark</title></head>
          <body>
            <article>
              <h1>Critical Exploit Writeup</h1>
              <p>{payload}</p>
              <pre><code>python3 exploit.py --target 10.0.0.5</code></pre>
            </article>
          </body>
        </html>
        """

        def _bench_once():
            soup, title, text, code_blocks = cwc.extract_text_and_title(html)
            self.assertTrue(title)
            self.assertGreater(len(text), 100)
            self.assertIsNotNone(soup)
            self.assertGreaterEqual(len(code_blocks), 1)

        _run_benchmark("extract_text_and_title", iterations=40, fn=_bench_once)

    def test_benchmark_relevance_score(self):
        title = "CVE-2026-12345 RCE advisory"
        text = (
            "exploit vulnerability malware ransomware phishing privilege escalation "
            "uac bypass printspoofer kerberoasting lsass dump "
        ) * 800

        def _bench_once():
            score = cwc.relevance_score(title, text)
            self.assertGreater(score, 0)

        _run_benchmark("relevance_score", iterations=200, fn=_bench_once)

    def test_benchmark_record_and_flush(self):
        title = "Critical RCE exploit advisory"
        base_text = (
            "A remote code execution vulnerability was discovered and exploited in the wild. "
            "CVE-2026-1001 allows attackers to perform privilege escalation via buffer overflow. "
            "Incident response teams should patch immediately. "
        )

        def _bench_once():
            for i in range(40):
                text = f"{base_text} unique_{i} " * 8
                url = f"https://bench.example.com/advisory/{i}"
                cwc.record_if_relevant(url, title, text, ["poc()"])
            cwc.flush_records()

        _run_benchmark("record_if_relevant+flush_records", iterations=20, fn=_bench_once)
        self.assertGreater(cwc.rows_saved, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)


