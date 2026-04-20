"""Convenience runner for OSIRIS micro-benchmarks.

Usage:
    python run_benchmarks.py
    python run_benchmarks.py -q
    python run_benchmarks.py -- -k benchmark_extract
"""

import argparse
import os
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description="Run OSIRIS benchmark tests.")
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Run unittest in quiet mode.",
    )
    parser.add_argument(
        "extra",
        nargs="*",
        help="Extra unittest args (pass after --).",
    )
    args = parser.parse_args()

    env = os.environ.copy()
    env["OSIRIS_RUN_BENCH"] = "1"

    verbosity_flag = "-q" if args.quiet else "-v"
    cmd = [sys.executable, "-m", "unittest", verbosity_flag, "test_benchmark.py", *args.extra]

    print("[bench-runner] Running:", " ".join(cmd))
    return subprocess.call(cmd, env=env)


if __name__ == "__main__":
    raise SystemExit(main())

