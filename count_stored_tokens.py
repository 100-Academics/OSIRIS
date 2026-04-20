import argparse
import json
import re
from pathlib import Path

TOKEN_RE = re.compile(r"\w+|[^\w\s]", re.UNICODE)


def _tokenize(text: str) -> int:
    if not text:
        return 0
    return len(TOKEN_RE.findall(text))


def _field_text(record: dict, fields: list[str]) -> str:
    parts = []
    for field in fields:
        value = record.get(field)
        if value is None:
            continue
        if isinstance(value, list):
            parts.extend(str(v) for v in value)
        else:
            parts.append(str(value))
    return "\n".join(parts)


def count_tokens(path: Path, fields: list[str]) -> tuple[int, int]:
    rows = 0
    tokens = 0
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            rows += 1
            tokens += _tokenize(_field_text(record, fields))
    return rows, tokens


def main():
    parser = argparse.ArgumentParser(
        description="Count approximate tokens stored in an OSIRIS JSONL file."
    )
    parser.add_argument(
        "--file",
        default="cyber_wide_data.jsonl",
        help="Path to JSONL file (default: cyber_wide_data.jsonl)",
    )
    parser.add_argument(
        "--fields",
        nargs="+",
        default=["title", "content", "code_blocks"],
        help="Fields to include in token counting",
    )
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        raise SystemExit(f"File not found: {path}")

    rows, tokens = count_tokens(path, args.fields)
    avg = (tokens / rows) if rows else 0.0
    print(f"file={path}")
    print(f"rows={rows}")
    print(f"tokens={tokens}")
    print(f"avg_tokens_per_row={avg:.2f}")
    print(f"fields={','.join(args.fields)}")


if __name__ == "__main__":
    main()

