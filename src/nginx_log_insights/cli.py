import argparse
import gzip
import sys
from collections.abc import Iterator
from contextlib import ExitStack
from datetime import timedelta
from pathlib import Path
from typing import TextIO

from .analyzers import analyze, default_analyzers
from .parser import LogReader
from .report import render_json, render_text


def open_log(path: Path, stack: ExitStack) -> TextIO:
    if path.suffix == ".gz":
        return stack.enter_context(gzip.open(path, "rt", encoding="utf-8", errors="replace"))
    return stack.enter_context(path.open(encoding="utf-8", errors="replace"))


def read_lines(paths: list[Path]) -> Iterator[str]:
    if not paths:
        yield from sys.stdin
        return
    for path in paths:
        with ExitStack() as stack:
            yield from open_log(path, stack)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="nginx-insights",
        description="Summarise nginx access logs (combined format). Reads stdin when no files are given.",
    )
    parser.add_argument("logs", nargs="*", type=Path, help="access logs, .gz files are read directly")
    parser.add_argument("--top", type=int, default=10, help="rows per top-N list (default: 10)")
    parser.add_argument("--burst-threshold", type=int, default=300, help="requests per window that count as a burst")
    parser.add_argument("--burst-window", type=int, default=60, help="burst window in seconds (default: 60)")
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)

    missing = [str(path) for path in args.logs if not path.is_file()]
    if missing:
        print(f"not found: {', '.join(missing)}", file=sys.stderr)
        return 2

    reader = LogReader()
    analyzers = default_analyzers(args.top, args.burst_threshold, timedelta(seconds=args.burst_window))
    report = analyze(reader.entries(read_lines(args.logs)), analyzers)

    print(render_json(report) if args.json else render_text(report))
    if reader.skipped_lines:
        print(f"\nskipped {reader.skipped_lines} lines that are not in combined format", file=sys.stderr)
    return 0
