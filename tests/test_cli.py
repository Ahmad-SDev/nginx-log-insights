import argparse
import gzip
import json
from datetime import datetime, timedelta, timezone

import pytest

from nginx_log_insights.cli import main, parse_duration

LINES = [
    '203.0.113.7 - - [23/Nov/2026:10:15:32 +0000] "GET / HTTP/1.1" 200 512 "-" "curl/8"',
    '203.0.113.7 - - [23/Nov/2026:10:15:33 +0000] "GET /missing HTTP/1.1" 404 10 "-" "curl/8"',
    "garbage",
]


def test_reads_plain_and_gzipped_logs_and_prints_json(tmp_path, capsys):
    plain = tmp_path / "access.log"
    plain.write_text("\n".join(LINES) + "\n")
    rotated = tmp_path / "access.log.1.gz"
    with gzip.open(rotated, "wt") as handle:
        handle.write(LINES[0] + "\n")

    assert main([str(plain), str(rotated), "--json"]) == 0

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["Summary"]["requests"] == 3
    assert report["Top 404 paths"]["top"] == [{"value": "/missing", "requests": 1}]
    assert "skipped 1 lines" in captured.err


def test_text_output_has_a_section_per_analyzer(tmp_path, capsys):
    log = tmp_path / "access.log"
    log.write_text(LINES[0] + "\n")

    main([str(log)])

    output = capsys.readouterr().out
    assert "== Summary ==" in output
    assert "== Request bursts ==" in output


def test_missing_file_exits_with_usage_error(tmp_path, capsys):
    assert main([str(tmp_path / "nope.log")]) == 2
    assert "not found" in capsys.readouterr().err


def test_since_keeps_only_recent_requests(tmp_path, capsys):
    recent = datetime.now(timezone.utc) - timedelta(minutes=2)
    log = tmp_path / "access.log"
    log.write_text(
        LINES[0] + "\n"  # 2026-11-23 10:15, long before the window
        + f'198.51.100.9 - - [{recent:%d/%b/%Y:%H:%M:%S %z}] "GET /now HTTP/1.1" 200 1 "-" "curl/8"\n'
    )

    assert main([str(log), "--since", "15m", "--json"]) == 0

    report = json.loads(capsys.readouterr().out)
    assert report["Summary"]["requests"] == 1


@pytest.mark.parametrize(("text", "expected"), [("90s", 90), ("15m", 900), ("2h", 7200), ("1d", 86400)])
def test_parse_duration(text, expected):
    assert parse_duration(text) == timedelta(seconds=expected)


@pytest.mark.parametrize("text", ["15", "0m", "1w", "abc"])
def test_parse_duration_rejects_bad_input(text):
    with pytest.raises(argparse.ArgumentTypeError):
        parse_duration(text)
