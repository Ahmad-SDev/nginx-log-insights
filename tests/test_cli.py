import gzip
import json

from nginx_log_insights.cli import main

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
