from nginx_log_insights.parser import LogReader, parse_line

LINE = (
    '203.0.113.7 - - [23/Nov/2026:10:15:32 +0000] "GET /wp-login.php?redirect=1 HTTP/1.1" 404 153 '
    '"-" "Mozilla/5.0 (compatible; scanner)"'
)


def test_parses_combined_format():
    entry = parse_line(LINE)

    assert entry.remote_addr == "203.0.113.7"
    assert entry.method == "GET"
    assert entry.path == "/wp-login.php"
    assert entry.status == 404
    assert entry.body_bytes == 153
    assert entry.user_agent == "Mozilla/5.0 (compatible; scanner)"
    assert entry.time.isoformat() == "2026-11-23T10:15:32+00:00"


def test_handles_dash_body_size_and_garbage_request_line():
    entry = parse_line('198.51.100.1 - - [23/Nov/2026:10:15:32 +0000] "\\x16\\x03\\x01" 400 - "-" "-"')

    assert entry.body_bytes == 0
    assert entry.method == "-"
    assert entry.status == 400


def test_reader_counts_unparseable_lines_but_not_blank_ones():
    reader = LogReader()

    entries = list(reader.entries([LINE, "not a log line", "", LINE]))

    assert len(entries) == 2
    assert reader.skipped_lines == 1
