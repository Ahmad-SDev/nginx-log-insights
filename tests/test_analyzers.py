from datetime import datetime, timedelta, timezone

from nginx_log_insights.analyzers import BurstDetector, ErrorSpikeDetector, TopValues, TrafficSummary, analyze
from nginx_log_insights.parser import LogEntry

START = datetime(2026, 11, 23, 10, 0, tzinfo=timezone.utc)


def entry(addr="203.0.113.1", seconds=0, status=200, path="/", body_bytes=100):
    return LogEntry(
        remote_addr=addr,
        time=START + timedelta(seconds=seconds),
        method="GET",
        path=path,
        status=status,
        body_bytes=body_bytes,
        referer="-",
        user_agent="curl/8",
    )


def test_summary_counts_requests_bytes_and_status_classes():
    result = analyze([entry(status=200), entry(status=404), entry(status=502)], [TrafficSummary()])["Summary"]

    assert result["requests"] == 3
    assert result["bytes_sent"] == 300
    assert result["status_classes"] == {"2xx": 1, "4xx": 1, "5xx": 1}


def test_top_values_respects_filter_and_limit():
    entries = [entry(path="/a", status=404)] * 3 + [entry(path="/b", status=404)] + [entry(path="/c")] * 5
    top_404 = TopValues("404s", lambda e: e.path, limit=1, include=lambda e: e.status == 404)

    assert analyze(entries, [top_404])["404s"]["top"] == [{"value": "/a", "requests": 3}]


def test_burst_detector_flags_only_clients_over_threshold_inside_window():
    noisy = [entry("198.51.100.9", seconds=i * 0.1) for i in range(50)]
    steady = [entry("203.0.113.5", seconds=i * 10) for i in range(50)]

    result = analyze(noisy + steady, [BurstDetector(threshold=20, window=timedelta(seconds=10))])

    clients = result["Request bursts"]["clients"]
    assert [client["remote_addr"] for client in clients] == ["198.51.100.9"]
    assert clients[0]["peak_requests"] == 50


def test_burst_window_slides():
    spaced_out = [entry(seconds=i * 2) for i in range(30)]

    result = analyze(spaced_out, [BurstDetector(threshold=10, window=timedelta(seconds=10))])

    assert result["Request bursts"]["clients"] == []


def test_error_spike_detector_ignores_quiet_minutes():
    busy_bad_minute = [entry(seconds=i, status=500 if i < 10 else 200) for i in range(40)]
    quiet_bad_minute = [entry(seconds=120 + i, status=500) for i in range(3)]

    result = analyze(busy_bad_minute + quiet_bad_minute, [ErrorSpikeDetector(max_error_rate=0.05, min_requests=20)])

    minutes = result["5xx spikes"]["minutes"]
    assert len(minutes) == 1
    assert minutes[0]["server_errors"] == 10
