from collections import Counter, defaultdict, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol

from .parser import LogEntry


class Analyzer(Protocol):
    title: str

    def feed(self, entry: LogEntry) -> None: ...

    def result(self) -> dict[str, Any]: ...


class TrafficSummary:
    title = "Summary"

    def __init__(self) -> None:
        self._requests = 0
        self._bytes = 0
        self._status_classes: Counter[str] = Counter()
        self._first_seen: datetime | None = None
        self._last_seen: datetime | None = None

    def feed(self, entry: LogEntry) -> None:
        self._requests += 1
        self._bytes += entry.body_bytes
        self._status_classes[f"{entry.status // 100}xx"] += 1
        if self._first_seen is None or entry.time < self._first_seen:
            self._first_seen = entry.time
        if self._last_seen is None or entry.time > self._last_seen:
            self._last_seen = entry.time

    def result(self) -> dict[str, Any]:
        return {
            "requests": self._requests,
            "bytes_sent": self._bytes,
            "status_classes": dict(sorted(self._status_classes.items())),
            "first_seen": self._first_seen.isoformat() if self._first_seen else None,
            "last_seen": self._last_seen.isoformat() if self._last_seen else None,
        }


class TopValues:
    def __init__(
        self,
        title: str,
        key: Callable[[LogEntry], str],
        limit: int = 10,
        include: Callable[[LogEntry], bool] = lambda entry: True,
    ) -> None:
        self.title = title
        self._key = key
        self._limit = limit
        self._include = include
        self._counts: Counter[str] = Counter()

    def feed(self, entry: LogEntry) -> None:
        if self._include(entry):
            self._counts[self._key(entry)] += 1

    def result(self) -> dict[str, Any]:
        return {"top": [{"value": value, "requests": count} for value, count in self._counts.most_common(self._limit)]}


@dataclass
class _Burst:
    peak_requests: int
    started_at: datetime


class BurstDetector:
    """Flags clients that sent more than `threshold` requests inside any `window` of time."""

    title = "Request bursts"

    def __init__(self, threshold: int = 300, window: timedelta = timedelta(seconds=60)) -> None:
        self._threshold = threshold
        self._window = window
        self._recent: defaultdict[str, deque[datetime]] = defaultdict(deque)
        self._bursts: dict[str, _Burst] = {}

    def feed(self, entry: LogEntry) -> None:
        recent = self._recent[entry.remote_addr]
        recent.append(entry.time)
        while recent and entry.time - recent[0] > self._window:
            recent.popleft()

        if len(recent) <= self._threshold:
            return
        burst = self._bursts.get(entry.remote_addr)
        if burst is None:
            self._bursts[entry.remote_addr] = _Burst(peak_requests=len(recent), started_at=recent[0])
        elif len(recent) > burst.peak_requests:
            burst.peak_requests = len(recent)

    def result(self) -> dict[str, Any]:
        ranked = sorted(self._bursts.items(), key=lambda item: item[1].peak_requests, reverse=True)
        return {
            "threshold": self._threshold,
            "window_seconds": int(self._window.total_seconds()),
            "clients": [
                {"remote_addr": addr, "peak_requests": burst.peak_requests, "started_at": burst.started_at.isoformat()}
                for addr, burst in ranked
            ],
        }


@dataclass
class _MinuteStats:
    requests: int = 0
    server_errors: int = 0

    @property
    def error_rate(self) -> float:
        return self.server_errors / self.requests if self.requests else 0.0


class ErrorSpikeDetector:
    """Lists minutes where the 5xx rate went above `max_error_rate`, ignoring quiet minutes."""

    title = "5xx spikes"

    def __init__(self, max_error_rate: float = 0.05, min_requests: int = 20) -> None:
        self._max_error_rate = max_error_rate
        self._min_requests = min_requests
        self._minutes: defaultdict[datetime, _MinuteStats] = defaultdict(_MinuteStats)

    def feed(self, entry: LogEntry) -> None:
        stats = self._minutes[entry.time.replace(second=0, microsecond=0)]
        stats.requests += 1
        if entry.is_server_error:
            stats.server_errors += 1

    def result(self) -> dict[str, Any]:
        spikes = [
            {
                "minute": minute.isoformat(),
                "requests": stats.requests,
                "server_errors": stats.server_errors,
                "error_rate": round(stats.error_rate, 4),
            }
            for minute, stats in sorted(self._minutes.items())
            if stats.requests >= self._min_requests and stats.error_rate > self._max_error_rate
        ]
        return {"max_error_rate": self._max_error_rate, "minutes": spikes}


def default_analyzers(top: int, burst_threshold: int, burst_window: timedelta) -> list[Analyzer]:
    return [
        TrafficSummary(),
        TopValues("Top clients", lambda entry: entry.remote_addr, top),
        TopValues("Top paths", lambda entry: entry.path, top),
        TopValues("Top 404 paths", lambda entry: entry.path, top, include=lambda entry: entry.status == 404),
        TopValues("Top user agents", lambda entry: entry.user_agent or "-", top),
        BurstDetector(burst_threshold, burst_window),
        ErrorSpikeDetector(),
    ]


def analyze(entries: Iterable[LogEntry], analyzers: list[Analyzer]) -> dict[str, dict[str, Any]]:
    for entry in entries:
        for analyzer in analyzers:
            analyzer.feed(entry)
    return {analyzer.title: analyzer.result() for analyzer in analyzers}
