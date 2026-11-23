import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime

# nginx's default "combined" log_format
COMBINED_FORMAT = re.compile(
    r'(?P<remote_addr>\S+) \S+ (?P<remote_user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<body_bytes>\d+|-) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)
TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


@dataclass(frozen=True, slots=True)
class LogEntry:
    remote_addr: str
    time: datetime
    method: str
    path: str
    status: int
    body_bytes: int
    referer: str
    user_agent: str

    @property
    def is_server_error(self) -> bool:
        return self.status >= 500


def parse_line(line: str) -> LogEntry | None:
    match = COMBINED_FORMAT.match(line)
    if match is None:
        return None

    method, path = _split_request(match["request"])
    try:
        time = datetime.strptime(match["time"], TIME_FORMAT)
    except ValueError:
        return None

    return LogEntry(
        remote_addr=match["remote_addr"],
        time=time,
        method=method,
        path=path,
        status=int(match["status"]),
        body_bytes=0 if match["body_bytes"] == "-" else int(match["body_bytes"]),
        referer=match["referer"],
        user_agent=match["user_agent"],
    )


def _split_request(request: str) -> tuple[str, str]:
    parts = request.split(" ")
    if len(parts) < 2:
        return "-", request or "-"
    path = parts[1].split("?", 1)[0]
    return parts[0], path


class LogReader:
    """Parses lines and counts the ones that don't match the combined format."""

    def __init__(self) -> None:
        self.skipped_lines = 0

    def entries(self, lines: Iterable[str]) -> Iterator[LogEntry]:
        for line in lines:
            entry = parse_line(line)
            if entry is None:
                if line.strip():
                    self.skipped_lines += 1
                continue
            yield entry
