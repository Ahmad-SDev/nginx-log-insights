import json
from typing import Any

Report = dict[str, dict[str, Any]]


def render_json(report: Report) -> str:
    return json.dumps(report, indent=2)


def render_text(report: Report) -> str:
    sections = [_render_section(title, result) for title, result in report.items()]
    return "\n\n".join(section for section in sections if section)


def _render_section(title: str, result: dict[str, Any]) -> str:
    heading = f"== {title} =="

    if "top" in result:
        rows = [(str(row["requests"]), row["value"]) for row in result["top"]]
        return _with_rows(heading, rows)

    if "clients" in result:
        rows = [
            (str(row["peak_requests"]), f"{row['remote_addr']}  (from {row['started_at']})")
            for row in result["clients"]
        ]
        note = f"more than {result['threshold']} requests in {result['window_seconds']}s"
        return _with_rows(f"{heading}  {note}", rows)

    if "minutes" in result:
        rows = [
            (f"{row['error_rate']:.1%}", f"{row['minute']}  {row['server_errors']}/{row['requests']} requests")
            for row in result["minutes"]
        ]
        return _with_rows(f"{heading}  above {result['max_error_rate']:.0%}", rows)

    lines = [heading] + [f"{key:<15} {_format_value(value)}" for key, value in result.items()]
    return "\n".join(lines)


def _with_rows(heading: str, rows: list[tuple[str, str]]) -> str:
    if not rows:
        return f"{heading}\nnone"
    width = max(len(count) for count, _ in rows)
    return "\n".join([heading] + [f"{count:>{width}}  {label}" for count, label in rows])


def _format_value(value: Any) -> str:
    if isinstance(value, dict):
        return "  ".join(f"{key}: {count}" for key, count in value.items())
    if isinstance(value, int):
        return f"{value:,}"
    return str(value)
