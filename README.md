# nginx-log-insights

A quick look at what's hitting a web server, straight from the nginx access log. I wrote it for the "the site is slow / something is hammering us" moments where you want answers in seconds and don't have a full ELK stack on that box.

It reports:

- totals, bandwidth and status classes
- top clients, paths, 404 paths and user agents
- **request bursts**: clients that sent more than N requests inside any sliding time window (scrapers, brute force, small L7 floods)
- **5xx spikes**: minutes where the server error rate went above 5%, ignoring minutes with very little traffic

Python 3.11+, standard library only. Reads plain and `.gz` rotated logs, or stdin.

## Usage

```bash
pip install git+https://github.com/Ahmad-SDev/nginx-log-insights

nginx-insights /var/log/nginx/access.log /var/log/nginx/access.log.1.gz
nginx-insights access.log --top 5 --burst-threshold 120 --burst-window 30
nginx-insights access.log --since 15m          # only the last 15 minutes: what is hitting us right now?
tail -n 100000 access.log | nginx-insights --json | jq '.["Request bursts"]'
```

```
== Top 404 paths ==
812  /wp-login.php
809  /.env

== Request bursts ==  more than 300 requests in 60s
500  198.51.100.66  (from 2026-11-23T09:22:26+00:00)

== 5xx spikes ==  above 5%
22.9%  2026-11-23T09:11:00+00:00  60/262 requests
23.0%  2026-11-23T09:12:00+00:00  59/257 requests
```

Lines that aren't in nginx's default `combined` format are skipped and counted on stderr.

## Adding a report

Each section is an analyzer with `feed(entry)` and `result()`. Write a new class, add it to `default_analyzers()`, and the CLI, text and JSON output pick it up. For example, a "top referers" list is one line:

```python
TopValues("Top referers", lambda entry: entry.referer, top, include=lambda entry: entry.referer != "-")
```

Everything streams through once, so memory stays flat on large logs (the burst detector keeps only the current window per client).

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
