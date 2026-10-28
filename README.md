# Network Security Port Scanner

A bounded TCP connect scanner for hosts and services you own or are authorized to assess.

## Problem and objective

An inventory of reachable TCP services helps defenders identify unexpected exposure. This scanner demonstrates target validation, port selection, timeouts, concurrency limits, and clear open/closed/filtered results.

## Features

- Hostname or IP target; explicit single ports, ranges, or a built-in common-port set.
- Bounded worker pool and per-connection timeout.
- Reports open, closed, or filtered/unknown results without service exploitation.
- Input validation and clear error handling.

## Technology

Python 3.10+ standard library (`socket`, `argparse`, `concurrent.futures`).

## Setup and run

```bash
python scanner.py 127.0.0.1 --ports 22,80,443,8000-8010
python scanner.py example.test --common
```

Use only against systems you own or have explicit permission to test. Keep port ranges narrow and scanning rates low.

## How it works

The tool resolves the supplied host, then attempts TCP connections to the selected ports with a short timeout. A successful connection is reported open, a refusal as closed, and a timeout or network error as filtered/unknown. It does not send exploit payloads.

## Screenshots and demo

No screenshots or live demo are provided; run against a local service such as `python -m http.server 8000` and capture the result.

## Tests

Run `python -m unittest discover -s tests -v` from this repository root.

## Security considerations

Scanning can trigger alerts and may violate policy or law without authorization. Results are point-in-time and network filtering can make a port appear unknown. Do not scan broad public ranges.

## Future improvements

Add IPv6, structured JSON output, cancellation, and tests with local mock sockets.

