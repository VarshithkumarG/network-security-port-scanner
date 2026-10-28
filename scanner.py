#!/usr/bin/env python3
"""A small, bounded TCP port scanner for authorized lab use."""
import argparse
import concurrent.futures
import ipaddress
import socket

COMMON = [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8000, 8080, 8443]


def parse_ports(spec):
    ports = set()
    for item in spec.split(","):
        if not item.strip():
            continue
        if "-" in item:
            parts = item.split("-")
            if len(parts) != 2:
                raise ValueError(f"Invalid port range: {item}")
            start, end = map(int, parts)
            if start > end:
                raise ValueError(f"Range must ascend: {item}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(item))
    if not ports or min(ports) < 1 or max(ports) > 65535 or len(ports) > 2048:
        raise ValueError("Choose 1–2048 ports in the valid range 1–65535.")
    return sorted(ports)


def scan_one(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port, "open"
    except ConnectionRefusedError:
        return port, "closed"
    except (TimeoutError, OSError):
        return port, "filtered/unknown"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", help="authorized hostname or IP address")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ports", help="comma-separated ports/ranges, e.g. 22,80,8000-8010")
    group.add_argument("--common", action="store_true", help="scan a short common-port list")
    parser.add_argument("--timeout", type=float, default=0.5, help="connection timeout (0.1–3 seconds)")
    args = parser.parse_args()
    try:
        if args.timeout < .1 or args.timeout > 3:
            raise ValueError("Timeout must be between 0.1 and 3 seconds.")
        socket.getaddrinfo(args.target, None)
        ports = COMMON if args.common else parse_ports(args.ports)
        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
            results = sorted(pool.map(lambda p: scan_one(args.target, p, args.timeout), ports))
        print(f"Results for {args.target} ({len(results)} ports)")
        for port, state in results:
            print(f"{port:5}  {state}")
    except (ValueError, OSError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()

