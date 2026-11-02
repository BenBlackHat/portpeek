#!/usr/bin/env python3
"""
PortPeek - a small multithreaded TCP port scanner with service/version detection.

Results are printed in real time as each port is checked.
Use ONLY on systems you own or have written permission to test.
"""

import argparse
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

__version__ = "1.0.0"

HTTP_PORTS = {80, 8000, 8008, 8080, 8888}
TLS_PORTS = {443, 8443}


class Color:
    """ANSI colors, disabled automatically when output is not a terminal."""
    on = sys.stdout.isatty()
    GREEN = "\033[92m" if on else ""
    RED = "\033[91m" if on else ""
    YELLOW = "\033[93m" if on else ""
    CYAN = "\033[96m" if on else ""
    BOLD = "\033[1m" if on else ""
    END = "\033[0m" if on else ""


def parse_ports(spec):
    """Turn '22,80,1000-1010' into a sorted list of port numbers."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = (int(x) for x in part.split("-", 1))
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    if not ports or any(p < 1 or p > 65535 for p in ports):
        raise ValueError("ports must be between 1 and 65535")
    return sorted(ports)


def service_name(port):
    """Look up the standard service name for a port (e.g. 22 -> ssh)."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def clean_banner(data):
    """Reduce raw bytes from a service into a short, readable version string."""
    text = data.decode("utf-8", errors="replace")
    if text.startswith("HTTP/"):
        for line in text.split("\r\n"):
            if line.lower().startswith("server:"):
                return "HTTP - " + line.split(":", 1)[1].strip()
        return text.split("\r\n")[0][:80]
    stripped = text.strip()
    if not stripped:
        return ""
    first_line = stripped.splitlines()[0]
    return "".join(ch for ch in first_line if ch.isprintable())[:80]


def grab_banner(sock, host, port, timeout):
    """Try to read an identifying banner from an open port."""
    try:
        sock.settimeout(timeout)
        if port in TLS_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        if port in HTTP_PORTS or port in TLS_PORTS:
            request = (
                f"HEAD / HTTP/1.0\r\nHost: {host}\r\n"
                "User-Agent: PortPeek\r\n\r\n"
            )
            sock.sendall(request.encode())
        try:
            data = sock.recv(1024)      # SSH, FTP, SMTP etc. speak first
        except socket.timeout:
            sock.sendall(b"\r\n")       # nudge services that wait for us
            data = sock.recv(1024)
        return clean_banner(data)
    except Exception:
        return ""
    finally:
        try:
            sock.close()
        except Exception:
            pass


def scan_port(ip, port, timeout):
    """Return (port, state, service, banner). State: open / closed / filtered."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except ConnectionRefusedError:
        return port, "closed", "", ""          # host answered: nothing listening
    except (socket.timeout, TimeoutError):
        return port, "filtered", "", ""        # no answer: likely firewalled
    except OSError:
        return port, "filtered", "", ""
    banner = grab_banner(sock, ip, port, timeout)
    return port, "open", service_name(port), banner


def print_row(port, state, service, banner):
    colors = {"open": Color.GREEN, "closed": Color.RED, "filtered": Color.YELLOW}
    color = colors[state]
    print(f"{port:<7}{color}{state:<10}{Color.END}{service:<14}{banner or '-'}",
          flush=True)


def main():
    parser = argparse.ArgumentParser(
        description="PortPeek: real-time TCP port scanner with service detection."
    )
    parser.add_argument("target", help="IP address or hostname to scan")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="ports to scan, e.g. 22,80,443 or 1-65535 (default: 1-1024)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                        help="seconds to wait per port (default: 1.0)")
    parser.add_argument("-w", "--workers", type=int, default=100,
                        help="number of parallel threads (default: 100)")
    parser.add_argument("--show-closed", action="store_true",
                        help="also print closed/filtered ports as they are found")
    parser.add_argument("-o", "--output", help="save open ports to this file")
    parser.add_argument("--version", action="version", version=f"PortPeek {__version__}")
    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as err:
        parser.error(f"invalid --ports value: {err}")

    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        sys.exit(f"Error: cannot resolve '{args.target}'")

    print(f"{Color.BOLD}PortPeek {__version__}{Color.END}")
    print(f"Target : {args.target} ({ip})")
    print(f"Ports  : {len(ports)}   Threads: {args.workers}   Timeout: {args.timeout}s")
    print(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    print(f"{Color.CYAN}{'PORT':<7}{'STATE':<10}{'SERVICE':<14}VERSION / BANNER{Color.END}")

    start = time.time()
    results = {"open": [], "closed": 0, "filtered": 0}

    executor = ThreadPoolExecutor(max_workers=args.workers)
    futures = [executor.submit(scan_port, ip, p, args.timeout) for p in ports]
    try:
        for future in as_completed(futures):
            port, state, service, banner = future.result()
            if state == "open":
                results["open"].append((port, service, banner))
                print_row(port, state, service, banner)
            else:
                results[state] += 1
                if args.show_closed:
                    print_row(port, state, "", "")
    except KeyboardInterrupt:
        print(f"\n{Color.YELLOW}Interrupted - stopping scan...{Color.END}")
        executor.shutdown(wait=False, cancel_futures=True)
    else:
        executor.shutdown()

    elapsed = time.time() - start
    results["open"].sort()
    print(f"\n{Color.BOLD}Done in {elapsed:.2f}s{Color.END} - "
          f"{Color.GREEN}{len(results['open'])} open{Color.END}, "
          f"{Color.RED}{results['closed']} closed{Color.END}, "
          f"{Color.YELLOW}{results['filtered']} filtered{Color.END}")

    if args.output:
        with open(args.output, "w") as f:
            f.write(f"# PortPeek results for {args.target} ({ip})\n")
            for port, service, banner in results["open"]:
                f.write(f"{port}\topen\t{service}\t{banner}\n")
        print(f"Open ports saved to {args.output}")


if __name__ == "__main__":
    main()
