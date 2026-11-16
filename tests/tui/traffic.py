#!/usr/bin/env python3
"""Real traffic for the namespace lab, so the live view has something true to show.

  traffic.py serve <address> <port>      a web server: GET /<bytes> sends that many
                                         bytes, POST takes whatever it is sent
  traffic.py use <base-url> [seconds]    a device that downloads and uploads in
                                         bursts of changing size, until the time is up
  traffic.py knock <address> <port>...   something that keeps trying ports,
                                         which the box should block

`use` and `knock` take from=<address> as a last argument, to send from one
of the machine's addresses in particular.

Only the standard library. Nothing here is sent anywhere but the lab's own
namespaces.
"""

import http.client
import http.server
import random
import socket
import sys
import time
import urllib.parse

CHUNK = b"\0" * 16384


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            size = int(self.path.strip("/") or 0)
        except ValueError:
            size = 0
        self.send_response(200)
        self.send_header("Content-Length", str(size))
        self.end_headers()
        while size > 0:
            part = CHUNK[: min(size, len(CHUNK))]
            self.wfile.write(part)
            size -= len(part)

    def do_POST(self):
        left = int(self.headers.get("Content-Length", 0))
        while left > 0:
            left -= len(self.rfile.read(min(left, 65536)))
        self.send_response(204)
        self.end_headers()

    def log_message(self, *_):
        pass


def serve(address, port):
    http.server.ThreadingHTTPServer((address, int(port)), Handler).serve_forever()


def use(base, seconds, source):
    rng = random.Random(len(source or "") + 7)
    end = time.time() + seconds
    where = urllib.parse.urlsplit(base)
    bind = (source, 0) if source else None
    while time.time() < end:
        try:
            link = http.client.HTTPConnection(where.hostname, where.port, timeout=5, source_address=bind)
            # Mostly downloads, of very different sizes, with an upload now and then.
            if rng.random() < 0.75:
                size = int(rng.choice([40_000, 150_000, 400_000, 900_000]) * rng.uniform(0.5, 1.5))
                link.request("GET", f"/{size}")
                answer = link.getresponse()
                while answer.read(65536):
                    pass
            else:
                size = int(rng.choice([30_000, 120_000, 300_000]) * rng.uniform(0.5, 1.5))
                link.request("POST", "/", body=b"\0" * size)
                link.getresponse().read()
            link.close()
        except OSError:
            pass
        time.sleep(rng.uniform(0.05, 0.6))


def knock(address, ports, seconds, source):
    rng = random.Random(3)
    end = time.time() + seconds
    while time.time() < end:
        for port in ports:
            probe = socket.socket()
            probe.settimeout(0.3)
            try:
                if source:
                    probe.bind((source, 0))
                probe.connect((address, int(port)))
            except OSError:
                pass
            probe.close()
        time.sleep(rng.uniform(1.0, 4.0))


if __name__ == "__main__":
    what, args = sys.argv[1], sys.argv[2:]
    source = None
    if args and args[-1].startswith("from="):
        source = args.pop()[5:]
    if what == "serve":
        serve(*args)
    elif what == "use":
        use(args[0], float(args[1]) if len(args) > 1 else 3600, source)
    elif what == "knock":
        knock(args[0], args[1:], 3600, source)
    else:
        sys.exit(__doc__)
