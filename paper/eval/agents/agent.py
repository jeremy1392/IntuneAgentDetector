"""Synthetic AI agent for the evaluation bench (standard library only).

It reproduces the observable footprint of an LLM agent on a Windows endpoint,
without any account or model call:

- a keep-alive HTTPS connection to an API endpoint, polled with an INVALID
  key (the server answers 401: no data is sent, nothing is billed);
- a persistent shell child that receives a harmless command at every poll,
  like the persistent shell of a coding agent, or one short-lived shell per
  tool call (--shell cmd-per-call), like agents that run each command as its
  own process;
- optionally a connection that is closed when idle (--keepalive), like a
  client whose pooled connections expire;
- optionally an MCP server child (npx), an automated browser child, a module
  named like an inference runtime, or a local LLM-style HTTP listener.

The same script with a non-LLM endpoint (for example https://api.github.com)
is the "behavioural twin" used as a benign control.

Usage:
  python agent.py --endpoint https://api.openai.com/v1/models --shell cmd
"""

import argparse
import ctypes
import http.client
import http.server
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.parse

CREATE_NO_WINDOW = 0x08000000


def parse_args():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--endpoint", default="https://api.openai.com/v1/models",
                   help="URL polled over a keep-alive HTTPS connection")
    p.add_argument("--interval", type=float, default=5.0, help="seconds between polls")
    p.add_argument("--duration", type=float, default=0, help="seconds to run, 0 = until stopped")
    p.add_argument("--shell", choices=["cmd", "powershell", "cmd-per-call", "none"], default="cmd",
                   help="persistent shell child fed one harmless command per poll, "
                        "or one short-lived cmd.exe per poll (cmd-per-call)")
    p.add_argument("--keepalive", type=float, default=0,
                   help="close the connection this many seconds after each poll (0 = keep it open)")
    p.add_argument("--mcp", metavar="DIR", help="start the reference MCP filesystem server on DIR as a child")
    p.add_argument("--browser", metavar="CHROME", help="start this Chrome headless with a remote debugging port")
    p.add_argument("--module", metavar="DLL", help="load this DLL (named like an inference runtime)")
    p.add_argument("--listen", type=int, metavar="PORT", help="serve a local LLM-style HTTP API on this port")
    p.add_argument("--no-network", action="store_true", help="do not open the HTTPS connection")
    return p.parse_args()


class Poller:
    """Keeps one HTTPS connection open and polls the endpoint with an invalid key."""

    def __init__(self, url):
        u = urllib.parse.urlsplit(url)
        self.tls = u.scheme != "http"
        self.host, self.port = u.hostname, u.port or (443 if self.tls else 80)
        self.path = (u.path or "/") + (("?" + u.query) if u.query else "")
        self.conn = None

    def poll(self):
        for _ in range(2):
            try:
                if self.conn is None:
                    cls = http.client.HTTPSConnection if self.tls else http.client.HTTPConnection
                    self.conn = cls(self.host, self.port, timeout=15)
                self.conn.request("GET", self.path, headers={
                    "Authorization": "Bearer sk-invalid-key-for-detection-research",
                    "User-Agent": "agent-detector-eval/1.0",
                    "Connection": "keep-alive",
                })
                r = self.conn.getresponse()
                r.read()
                if self.conn.sock is None:
                    # The server closed the connection (for example after a
                    # 401): open a warm one right away, as connection pools do.
                    self.conn.connect()
                return r.status
            except (OSError, http.client.HTTPException):
                self.close()
        return None

    def close(self):
        if self.conn is not None:
            try:
                self.conn.close()
            except OSError:
                pass
        self.conn = None


class LocalLLMHandler(http.server.BaseHTTPRequestHandler):
    """Answers like a local inference server would, with a fixed body."""

    def do_GET(self):
        body = b'{"models":[]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def popen(cmd, **kw):
    """Starts a hidden child process (no console window on Windows)."""
    if os.name == "nt":
        kw["creationflags"] = CREATE_NO_WINDOW
    return subprocess.Popen(cmd, **kw)


def start_children(args):
    children = []
    shell = None
    if args.shell not in ("none", "cmd-per-call"):
        if os.name != "nt":
            cmd = ["bash"]
        elif args.shell == "cmd":
            cmd = ["cmd.exe", "/Q", "/K"]
        else:
            cmd = ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"]
        shell = popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        children.append(shell)
    if args.mcp:
        npx = "npx.cmd" if os.name == "nt" else "npx"
        children.append(popen([npx, "-y", "@modelcontextprotocol/server-filesystem", args.mcp],
                              stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    if args.browser:
        profile = os.path.join(os.environ.get("TEMP", "."), "agent-eval-chrome-%d" % os.getpid())
        children.append(popen([args.browser, "--headless=new", "--remote-debugging-port=0", "--no-first-run",
                               "--user-data-dir=" + profile, "about:blank"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    return shell, children


def main():
    args = parse_args()
    if args.module:
        ctypes.WinDLL(os.path.abspath(args.module))
    if args.listen:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", args.listen), LocalLLMHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()

    shell, children = start_children(args)
    poller = None if args.no_network else Poller(args.endpoint)

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    deadline = time.time() + args.duration if args.duration > 0 else None
    calls = []
    print("agent pid %d running" % os.getpid(), flush=True)
    try:
        while not stop.is_set() and (deadline is None or time.time() < deadline):
            if poller is not None:
                poller.poll()
            if shell is not None and shell.poll() is None:
                try:
                    shell.stdin.write(b"echo tool-call\r\n" if os.name == "nt" else b"echo tool-call\n")
                    shell.stdin.flush()
                except OSError:
                    pass
            elif args.shell == "cmd-per-call":
                # One shell per tool call, alive for about one second.
                calls = [c for c in calls if c.poll() is None]
                calls.append(popen(["cmd.exe", "/c", "ping -n 2 127.0.0.1 >nul"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            if poller is not None and 0 < args.keepalive < args.interval:
                stop.wait(args.keepalive)
                poller.close()
                stop.wait(args.interval - args.keepalive)
            else:
                stop.wait(args.interval)
    finally:
        if poller is not None:
            poller.close()
        for c in children + calls:
            if c.poll() is None:
                c.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
