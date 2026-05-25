#!/usr/bin/env python3
"""
bridge.py - HTTP <-> CE pipe bridge for browser userscripts.

    browser userscript ──fetch()──> bridge.py ──named pipe──> ce_mcp_bridge.lua

Routes:
    POST /api      JSON-RPC 2.0 forwarded to the CE pipe
    GET  /health   {"connected": bool, "last_ok_age_s": float|null, ...}
    OPTIONS *      CORS preflight (incl. Chrome Private Network Access)

Pipe:  \\\\.\\pipe\\CE_MCP_Bridge_v99
Wire:  [4-byte LE length][UTF-8 JSON body]   (matches ce_mcp_bridge.lua)

    py -m pip install pywin32
    py bridge.py
"""

import argparse
import json
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import win32file
    import pywintypes
except ImportError:
    sys.stderr.write("ERROR: pywin32 is required.  py -m pip install pywin32\n")
    sys.exit(1)

PIPE_NAME          = r"\\.\pipe\CE_MCP_Bridge_v99"
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_REQUEST_BYTES  = 16 * 1024 * 1024
DEFAULT_TIMEOUT_S  = 60

# Reconnect tuning - matches the Lua bridge's pipe-recycle window
# (Lua sleep(50) between accept() iterations means we may briefly find no listener)
CONNECT_RETRIES    = 5      # how many times to retry CreateFile
CONNECT_BACKOFF_S  = 0.05   # wait between attempts; doubles each time, capped at 0.4s
CONNECT_MAX_BACKOFF = 0.4

# Liveness tracking - probes the pipe in the background so /health is accurate
PROBE_INTERVAL_S   = 5.0
LIVENESS_WINDOW_S  = 12.0
PROBE_TIMEOUT_S    = 3.0

# ----------------------------------------------------------------------------
# Pipe client - persistent connection, thread-safe, auto-reconnect, live-checked
# ----------------------------------------------------------------------------

class PipeClient:
    def __init__(self):
        self._handle = None
        self._lock = threading.Lock()
        self._auto_id = 1
        self._auto_id_lock = threading.Lock()
        self._last_ok_ts = 0.0
        self._last_err = None
        self._stop = threading.Event()
        self._prober = None

    # -- low-level open ---------------------------------------------------------

    def _open_once(self):
        try:
            self._handle = win32file.CreateFile(
                PIPE_NAME,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0, None, win32file.OPEN_EXISTING, 0, None,
            )
            return True
        except pywintypes.error as e:
            self._handle = None
            self._last_err = f"connect failed: {e}"
            return False

    def connect(self, retries=CONNECT_RETRIES, backoff_s=CONNECT_BACKOFF_S):
        """Open the pipe with backoff retry. The Lua bridge cycles its pipe
        instance briefly between connections (50ms sleep) - if we hit that
        window we retry instead of giving up immediately."""
        delay = backoff_s
        for attempt in range(retries):
            if self._open_once():
                return True
            if attempt < retries - 1:
                time.sleep(delay)
                delay = min(delay * 2, CONNECT_MAX_BACKOFF)
        return False

    def close(self):
        if self._handle is not None:
            try: win32file.CloseHandle(self._handle)
            except Exception: pass
            self._handle = None

    def is_alive(self):
        return self._handle is not None and (time.time() - self._last_ok_ts) < LIVENESS_WINDOW_S

    def last_ok_age(self):
        if self._last_ok_ts == 0.0:
            return None
        return round(time.time() - self._last_ok_ts, 2)

    # -- background prober ------------------------------------------------------

    def start_prober(self):
        if self._prober is None or not self._prober.is_alive():
            self._stop.clear()
            self._prober = threading.Thread(target=self._probe_loop,
                                            daemon=True, name="ce-prober")
            self._prober.start()

    def stop_prober(self):
        self._stop.set()
        if self._prober:
            self._prober.join(timeout=1.5)

    def _probe_loop(self):
        while not self._stop.wait(PROBE_INTERVAL_S):
            if (time.time() - self._last_ok_ts) < (PROBE_INTERVAL_S * 0.8):
                continue
            try:
                self.call({"jsonrpc": "2.0", "method": "ping", "id": 0},
                          timeout_s=PROBE_TIMEOUT_S)
            except Exception:
                pass

    # -- helpers ----------------------------------------------------------------

    def _next_id(self):
        with self._auto_id_lock:
            v = self._auto_id
            self._auto_id += 1
            return v

    def _read_exact(self, n, deadline):
        buf = b""
        while len(buf) < n:
            if time.time() > deadline:
                raise TimeoutError("pipe read timed out")
            _, chunk = win32file.ReadFile(self._handle, n - len(buf))
            if not chunk:
                raise ConnectionError("EOF from CE pipe")
            buf += chunk
        return buf

    # -- main entry point -------------------------------------------------------

    def call(self, request_obj, timeout_s=DEFAULT_TIMEOUT_S):
        if not isinstance(request_obj, dict):
            raise ValueError("request must be a JSON object")
        if "id" not in request_obj or request_obj["id"] is None:
            request_obj["id"] = self._next_id()
        request_obj.setdefault("jsonrpc", "2.0")

        body   = json.dumps(request_obj, ensure_ascii=False).encode("utf-8")
        framed = struct.pack("<I", len(body)) + body

        deadline = time.time() + timeout_s
        last_err = None

        with self._lock:
            for attempt in range(3):  # up to 3 write attempts with reconnect between
                if self._handle is None:
                    # Use the configured retry window; remaining time = whatever's left of budget
                    remaining = max(0.5, deadline - time.time())
                    # Cap connect retries by remaining time
                    if not self.connect():
                        self._last_err = (
                            f"cannot open {PIPE_NAME} - is Cheat Engine running "
                            "with ce_mcp_bridge.lua loaded?"
                        )
                        if time.time() > deadline:
                            raise ConnectionError(self._last_err)
                        # Brief wait, try again
                        time.sleep(0.1)
                        continue
                try:
                    win32file.WriteFile(self._handle, framed)
                    hdr = self._read_exact(4, deadline)
                    resp_len = struct.unpack("<I", hdr)[0]
                    if resp_len <= 0 or resp_len > MAX_RESPONSE_BYTES:
                        raise ConnectionError(f"bad response length: {resp_len}")
                    body_buf = self._read_exact(resp_len, deadline)
                    result = json.loads(body_buf.decode("utf-8", errors="replace"))
                    self._last_ok_ts = time.time()
                    self._last_err = None
                    return result
                except (pywintypes.error, ConnectionError, TimeoutError) as e:
                    last_err = e
                    self.close()
                    if time.time() > deadline:
                        break

        self._last_err = f"CE pipe I/O failed: {last_err}"
        raise ConnectionError(self._last_err)


PIPE = PipeClient()

# ----------------------------------------------------------------------------
# HTTP layer
# ----------------------------------------------------------------------------

CORS_HEADERS = (
    ("Access-Control-Allow-Origin",          "*"),
    ("Access-Control-Allow-Methods",         "POST, GET, OPTIONS"),
    ("Access-Control-Allow-Headers",         "Content-Type"),
    ("Access-Control-Allow-Private-Network", "true"),
    ("Access-Control-Max-Age",               "86400"),
    ("Vary",                                 "Origin"),
)

def _send(handler, status, body=b"", content_type="application/json"):
    if isinstance(body, str):
        body = body.encode("utf-8")
    handler.send_response(status)
    for k, v in CORS_HEADERS:
        handler.send_header(k, v)
    handler.send_header("Content-Type",   content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control",  "no-store")
    handler.end_headers()
    if body:
        handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    server_version = "ce_bridge"
    sys_version    = ""

    def log_message(self, fmt, *args):
        sys.stderr.write("[bridge] " + (fmt % args) + "\n")

    def do_OPTIONS(self):
        _send(self, 204)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/health":
            payload = json.dumps({
                "service":       "ce_bridge",
                "pipe":          PIPE_NAME,
                "connected":     PIPE.is_alive(),
                "last_ok_age_s": PIPE.last_ok_age(),
                "last_error":    PIPE._last_err,
            }).encode("utf-8")
            _send(self, 200, payload)
            return
        _send(self, 404, b'{"error":"not found"}')

    def do_POST(self):
        if self.path != "/api":
            _send(self, 404, b'{"error":"not found - use POST /api"}')
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_REQUEST_BYTES:
            _send(self, 400, b'{"error":"missing or oversized Content-Length"}')
            return

        try:
            raw = self.rfile.read(length)
            req = json.loads(raw.decode("utf-8"))
        except Exception as e:
            err = {"jsonrpc": "2.0", "id": None,
                   "error": {"code": -32700, "message": f"parse error: {e}"}}
            _send(self, 400, json.dumps(err).encode("utf-8"))
            return

        try:
            if isinstance(req, list):
                results = [PIPE.call(r) for r in req]
                _send(self, 200, json.dumps(results).encode("utf-8"))
            else:
                resp = PIPE.call(req)
                _send(self, 200, json.dumps(resp).encode("utf-8"))
        except Exception as e:
            err = {"jsonrpc": "2.0",
                   "id": req.get("id") if isinstance(req, dict) else None,
                   "error": {"code": -32000, "message": str(e)}}
            _send(self, 502, json.dumps(err).encode("utf-8"))


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="HTTP <-> Cheat Engine pipe bridge")
    ap.add_argument("--host", default="127.0.0.1", help="HTTP bind host (default 127.0.0.1)")
    ap.add_argument("--port", default=9999, type=int, help="HTTP bind port (default 9999)")
    args = ap.parse_args()

    print(f"ce_bridge -> http://{args.host}:{args.port}/api")
    print(f"            pipe: {PIPE_NAME}")

    if PIPE.connect():
        try:
            PIPE.call({"jsonrpc": "2.0", "method": "ping", "id": 0}, timeout_s=3)
            print("            pipe: CONNECTED (verified)")
        except Exception as e:
            print(f"            pipe: handle opened but CE didn't respond ({e})")
            print("                  -> is the Lua script actually running in CE?")
    else:
        print("            pipe: not connected (will retry on first request)")
        print("                  -> open Cheat Engine and execute ce_mcp_bridge.lua")

    PIPE.start_prober()
    print(f"            prober: pings every {PROBE_INTERVAL_S:.0f}s when idle")
    print(f"            reconnect: up to {CONNECT_RETRIES} attempts with backoff")
    print("Ready. Ctrl+C to stop.\n")

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[bridge] shutting down")
    finally:
        server.server_close()
        PIPE.stop_prober()
        PIPE.close()


if __name__ == "__main__":
    main()