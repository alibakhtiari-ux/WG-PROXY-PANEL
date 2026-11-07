"""ctl.sock — panel → nqmo requests (JSON-lines, one request per connection).

Only uid 0 (the panel) is accepted, via SO_PEERCRED. Requests are size-capped,
schema-checked and time-limited. The server thread never runs request logic
itself: it hands (request, reply-queue) to the main loop, which owns the
store — a SQLite connection must never be shared across threads (review
round 2, B1). Ops: mode.get, mode.set (one step at a time),
ack, probe. `probe` is answered by the engine, which applies every gate of
design 04 §7 and refuses with a reason code otherwise.
"""
import json
import os
import queue
import re
import socket
import struct
import threading

from .config import MODES, adjacent_mode

MAX_REQ = 64 * 1024
ACTOR_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,64}$")
SCHEMAS = {
    "mode.get": {"v", "op"},
    "mode.set": {"v", "op", "to", "actor"},
    "ack": {"v", "op", "id", "actor"},
    "probe": {"v", "op", "peer", "actor"},
}


def validate_request(req):
    """→ None if valid, else an error code string."""
    if not isinstance(req, dict) or req.get("v") != 1:
        return "BAD_VERSION"
    op = req.get("op")
    if op not in SCHEMAS:
        return "UNKNOWN_OP"
    if set(req) != SCHEMAS[op]:
        return "BAD_FIELDS"
    if "actor" in req and not (isinstance(req["actor"], str) and ACTOR_RE.match(req["actor"])):
        return "BAD_ACTOR"
    if op == "mode.set" and req["to"] not in MODES:
        return "BAD_MODE"
    if op == "ack" and (isinstance(req["id"], bool) or not isinstance(req["id"], int)
                        or req["id"] <= 0):
        return "BAD_ID"
    if op == "probe" and not (isinstance(req["peer"], str) and 0 < len(req["peer"]) <= 64):
        return "BAD_PEER"
    return None


class Handler:
    """Pure request logic (no sockets) — the engine supplies the callbacks."""

    def __init__(self, get_mode, set_mode, ack, probe=None):
        self.get_mode = get_mode
        self.set_mode = set_mode
        self.ack = ack
        self.probe = probe

    def handle(self, req):
        err = validate_request(req)
        if err:
            return {"ok": False, "refused": err}
        op = req["op"]
        if op == "mode.get":
            return {"ok": True, "mode": self.get_mode()}
        if op == "mode.set":
            cur = self.get_mode()
            if not adjacent_mode(cur, req["to"]):
                return {"ok": False, "refused": "NOT_ADJACENT"}
            self.set_mode(req["to"], req["actor"])
            return {"ok": True, "mode": req["to"]}
        if op == "ack":
            return ({"ok": True} if self.ack(req["id"], req["actor"])
                    else {"ok": False, "refused": "NO_SUCH_OPEN_DIAGNOSIS"})
        if op == "probe":
            if self.probe is None:
                return {"ok": False, "refused": "NOT_AVAILABLE"}
            return self.probe(req["peer"], req["actor"])
        return {"ok": False, "refused": "UNKNOWN_OP"}


def peer_uid(conn):
    creds = conn.getsockopt(socket.SOL_SOCKET, getattr(socket, "SO_PEERCRED", 17),
                            struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", creds)
    return uid


class Server(threading.Thread):
    """Socket front-end. `requests` is a queue.Queue the main loop serves with
    serve_pending(); replies come back on a per-request queue."""

    REPLY_TIMEOUT = 5.0

    def __init__(self, path, requests, allowed_uid=0, uid_fn=peer_uid):
        super().__init__(name="nqmo-ctl", daemon=True)
        self.path = path
        self.requests = requests
        self.allowed_uid = allowed_uid
        self.uid_fn = uid_fn
        self.stop = threading.Event()
        self.heartbeat = 0.0
        self.error = ""

    def _dispatch(self, req):
        reply = queue.Queue(maxsize=1)
        try:
            self.requests.put_nowait((req, reply))
        except queue.Full:
            return {"ok": False, "refused": "BUSY"}
        try:
            return reply.get(timeout=self.REPLY_TIMEOUT)
        except queue.Empty:
            return {"ok": False, "refused": "TIMEOUT"}

    def run(self):
        import time
        # bind + listen on a side name, then rename: the path appears only once
        # it accepts. Bound in place, a client in the bind→listen gap got
        # ECONNREFUSED (lab, 28 Oct: under load, a request racing a restart).
        tmp = self.path + ".new"
        try:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            old = os.umask(0o177)
            try:
                srv.bind(tmp)
            finally:
                os.umask(old)
            srv.listen(4)
            os.replace(tmp, self.path)
            mine = os.stat(self.path).st_ino
        except OSError as e:
            self.error = "bind: %s" % e
            return
        srv.settimeout(1.0)
        while not self.stop.is_set():
            self.heartbeat = time.monotonic()
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                continue
            with conn:
                conn.settimeout(5.0)
                try:
                    if self.uid_fn(conn) != self.allowed_uid:
                        continue
                    data = b""
                    while b"\n" not in data and len(data) <= MAX_REQ:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    if len(data) > MAX_REQ:
                        resp = {"ok": False, "refused": "TOO_LARGE"}
                    else:
                        try:
                            req = json.loads(data.split(b"\n", 1)[0])
                        except ValueError:
                            req = None
                        resp = (self._dispatch(req) if req is not None
                                else {"ok": False, "refused": "BAD_JSON"})
                    conn.sendall((json.dumps(resp) + "\n").encode())
                except Exception as e:          # one bad client never kills the thread
                    self.error = ("%s: %s" % (type(e).__name__, e))[:200]
                    continue
        srv.close()
        # a dead socket file reads "refused", not "engine down": remove ours —
        # only ours (same inode), never one a later engine already put there
        try:
            if os.stat(self.path).st_ino == mine:
                os.unlink(self.path)
        except OSError:
            pass


def serve_pending(requests, handler, limit=16):
    """Main-thread side: answer queued requests. Returns how many."""
    n = 0
    while n < limit:
        try:
            req, reply = requests.get_nowait()
        except queue.Empty:
            break
        try:
            resp = handler.handle(req)
        except Exception as e:
            resp = {"ok": False, "refused": "INTERNAL", "error": type(e).__name__}
        try:
            reply.put_nowait(resp)
        except queue.Full:
            pass
        n += 1
    return n
