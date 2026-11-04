"""wazuh-logtest batch client - runs INSIDE the Wazuh manager container.

Reads one JSON request per line on stdin ({"event", "log_format", "location"}),
sends each through the logtest socket in its own session (so no state leaks from
one sample to the next) and prints one JSON result per line.
Uses only the standard library (executed with /var/ossec/framework/python).
"""
import json
import socket
import struct
import sys

SOCKET = "/var/ossec/queue/sockets/logtest"


def call(payload):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCKET)
    data = json.dumps(payload).encode()
    s.sendall(struct.pack("<I", len(data)) + data)
    header = b""
    while len(header) < 4:
        chunk = s.recv(4 - len(header))
        if not chunk:
            raise RuntimeError("logtest socket closed")
        header += chunk
    size = struct.unpack("<I", header)[0]
    body = b""
    while len(body) < size:
        chunk = s.recv(size - len(body))
        if not chunk:
            raise RuntimeError("logtest socket closed")
        body += chunk
    s.close()
    return json.loads(body.decode("utf-8", "replace"))


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    resp = call({"version": 1, "command": "log_processing", "parameters": req})
    data = resp.get("data", {})
    out = data.get("output", {})
    token = data.get("token")
    if token:
        try:
            call({"version": 1, "command": "remove_session", "parameters": {"token": token}})
        except Exception:
            pass
    print(json.dumps({
        "error": resp.get("error"),
        "messages": data.get("messages", []),
        "decoder": out.get("decoder", {}).get("name"),
        "rule": out.get("rule", {}),
        "data": out.get("data"),
    }))
    sys.stdout.flush()
