#!/usr/bin/env python3
"""Small HTTP bridge for the ScanSnap iX1300 PFU Wi-Fi protocol.

This is not a SANE backend. It is a local JSON bridge that keeps scanner
sessions open so we can incrementally map the protocol and later adapt it to
SANE or another frontend.
"""

from __future__ import annotations

import argparse
import json
import threading
import uuid
from dataclasses import asdict, dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional

from ix1300_proto import (
    AppIFSession,
    DeviceInfoReply,
    HostInfo,
    InquiryReply,
    ReserveReply,
    ScannerIFReply,
    TriggerPacket,
    XferDataReply,
    discover,
    guess_local_ip_for_target,
    guess_local_mac,
    monitor_trigger_once,
    scanner_inquiry,
    status_name,
)


@dataclass(slots=True)
class ManagedSession:
    session_id: str
    target_ip: str
    port2: int
    local_ip: str
    local_mac: str
    if_version: int
    trigger_port: int
    password: bytes
    timeout: float
    appif: AppIFSession
    reserve_reply: Optional[ReserveReply] = None

    def summary(self) -> dict[str, Any]:
        data = {
            "session_id": self.session_id,
            "target_ip": self.target_ip,
            "port2": self.port2,
            "local_ip": self.local_ip,
            "local_mac": self.local_mac,
            "if_version": self.if_version,
            "trigger_port": self.trigger_port,
            "connected": self.appif.sock is not None,
        }
        if self.reserve_reply is not None:
            data["reserve"] = reserve_reply_to_dict(self.reserve_reply)
        return data


def host_info_to_dict(info: HostInfo) -> dict[str, Any]:
    data = asdict(info)
    data["is_scanner"] = info.is_scanner
    return data


def reserve_reply_to_dict(reply: ReserveReply) -> dict[str, Any]:
    data = asdict(reply)
    data["status_name"] = status_name(reply.status)
    data["raw"] = reply.raw.hex()
    return data


def device_info_reply_to_dict(reply: DeviceInfoReply) -> dict[str, Any]:
    data = asdict(reply)
    data["status_name"] = status_name(reply.status)
    data["raw"] = reply.raw.hex()
    return data


def trigger_packet_to_dict(packet: TriggerPacket) -> dict[str, Any]:
    data = asdict(packet)
    data["sensor"] = packet.sensor.hex()
    data["raw"] = packet.raw.hex()
    return data


def xfer_data_reply_to_dict(reply: XferDataReply) -> dict[str, Any]:
    data = asdict(reply)
    data["status_name"] = status_name(reply.status)
    data["raw"] = reply.raw.hex()
    return data


def scanner_if_reply_to_dict(reply: ScannerIFReply) -> dict[str, Any]:
    data = asdict(reply)
    data["status_name"] = status_name(reply.status)
    data["raw"] = reply.raw.hex()
    return data


def inquiry_reply_to_dict(reply: InquiryReply) -> dict[str, Any]:
    data = asdict(reply)
    data["status_name"] = status_name(reply.status)
    data["fixed_block"] = reply.fixed_block.hex()
    data["extra_data"] = reply.extra_data.hex()
    data["raw"] = reply.raw.hex()
    return data


class BridgeState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: Dict[str, ManagedSession] = {}

    def create_session(
        self,
        *,
        target_ip: str,
        port2: int,
        local_ip: str,
        local_mac: str,
        if_version: int,
        trigger_port: int,
        password: str,
        timeout: float,
    ) -> ManagedSession:
        session_id = uuid.uuid4().hex
        appif = AppIFSession(target_ip=target_ip, port2=port2, local_ip=local_ip, timeout=timeout)
        appif.open()
        reserve_reply = appif.reserve(
            local_mac=local_mac,
            if_version=if_version,
            trigger_port=trigger_port,
            password=password.encode("utf-8"),
        )
        session = ManagedSession(
            session_id=session_id,
            target_ip=target_ip,
            port2=port2,
            local_ip=local_ip,
            local_mac=local_mac,
            if_version=if_version,
            trigger_port=trigger_port,
            password=password.encode("utf-8"),
            timeout=timeout,
            appif=appif,
            reserve_reply=reserve_reply,
        )
        with self._lock:
            self._sessions[session_id] = session
        return session

    def list_sessions(self) -> list[dict[str, Any]]:
        with self._lock:
            return [session.summary() for session in self._sessions.values()]

    def get_session(self, session_id: str) -> ManagedSession:
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            raise KeyError(session_id)
        return session

    def close_session(self, session_id: str) -> bool:
        with self._lock:
            session = self._sessions.pop(session_id, None)
        if session is None:
            return False
        session.appif.close()
        return True

    def close_all(self) -> None:
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            session.appif.close()


class BridgeHandler(BaseHTTPRequestHandler):
    server: "BridgeHTTPServer"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send_json({"ok": True, "service": "ix1300-bridge"})
            return
        if self.path == "/sessions":
            self._send_json({"sessions": self.server.state.list_sessions()})
            return
        self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        body = self._read_json_body()
        if body is None:
            return

        try:
            if self.path == "/discover":
                self._handle_discover(body)
                return
            if self.path == "/scanner-inquiry":
                self._handle_scanner_inquiry(body)
                return
            if self.path == "/sessions":
                self._handle_open_session(body)
                return
            if self.path.endswith("/device-info"):
                self._handle_device_info(body)
                return
            if self.path.endswith("/xfer-data"):
                self._handle_xfer_data(body)
                return
            if self.path == "/trigger/monitor-once":
                self._handle_monitor_trigger(body)
                return
        except KeyError as exc:
            self._send_json({"error": f"missing field: {exc.args[0]}"}, status=HTTPStatus.BAD_REQUEST)
            return
        except ValueError as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return
        except Exception as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def do_DELETE(self) -> None:
        if not self.path.startswith("/sessions/"):
            self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return
        session_id = self.path.split("/")[2]
        if self.server.state.close_session(session_id):
            self._send_json({"ok": True, "session_id": session_id})
            return
        self._send_json({"error": "unknown session"}, status=HTTPStatus.NOT_FOUND)

    def _handle_discover(self, body: dict[str, Any]) -> None:
        target_ip = body.get("target_ip")
        local_ip = body.get("local_ip") or guess_local_ip_for_target(target_ip or "255.255.255.255")
        local_mac = body.get("local_mac") or guess_local_mac()
        listen_port = int(body.get("listen_port", 40000))
        timeout = float(body.get("timeout", 2.0))

        hosts = discover(
            local_ip=local_ip,
            local_mac=local_mac,
            listen_port=listen_port,
            timeout=timeout,
            target_ip=target_ip,
        )
        self._send_json(
            {
                "local_ip": local_ip,
                "local_mac": local_mac,
                "hosts": [host_info_to_dict(host) for host in hosts],
            }
        )

    def _handle_open_session(self, body: dict[str, Any]) -> None:
        session = self.server.state.create_session(
            target_ip=body["target_ip"],
            port2=int(body["port2"]),
            local_ip=body["local_ip"],
            local_mac=body["local_mac"],
            if_version=int(body["if_version"], 0) if isinstance(body["if_version"], str) else int(body["if_version"]),
            trigger_port=int(body.get("trigger_port", 40000)),
            password=str(body.get("password", "")),
            timeout=float(body.get("timeout", 30.0)),
        )
        self._send_json(
            {
                "session": session.summary(),
                "reserve": reserve_reply_to_dict(session.reserve_reply) if session.reserve_reply else None,
            },
            status=HTTPStatus.CREATED,
        )

    def _handle_scanner_inquiry(self, body: dict[str, Any]) -> None:
        ack, reply = scanner_inquiry(
            target_ip=body["target_ip"],
            port1=int(body["port1"]),
            local_ip=body["local_ip"],
            local_mac=body["local_mac"],
            inquiry_status=int(body.get("inquiry_status", 0)),
            timeout=float(body.get("timeout", 30.0)),
        )
        self._send_json(
            {
                "scanner_if_ack": scanner_if_reply_to_dict(ack),
                "inquiry": inquiry_reply_to_dict(reply),
            }
        )

    def _handle_device_info(self, body: dict[str, Any]) -> None:
        parts = self.path.strip("/").split("/")
        if len(parts) != 3 or parts[0] != "sessions" or parts[2] != "device-info":
            self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return
        session = self.server.state.get_session(parts[1])
        reply = session.appif.get_device_info(local_mac=session.local_mac)
        self._send_json({"device_info": device_info_reply_to_dict(reply), "session": session.summary()})

    def _handle_monitor_trigger(self, body: dict[str, Any]) -> None:
        local_ip = body["local_ip"]
        trigger_port = int(body.get("trigger_port", 40000))
        timeout = float(body.get("timeout", 30.0))
        packet = monitor_trigger_once(local_ip=local_ip, trigger_port=trigger_port, timeout=timeout)
        self._send_json({"trigger": trigger_packet_to_dict(packet)})

    def _handle_xfer_data(self, body: dict[str, Any]) -> None:
        parts = self.path.strip("/").split("/")
        if len(parts) != 3 or parts[0] != "sessions" or parts[2] != "xfer-data":
            self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return
        session = self.server.state.get_session(parts[1])
        payload_hex = str(body.get("payload_hex", ""))
        payload = bytes.fromhex(payload_hex) if payload_hex else b""
        reply = session.appif.xfer_data(
            local_mac=session.local_mac,
            xfer_status=int(body["xfer_status"], 0) if isinstance(body["xfer_status"], str) else int(body["xfer_status"]),
            total_length=int(body["total_length"]),
            offset=int(body.get("offset", 0)),
            payload=payload,
        )
        self._send_json({"xfer_data": xfer_data_reply_to_dict(reply), "session": session.summary()})

    def _read_json_body(self) -> Optional[dict[str, Any]]:
        content_length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(content_length) if content_length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            self._send_json({"error": f"invalid JSON: {exc}"}, status=HTTPStatus.BAD_REQUEST)
            return None
        if not isinstance(payload, dict):
            self._send_json({"error": "JSON body must be an object"}, status=HTTPStatus.BAD_REQUEST)
            return None
        return payload

    def _send_json(self, payload: dict[str, Any], *, status: HTTPStatus = HTTPStatus.OK) -> None:
        data = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class BridgeHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], handler_class: type[BaseHTTPRequestHandler], state: BridgeState):
        super().__init__(server_address, handler_class)
        self.state = state


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1", help="HTTP bind address")
    parser.add_argument("--port", type=int, default=18080, help="HTTP bind port")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    state = BridgeState()
    server = BridgeHTTPServer((args.bind, args.port), BridgeHandler, state)
    try:
        print(f"ix1300 bridge listening on http://{args.bind}:{args.port}")
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        state.close_all()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
