#!/usr/bin/env python3
"""Background listener for iX1300 scan-button triggers."""

from __future__ import annotations

import argparse
import datetime as dt
import select
import socket
import sys
import time
from pathlib import Path
from typing import Optional, Tuple

import ix1300_proto as proto


TRIGGER_COMMAND_SCAN_PAPER = 0x01
TRIGGER_COMMAND_RELEASE_SCANNER_NORMAL = 0x10
TRIGGER_COMMAND_RELEASE_SCANNER_ENFORCE = 0x11
TRIGGER_COMMAND_RELEASE_SCANNER_ORDER = 0x12
TRIGGER_COMMAND_RELEASE_SCANNER_BATTERY_SAVE_MODE = 0x22

RELEASE_COMMANDS = {
    TRIGGER_COMMAND_RELEASE_SCANNER_NORMAL,
    TRIGGER_COMMAND_RELEASE_SCANNER_ENFORCE,
    TRIGGER_COMMAND_RELEASE_SCANNER_ORDER,
    TRIGGER_COMMAND_RELEASE_SCANNER_BATTERY_SAVE_MODE,
}


def log(message: str) -> None:
    timestamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}", flush=True)


def parse_paper_handling(value: str) -> int:
    normalized = value.strip().lower()
    if normalized in {"1", "uturn", "u-turn"}:
        return 1
    if normalized in {"2", "return"}:
        return 2
    raise argparse.ArgumentTypeError("paper handling must be 1|2|uturn|return")


def parse_start_mode(value: str) -> int:
    normalized = value.strip().lower()
    if normalized in {"0", "normal"}:
        return 0
    if normalized in {"1", "quick"}:
        return 1
    raise argparse.ArgumentTypeError("start mode must be normal|quick|0|1")


def resolve_scanner(
    *,
    target_ip: Optional[str],
    port1: Optional[int],
    port2: Optional[int],
    local_ip: str,
    local_mac: str,
    trigger_port: int,
    discover_timeout: float,
) -> Tuple[str, int, int]:
    if target_ip is not None and port1 is not None and port2 is not None:
        return target_ip, port1, port2

    hosts = proto.discover(
        local_ip=local_ip,
        local_mac=local_mac,
        listen_port=trigger_port,
        timeout=discover_timeout,
        target_ip=target_ip,
    )
    scanners = [host for host in hosts if host.is_scanner]
    if not scanners:
        raise RuntimeError("discovery found no scanners")
    if port1 is None:
        port1 = scanners[0].port1
    if port2 is None:
        port2 = scanners[0].port2
    if target_ip is None:
        target_ip = scanners[0].ip_address
    return target_ip, port1, port2


class TriggerListener:
    def __init__(self, *, local_ip: str, trigger_port: int, timeout: float) -> None:
        self.local_ip = local_ip
        self.trigger_port = trigger_port
        self.timeout = timeout
        self.tcp_server: Optional[socket.socket] = None
        self.udp_sock: Optional[socket.socket] = None

    def __enter__(self) -> "TriggerListener":
        self.open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def open(self) -> None:
        if self.tcp_server is not None or self.udp_sock is not None:
            return

        tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_server.bind((self.local_ip, self.trigger_port))
        tcp_server.listen(4)
        tcp_server.setblocking(False)

        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_sock.bind((self.local_ip, self.trigger_port))
        udp_sock.setblocking(False)

        self.tcp_server = tcp_server
        self.udp_sock = udp_sock

    def close(self) -> None:
        if self.tcp_server is not None:
            self.tcp_server.close()
            self.tcp_server = None
        if self.udp_sock is not None:
            self.udp_sock.close()
            self.udp_sock = None

    def wait(self) -> tuple[proto.TriggerPacket, str]:
        if self.tcp_server is None or self.udp_sock is None:
            raise RuntimeError("trigger listener is not open")

        ready, _, _ = select.select([self.tcp_server, self.udp_sock], [], [], self.timeout)
        if not ready:
            raise TimeoutError("timed out waiting for scanner trigger")

        if self.udp_sock in ready:
            packet, addr = self.udp_sock.recvfrom(2048)
            trigger = proto.parse_trigger_packet(packet)
            try:
                self.udp_sock.sendto(proto.build_trigger_answer(), addr)
            except OSError:
                pass
            return trigger, "udp"

        conn, _addr = self.tcp_server.accept()
        with conn:
            conn.settimeout(self.timeout)
            conn.sendall(proto.build_trigger_ack())
            packet = proto.recv_frame(conn)
            trigger = proto.parse_trigger_packet(packet)
            conn.sendall(proto.build_trigger_answer())
            return trigger, "tcp"


def make_output_pattern(output_dir: Path, prefix: str) -> str:
    scan_stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = output_dir / f"{prefix}_{scan_stamp}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return str(run_dir / "page_{page}.jpg")


def run_service(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    scan_params = proto.build_default_scan_params(
        color_mode=args.color_mode,
        quality=args.quality,
        paper_size=args.paper_size,
        paper_handling=args.paper_handling,
        del_white_page=args.del_white_page,
        bleed_through_reduction=args.bleed_through_reduction,
        ix1300_paper_protection=args.paper_protection,
    )

    with TriggerListener(local_ip=args.local_ip, trigger_port=args.trigger_port, timeout=args.idle_timeout) as listener:
        while True:
            try:
                scanner_ip, port1, port2 = resolve_scanner(
                    target_ip=args.target_ip,
                    port1=args.port1,
                    port2=args.port2,
                    local_ip=args.local_ip,
                    local_mac=args.local_mac,
                    trigger_port=args.trigger_port,
                    discover_timeout=args.discover_timeout,
                )
                log(f"scanner={scanner_ip} port1={port1} port2={port2} reserving")
                with proto.AppIFSession(
                    target_ip=scanner_ip,
                    port2=port2,
                    local_ip=args.local_ip,
                    timeout=args.timeout,
                ) as app_session:
                    reserve_reply = app_session.reserve(
                        local_mac=args.local_mac,
                        if_version=args.if_version,
                        trigger_port=args.trigger_port,
                        password=args.password.encode("utf-8"),
                    )
                    if not reserve_reply.ok:
                        raise RuntimeError(f"reserve failed with status {reserve_reply.status}")
                    start_mode_reply = app_session.set_start_mode(
                        local_mac=args.local_mac,
                        start_mode=args.start_mode,
                    )
                    if not start_mode_reply.ok:
                        raise RuntimeError(f"set start mode failed with status {start_mode_reply.status}")
                    log(f"reserve ok; start_mode={args.start_mode}; waiting for trigger")

                    while True:
                        try:
                            trigger, transport = listener.wait()
                        except TimeoutError:
                            continue

                        log(
                            f"trigger transport={transport} cmd=0x{trigger.cmd:08X} "
                            f"sequence={trigger.sequence_id} sensor={trigger.sensor.hex()}"
                        )

                        if trigger.cmd == TRIGGER_COMMAND_SCAN_PAPER:
                            output_pattern = make_output_pattern(output_dir, args.prefix)
                            scan_result = proto.extract_images_multi_with_reservation(
                                reserve_reply=reserve_reply,
                                target_ip=scanner_ip,
                                port1=port1,
                                local_ip=args.local_ip,
                                local_mac=args.local_mac,
                                scan_params=scan_params,
                                output_path=output_pattern,
                                job_id=args.job_id,
                                ix15xx_special=args.ix15xx_special,
                                read_timeout=args.read_timeout,
                                timeout=args.timeout,
                            )
                            total_pages = len(scan_result.pages)
                            total_bytes = sum(page.image_bytes for page in scan_result.pages)
                            log(
                                f"scan complete pages={total_pages} total_bytes={total_bytes} "
                                f"output_dir={Path(output_pattern).parent}"
                            )
                            continue

                        if trigger.cmd in RELEASE_COMMANDS:
                            log(f"scanner release trigger cmd=0x{trigger.cmd:08X}; reconnecting")
                            break

                        log(f"ignoring unhandled trigger cmd=0x{trigger.cmd:08X}")
            except KeyboardInterrupt:
                log("stopping")
                return 0
            except Exception as exc:
                log(f"service error: {exc}")
                time.sleep(args.retry_delay)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-ip")
    parser.add_argument("--port1", type=int)
    parser.add_argument("--port2", type=int)
    parser.add_argument("--local-ip", required=True)
    parser.add_argument("--local-mac", required=True)
    parser.add_argument("--if-version", type=lambda x: int(x, 0), required=True)
    parser.add_argument("--trigger-port", type=int, default=40000)
    parser.add_argument("--password", default="")
    parser.add_argument("--job-id", type=int, default=0)
    parser.add_argument("--ix15xx-special", action="store_true")
    parser.add_argument("--color-mode", choices=["auto", "color", "gray", "mono"], default="color")
    parser.add_argument("--quality", type=int, default=2)
    parser.add_argument("--paper-size", choices=["auto", "a4", "letter"], default="auto")
    parser.add_argument("--paper-handling", type=parse_paper_handling, default=1)
    parser.add_argument("--start-mode", type=parse_start_mode, default=1)
    parser.add_argument("--del-white-page", action="store_true")
    parser.add_argument("--bleed-through-reduction", action="store_true")
    parser.add_argument("--paper-protection", action="store_true")
    parser.add_argument("--output-dir", default="scans")
    parser.add_argument("--prefix", default="scan")
    parser.add_argument("--idle-timeout", type=float, default=5.0)
    parser.add_argument("--discover-timeout", type=float, default=2.0)
    parser.add_argument("--read-timeout", type=float, default=8.0)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--retry-delay", type=float, default=5.0)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return run_service(args)


if __name__ == "__main__":
    sys.exit(main())
