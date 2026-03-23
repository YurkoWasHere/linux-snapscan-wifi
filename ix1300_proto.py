#!/usr/bin/env python3
"""Prototype implementation of the ScanSnap iX1300 Wi-Fi protocol.

Current scope:
- build PFU discovery packets
- broadcast or unicast discover scanners
- parse discovery replies into HostInfo
- reserve the app interface
- query device info
- monitor basic trigger notifications

This is an implementation aid, not a complete working scanner client yet.
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional


DISCOVERY_PORT = 52217
DISCOVERY_KEY_IX1300 = 0x56454E53
PC_KEY = 0x53574642

HOST_TYPE_SCANNER = 0x30

CMD_RESERVE = 0x11
CMD_GET_DEV_INFO = 0x13
CMD_XFER_DATA = 0x50
CMD_SET_START_MODE = 0x62

NOTIFY_NOT_CONNECTED = 0x0000
NOTIFY_CONNECTED = 0x0001
NOTIFY_KEEPALIVE = 0x8001

STATUS_AI_PARAMETER_NG = -1
STATUS_AI_PASSWORD_AVAIL_NG = -2
STATUS_AI_PASSWORD_NG = -3
STATUS_AI_USED_BY_OTHER = -4
STATUS_AI_IF_VER_NG = -5


@dataclass(slots=True)
class HostInfo:
    key_code: int
    notify_code: int
    if_version: int
    host_type: int
    need_password: bool
    ip_address: str
    port1: int
    port2: int
    mac_address: str
    action_mode: Optional[int]
    scanner_status: Optional[int]
    occupied_status: Optional[int]
    host_name: str
    product_name: str

    @property
    def is_scanner(self) -> bool:
        return self.host_type == HOST_TYPE_SCANNER


@dataclass(slots=True)
class ReserveReply:
    ok: bool
    length: int
    key_code: int
    status: int
    if_version: int
    raw: bytes


@dataclass(slots=True)
class DeviceInfoReply:
    ok: bool
    length: int
    key_code: int
    status: int
    unknown_0c: int
    host_name: str
    raw: bytes


@dataclass(slots=True)
class SetStartModeReply:
    ok: bool
    length: int
    key_code: int
    status: int
    raw: bytes


@dataclass(slots=True)
class TriggerPacket:
    length: int
    key_code: int
    cmd: int
    sensor: bytes
    sequence_id: int
    raw: bytes


@dataclass(slots=True)
class XferDataReply:
    ok: bool
    length: int
    key_code: int
    status: int
    reserved_0c: int
    echoed_xfer_status: int
    raw: bytes


@dataclass(slots=True)
class ScannerIFReply:
    ok: bool
    length: int
    key_code: int
    status: int
    raw: bytes


@dataclass(slots=True)
class InquiryReply:
    ok: bool
    length: int
    key_code: int
    status: int
    scan_status: int
    fixed_block: bytes
    extra_data: bytes
    raw: bytes


@dataclass(slots=True)
class HardwareStatusReply:
    ok: bool
    length: int
    key_code: int
    status: int
    scan_status: int
    fixed_block: bytes
    data: bytes
    raw: bytes


@dataclass(slots=True)
class HardwareStatus:
    top_cover_open: bool
    hopper_empty: bool
    adf_cover_open: bool
    exit_cover_open: bool
    sleeping: bool
    long_paper_switch: bool
    scan_button: bool
    double_feed: bool
    scan_cancel: bool
    non_separation: bool
    continue_scan: bool
    scan_end: bool
    battery_power_zero: bool
    battery_power: int
    raw: bytes


@dataclass(slots=True)
class TriggerWaitResult:
    trigger: Optional[TriggerPacket]
    error: Optional[str]
    transport: Optional[str] = None


@dataclass(slots=True)
class ReadParams:
    bFront: bool
    nDataType: int
    nPageID: int
    nSequenceID: int
    nTransferLen: int
    nTrasferMode: int
    bMultiFeedDetect: bool = False


@dataclass(slots=True)
class ReadReply:
    ok: bool
    length: int
    key_code: int
    status: int
    scan_status: int
    fixed_block: bytes
    data: bytes
    raw: bytes


@dataclass(slots=True)
class SenseData:
    bEOM: bool
    bILI: bool
    nSenseKey: int
    nInformation: int
    nSenseCode: int
    nSenseQualifier: int
    raw: bytes


@dataclass(slots=True)
class SenseOutcome:
    ok: bool
    sense: SenseData
    error_name: Optional[str]
    retry_read: bool
    hopper_empty: bool
    page_complete: bool
    fatal: bool


@dataclass(slots=True)
class ScanPageResult:
    page_number: int
    paper_reply: InquiryReply
    replies: list[ReadReply]
    sense: Optional[SenseData]
    outcome: Optional[SenseOutcome]
    image_type: str
    image_bytes: int
    path: Optional[str]


@dataclass(slots=True)
class ScanSessionResult:
    reserve_reply: ReserveReply
    ack: ScannerIFReply
    cancel_reply: InquiryReply
    set_reply: InquiryReply
    start_reply: InquiryReply
    pages: list[ScanPageResult]


@dataclass(slots=True)
class WindowInfo:
    nWndID: int
    nDataFormat: int
    nXRes: int
    nYRes: int
    nImageComposition: int
    nImageCompressionType: int
    nCompressionArg: int
    nPaperWidth: int
    nPaperLength: int
    nGAMMA: int
    nBrightness: int
    nContrast: int
    nShadow: int
    nHighlight: int
    bUnSharpMask: bool
    bsRGB: bool
    nDoubleRes: int
    nThreshold: int
    nAutoBinaryMode: int
    nBinaryDensity: int
    bMakeThumbnail: bool
    nThumbnailComposition: int
    nThumbnailCompressionType: int
    nThumbnailWidth: int
    nThumbnailLength: int


@dataclass(slots=True)
class ScanParams:
    nPaperHanling: int
    bOverScan: bool
    bAutoLenDetect: bool
    bNameCard: bool
    bMutiFeedDetectByDevice: bool
    bStopScanWhenMultiFeed: bool
    bMutiFeedUseSupersonic: bool
    bMutiFeedUsePaperLenChk: bool
    nAutoSizeDetect: int
    bContinueScan: bool
    bAutoColorDetect: bool
    bColorDetectColor: bool
    bColorDetectGray: bool
    bColorDetectMono: bool
    bDelWhitePage: bool
    bPaperLengthDection: bool
    bBleedThroughReduction: bool
    bTRANSFER_MODE: bool
    ix1300_paper_protection: bool
    wndDescBlks: list[WindowInfo]


def ipv4_to_int(ip: str) -> int:
    return int(ipaddress.IPv4Address(ip))


def int_to_ipv4(value: int) -> str:
    return str(ipaddress.IPv4Address(value))


def mac_to_bytes(mac: str) -> bytes:
    parts = mac.split(":")
    if len(parts) != 6:
        raise ValueError(f"invalid MAC address: {mac}")
    return bytes(int(part, 16) for part in parts)


def bytes_to_mac(buf: bytes) -> str:
    if len(buf) < 6:
        raise ValueError("MAC buffer too short")
    return ":".join(f"{b:02X}" for b in buf[:6])


def pad(data: bytes, size: int) -> bytes:
    if len(data) > size:
        raise ValueError(f"field too large: {len(data)} > {size}")
    return data + (b"\x00" * (size - len(data)))


def build_discovery_request(
    local_ip: str,
    local_mac: str,
    callback_port: int,
    *,
    key_code: int = DISCOVERY_KEY_IX1300,
    need_password: bool = False,
    status_word: int = 0x0010,
) -> bytes:
    """Build the scanner-family discovery request used by the Android app.

    This maps the `DeviceFinder.PrepareSendData(...)` path for iX1300-family devices.
    """

    buf = bytearray()
    buf += struct.pack(">I", key_code)
    buf += struct.pack(">I", 1 if need_password else 0)
    buf += struct.pack(">I", ipv4_to_int(local_ip))
    buf += mac_to_bytes(local_mac)
    buf += b"\x00\x00"
    buf += struct.pack(">I", callback_port)
    buf += struct.pack(">H", status_word)
    buf += struct.pack(">H", 0)
    buf += struct.pack(">I", 0)
    return bytes(buf)


def parse_discovery_response(packet: bytes) -> HostInfo:
    """Parse the `HostInfo` response format used by discovery."""

    if len(packet) < 0x68:
        raise ValueError(f"packet too short: {len(packet)}")

    key_code, notify_code, status = struct.unpack_from(">IHH", packet, 0x00)
    if key_code not in (PC_KEY, DISCOVERY_KEY_IX1300, 0x73734E52):
        raise ValueError(f"unexpected key code: 0x{key_code:08X}")
    if status != 0:
        raise ValueError(f"scanner returned non-zero status: {status}")

    if_version, host_type = struct.unpack_from(">HH", packet, 0x08)
    need_password = struct.unpack_from(">I", packet, 0x0C)[0] != 0
    ip_address = int_to_ipv4(struct.unpack_from(">I", packet, 0x10)[0])
    port1 = struct.unpack_from(">I", packet, 0x14)[0]
    port2 = struct.unpack_from(">I", packet, 0x18)[0]
    mac_address = bytes_to_mac(packet[0x1C:0x24])

    if if_version < 6:
        action_mode = None
        scanner_status = None
        occupied_status = struct.unpack_from(">I", packet, 0x24)[0]
    else:
        action_mode = packet[0x24]
        scanner_status = packet[0x25]
        occupied_status = struct.unpack_from(">H", packet, 0x26)[0]

    host_name = packet[0x28:0x68].split(b"\x00", 1)[0].decode("utf-8", errors="ignore").strip()
    if host_type == HOST_TYPE_SCANNER and len(packet) >= 0x7F:
        product_name = packet[0x6F:0x7F].split(b"\x00", 1)[0].decode("utf-8", errors="ignore").strip().lower()
    elif host_type == HOST_TYPE_SCANNER and len(packet) >= 0x78:
        product_name = packet[0x68:0x78].split(b"\x00", 1)[0].decode("utf-8", errors="ignore").strip().lower()
    else:
        product_name = "pc"

    return HostInfo(
        key_code=key_code,
        notify_code=notify_code,
        if_version=if_version,
        host_type=host_type,
        need_password=need_password,
        ip_address=ip_address,
        port1=port1,
        port2=port2,
        mac_address=mac_address,
        action_mode=action_mode,
        scanner_status=scanner_status,
        occupied_status=occupied_status,
        host_name=host_name,
        product_name=product_name,
    )


def guess_local_ip_for_target(target_ip: str) -> str:
    try:
        ip_obj = ipaddress.IPv4Address(target_ip)
    except ipaddress.AddressValueError:
        ip_obj = None

    candidates = []
    if ip_obj is not None and not ip_obj.is_multicast and ip_obj != ipaddress.IPv4Address("255.255.255.255"):
        candidates.append(str(ip_obj))
    candidates.extend(["8.8.8.8", "1.1.1.1", "192.168.0.1"])

    for candidate in candidates:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect((candidate, 9))
            local_ip = sock.getsockname()[0]
            if local_ip and local_ip != "0.0.0.0":
                return local_ip
        except OSError:
            pass
        finally:
            sock.close()

    hostname = socket.gethostname()
    for family, _type, _proto, _canonname, sockaddr in socket.getaddrinfo(hostname, None, socket.AF_INET):
        if family != socket.AF_INET:
            continue
        local_ip = sockaddr[0]
        if not local_ip.startswith("127."):
            return local_ip

    raise RuntimeError("could not determine a usable local IPv4 address; pass --local-ip explicitly")


def guess_local_mac() -> str:
    node = uuid_getnode()
    return ":".join(f"{(node >> shift) & 0xFF:02X}" for shift in range(40, -1, -8))


def uuid_getnode() -> int:
    import uuid

    return uuid.getnode()


def discover(
    *,
    local_ip: str,
    local_mac: str,
    listen_port: int,
    timeout: float = 2.0,
    target_ip: Optional[str] = None,
) -> List[HostInfo]:
    request = build_discovery_request(local_ip, local_mac, listen_port)
    destination = (target_ip or "255.255.255.255", DISCOVERY_PORT)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if target_ip is None:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind((local_ip, listen_port))
    sock.settimeout(timeout)

    found: dict[tuple[str, int, int], HostInfo] = {}
    try:
        sock.sendto(request, destination)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                packet, _addr = sock.recvfrom(2048)
            except socket.timeout:
                break
            try:
                info = parse_discovery_response(packet)
            except ValueError:
                continue
            found[(info.ip_address, info.port1, info.port2)] = info
    finally:
        sock.close()

    return list(found.values())


def build_reserve_request(
    *,
    local_mac: str,
    if_version: int,
    trigger_port: int,
    password: bytes = b"",
    host_type: int = 1,
    key_code: int = DISCOVERY_KEY_IX1300,
    unknown_1e: int = 0x1E,
    ix1300_mode: bool = True,
) -> bytes:
    """Prototype reserve request builder.

    This follows the APK enough to reproduce the packet prefix and password field.
    The trailing timestamp/extended fields are currently zero-filled.
    """

    if host_type not in (1, 2, 3):
        raise ValueError("host_type must be 1, 2, or 3")
    if len(password) > 0x30:
        raise ValueError("password too long")

    if 0x100 <= if_version <= 0x1FF:
        packet_len = 0x180
    else:
        packet_len = 0x80
    if ix1300_mode:
        packet_len = 0x80

    buf = bytearray(packet_len)
    struct.pack_into(">I", buf, 0x00, packet_len)
    struct.pack_into(">I", buf, 0x04, key_code)
    struct.pack_into(">I", buf, 0x08, CMD_RESERVE)
    struct.pack_into(">I", buf, 0x0C, 0)

    mac = mac_to_bytes(local_mac)
    buf[0x10:0x16] = mac
    buf[0x16:0x18] = b"\x00\x00"
    struct.pack_into(">I", buf, 0x18, 0)
    struct.pack_into(">I", buf, 0x1C, 0)
    struct.pack_into(">H", buf, 0x20, if_version)
    struct.pack_into(">B", buf, 0x22, trigger_port & 0xFF)
    struct.pack_into(">B", buf, 0x23, 0)
    struct.pack_into(">I", buf, 0x24, host_type)
    struct.pack_into(">I", buf, 0x28, 1 if password else 0)
    struct.pack_into(">I", buf, 0x2C, trigger_port)
    struct.pack_into(">I", buf, 0x30, unknown_1e)
    buf[0x34:0x64] = pad(password, 0x30)

    return bytes(buf)


def build_get_device_info_request(*, local_mac: str, key_code: int = DISCOVERY_KEY_IX1300) -> bytes:
    buf = bytearray(0x20)
    struct.pack_into(">I", buf, 0x00, 0x20)
    struct.pack_into(">I", buf, 0x04, key_code)
    struct.pack_into(">I", buf, 0x08, CMD_GET_DEV_INFO)
    struct.pack_into(">I", buf, 0x0C, 0)
    buf[0x10:0x16] = mac_to_bytes(local_mac)
    buf[0x16:0x18] = b"\x00\x00"
    struct.pack_into(">I", buf, 0x18, 0)
    struct.pack_into(">I", buf, 0x1C, 0)
    return bytes(buf)


def build_set_start_mode_request(
    *,
    local_mac: str,
    start_mode: int,
    key_code: int = DISCOVERY_KEY_IX1300,
) -> bytes:
    if start_mode not in (0, 1):
        raise ValueError("start_mode must be 0 (normal) or 1 (quick)")

    buf = bytearray(0x30)
    struct.pack_into(">I", buf, 0x00, 0x30)
    struct.pack_into(">I", buf, 0x04, key_code)
    struct.pack_into(">I", buf, 0x08, CMD_SET_START_MODE)
    struct.pack_into(">I", buf, 0x0C, 0)
    buf[0x10:0x16] = mac_to_bytes(local_mac)
    buf[0x16:0x18] = b"\x00\x00"
    struct.pack_into(">I", buf, 0x18, 0)
    struct.pack_into(">I", buf, 0x1C, 0)
    struct.pack_into(">I", buf, 0x20, 2)
    struct.pack_into(">I", buf, 0x24, start_mode)
    struct.pack_into(">I", buf, 0x28, 0)
    struct.pack_into(">I", buf, 0x2C, 0)
    return bytes(buf)


def build_xfer_data_request(
    *,
    local_mac: str,
    xfer_status: int,
    total_length: int,
    offset: int,
    payload: bytes = b"",
    key_code: int = DISCOVERY_KEY_IX1300,
) -> bytes:
    if xfer_status not in (0x80, 0x40, 0x20):
        raise ValueError("xfer_status must be one of 0x80, 0x40, 0x20")
    if total_length < offset + len(payload):
        raise ValueError("total_length must be >= offset + payload length")

    packet_len = 0x30 + len(payload)
    buf = bytearray(packet_len)
    struct.pack_into(">I", buf, 0x00, packet_len)
    struct.pack_into(">I", buf, 0x04, key_code)
    struct.pack_into(">I", buf, 0x08, CMD_XFER_DATA)
    struct.pack_into(">I", buf, 0x0C, 0)
    buf[0x10:0x16] = mac_to_bytes(local_mac)
    buf[0x16:0x18] = b"\x00\x00"
    struct.pack_into(">I", buf, 0x18, 0)
    struct.pack_into(">I", buf, 0x1C, 0)
    buf[0x20] = 0
    buf[0x21] = 1
    buf[0x22] = xfer_status & 0xFF
    buf[0x23] = 0
    struct.pack_into(">I", buf, 0x24, total_length)
    struct.pack_into(">I", buf, 0x28, offset)
    struct.pack_into(">I", buf, 0x2C, len(payload))
    buf[0x30:] = payload
    return bytes(buf)


def build_scanner_cmd_request(
    *,
    local_mac: str,
    cdb: bytes,
    transfer_length: int,
    payload: bytes = b"",
    use_mode_2: bool = False,
    key_code: int = DISCOVERY_KEY_IX1300,
) -> bytes:
    if not cdb or len(cdb) > 0x10:
        raise ValueError("cdb length must be between 1 and 16")
    if len(payload) > 0x10000:
        raise ValueError("payload too large")

    packet_len = 0x40 + len(payload)
    buf = bytearray(packet_len)
    struct.pack_into(">I", buf, 0x00, packet_len)
    struct.pack_into(">I", buf, 0x04, key_code)
    struct.pack_into(">I", buf, 0x08, 2 if use_mode_2 else 1)
    struct.pack_into(">I", buf, 0x0C, 0)
    buf[0x10:0x16] = mac_to_bytes(local_mac)
    buf[0x16:0x18] = b"\x00\x00"
    struct.pack_into(">I", buf, 0x18, 0)
    struct.pack_into(">I", buf, 0x1C, 0)
    struct.pack_into(">I", buf, 0x20, len(cdb))
    struct.pack_into(">I", buf, 0x24, transfer_length)
    struct.pack_into(">I", buf, 0x28, len(payload))
    struct.pack_into(">I", buf, 0x2C, 0)
    buf[0x30:0x30 + len(cdb)] = cdb
    buf[0x30 + len(cdb):0x40] = b"\x00" * (0x10 - len(cdb))
    if payload:
        buf[0x40:] = payload
    return bytes(buf)


def build_inquiry_request(inquiry_status: int = 0) -> tuple[bytes, int]:
    cdb = bytearray(6)
    cdb[0] = 0x12
    transfer_length = 0x60
    if inquiry_status == 0:
        cdb[4] = 0x60
    elif inquiry_status == 2:
        cdb[1] = 0x01
        cdb[2] = 0xF0
        cdb[4] = 0x90
        transfer_length = 0x90
    else:
        cdb[4] = 0x60
    return bytes(cdb), transfer_length


def build_set_job_data(job_id: int) -> bytes:
    return struct.pack(">II", job_id, 0)


def build_window_info(
    *,
    color_mode: str = "color",
    quality: int = 2,
    paper_size: str = "auto",
    paper_handling: int = 1,
    del_white_page: bool = False,
    bleed_through_reduction: bool = False,
    ix1300_paper_protection: bool = False,
) -> WindowInfo:
    if quality == 0:
        x_res = y_res = 0
    elif quality == 1:
        x_res = y_res = 0x96
    elif quality == 2:
        x_res = y_res = 0xC8
    elif quality == 3:
        x_res = y_res = 0x12C
    else:
        raise ValueError("quality must be 0, 1, 2, or 3")

    mode = color_mode.lower()
    if mode == "color":
        wnd_id = 0x00 if paper_handling == 1 else 0x80
        data_format = 0x10
        image_composition = 0x05
        compression_type = 0x82
        compression_arg = 0x0C
        double_res = 0
        binary_density = 0
    elif mode == "gray":
        wnd_id = 0x01 if paper_handling == 1 else 0x81
        data_format = 0x10
        image_composition = 0x02
        compression_type = 0x82
        compression_arg = 0x0C
        double_res = 0
        binary_density = 0
    elif mode == "mono":
        wnd_id = 0x00
        data_format = 0x40
        image_composition = 0x00
        compression_type = 0x03
        compression_arg = 0x00
        double_res = 1
        binary_density = 0
    else:
        raise ValueError("color_mode must be color, gray, or mono")

    if paper_size == "auto":
        paper_width = 0x2880
        paper_length = 0x4350 if paper_handling == 1 else 0x4410
    elif paper_size == "a4":
        paper_width = 0x1B50
        paper_length = 0x26C0
    elif paper_size == "letter":
        paper_width = 0x1A20
        paper_length = 0x2880
    else:
        raise ValueError("paper_size must be auto, a4, or letter")

    return WindowInfo(
        nWndID=wnd_id,
        nDataFormat=data_format,
        nXRes=x_res,
        nYRes=y_res,
        nImageComposition=image_composition,
        nImageCompressionType=compression_type,
        nCompressionArg=compression_arg,
        nPaperWidth=paper_width,
        nPaperLength=paper_length,
        nGAMMA=0x04,
        nBrightness=0,
        nContrast=0,
        nShadow=0,
        nHighlight=1,
        bUnSharpMask=True,
        bsRGB=True,
        nDoubleRes=double_res,
        nThreshold=0,
        nAutoBinaryMode=0,
        nBinaryDensity=binary_density,
        bMakeThumbnail=False,
        nThumbnailComposition=0,
        nThumbnailCompressionType=0,
        nThumbnailWidth=0,
        nThumbnailLength=0,
    )


def build_default_scan_params(
    *,
    color_mode: str = "color",
    quality: int = 2,
    paper_size: str = "auto",
    paper_handling: int = 1,
    del_white_page: bool = False,
    bleed_through_reduction: bool = False,
    ix1300_paper_protection: bool = False,
) -> ScanParams:
    if color_mode == "auto":
        auto_color = True
        detect_color = True
        detect_gray = True
        detect_mono = False
        window_mode = "color"
    else:
        auto_color = False
        detect_color = color_mode == "color"
        detect_gray = color_mode == "gray"
        detect_mono = color_mode == "mono"
        window_mode = color_mode

    auto_len = paper_size == "auto"
    window = build_window_info(
        color_mode=window_mode,
        quality=quality,
        paper_size=paper_size,
        paper_handling=paper_handling,
        del_white_page=del_white_page,
        bleed_through_reduction=bleed_through_reduction,
        ix1300_paper_protection=ix1300_paper_protection,
    )
    return ScanParams(
        nPaperHanling=paper_handling,
        bOverScan=auto_len,
        bAutoLenDetect=auto_len,
        bNameCard=False,
        bMutiFeedDetectByDevice=False,
        bStopScanWhenMultiFeed=False,
        bMutiFeedUseSupersonic=False,
        bMutiFeedUsePaperLenChk=False,
        nAutoSizeDetect=1 if auto_len else 0,
        bContinueScan=False,
        bAutoColorDetect=auto_color,
        bColorDetectColor=detect_color,
        bColorDetectGray=detect_gray,
        bColorDetectMono=detect_mono,
        bDelWhitePage=del_white_page,
        bPaperLengthDection=(quality == 0),
        bBleedThroughReduction=bleed_through_reduction,
        bTRANSFER_MODE=False,
        ix1300_paper_protection=ix1300_paper_protection,
        wndDescBlks=[window],
    )


def build_scan_parameters_payload(scan_params: ScanParams) -> bytes:
    auto_color_block = (
        scan_params.bAutoColorDetect
        and scan_params.bColorDetectColor
        and scan_params.bColorDetectGray
    )
    payload_len = 0x80 if auto_color_block else 0x50
    buf = bytearray(payload_len)
    off = 0

    def put_u8(value: int) -> None:
        nonlocal off
        buf[off] = value & 0xFF
        off += 1

    def put_u16(value: int) -> None:
        nonlocal off
        struct.pack_into(">H", buf, off, value & 0xFFFF)
        off += 2

    def put_u32(value: int) -> None:
        nonlocal off
        struct.pack_into(">I", buf, off, value & 0xFFFFFFFF)
        off += 4

    put_u8(1)  # ix1300 flag
    put_u8(scan_params.nPaperHanling)
    put_u8(1 if scan_params.bOverScan else 0)
    put_u8(1 if scan_params.bAutoLenDetect else (2 if scan_params.bNameCard else 0))

    multi_feed = 0 if scan_params.bMutiFeedDetectByDevice else 0x80
    if scan_params.bStopScanWhenMultiFeed:
        multi_feed |= 0x40
    if scan_params.bMutiFeedUseSupersonic:
        multi_feed |= 0x10
    if scan_params.bMutiFeedUsePaperLenChk:
        multi_feed |= 0x08
    put_u8(multi_feed)
    put_u8(scan_params.nAutoSizeDetect)
    put_u8(0x80 if scan_params.bContinueScan else 0xC1)
    put_u8(0xC1 if scan_params.bAutoColorDetect else 0x80)
    put_u8(0xE0 if scan_params.bDelWhitePage else 0x80)
    put_u8(0xC8)
    put_u8(0xA0 if scan_params.bPaperLengthDection else 0x80)
    put_u8(0xC0 if scan_params.bBleedThroughReduction else 0x80)
    put_u8(0x80 if scan_params.bBleedThroughReduction else 0x00)
    put_u8(0x80 if scan_params.bTRANSFER_MODE else 0x00)
    put_u8(0x00)
    put_u16(0x0000)
    put_u16(0x0000)
    put_u32(0x00000000)
    put_u32(0x00000000)
    put_u8(0x00)

    if scan_params.nPaperHanling == 2:
        put_u8(0x30 if scan_params.ix1300_paper_protection else 0x20)
    else:
        put_u8(0x00)
    put_u16(0x0000)

    put_u8(0x30)
    for wnd in scan_params.wndDescBlks:
        put_u8(wnd.nWndID)
        put_u8(wnd.nDataFormat)
        put_u16(wnd.nXRes)
        put_u16(wnd.nYRes)
        put_u8(wnd.nImageComposition)
        put_u8(wnd.nImageCompressionType)
        put_u8(wnd.nCompressionArg)
        put_u8(0x00)
        put_u32(wnd.nPaperWidth)
        put_u32(wnd.nPaperLength)
        put_u8(wnd.nGAMMA)
        put_u8(wnd.nBrightness)
        put_u8(wnd.nContrast)
        put_u8(wnd.nShadow)
        put_u8(wnd.nHighlight)
        put_u8(1 if wnd.bUnSharpMask else 0)
        put_u8(1 if wnd.bsRGB else 0)
        put_u8(wnd.nDoubleRes)
        put_u8(wnd.nThreshold)
        put_u8(wnd.nAutoBinaryMode)
        put_u8(wnd.nBinaryDensity)
        put_u16(0x0000)
        put_u8(0x00)
        put_u8(1 if wnd.bMakeThumbnail else 0)
        put_u8(wnd.nThumbnailComposition)
        put_u8(wnd.nThumbnailCompressionType)
        put_u8(0x00)
        put_u32(wnd.nThumbnailWidth)
        put_u32(wnd.nThumbnailLength)
        put_u32(0x00000000)

    return bytes(buf)


def build_set_params_request(scan_params: ScanParams) -> tuple[bytes, int, bytes]:
    cdb = bytearray(6)
    cdb[0] = 0xD4
    cdb[4] = 0x80 if (
        scan_params.bAutoColorDetect
        and scan_params.bColorDetectColor
        and scan_params.bColorDetectGray
    ) else 0x50
    payload = build_scan_parameters_payload(scan_params)
    return bytes(cdb), 0, payload


def build_start_job_request(job_id: int, *, ix15xx_special: bool = False) -> tuple[bytes, int, bytes]:
    cdb = bytearray(6)
    cdb[0] = 0xD5
    if ix15xx_special:
        cdb[3] = 0x01
    cdb[4] = 0x08
    cdb[5] = 0x08
    payload = build_set_job_data(job_id)
    return bytes(cdb), 0x08, payload


def build_cancel_read_request() -> tuple[bytes, int, bytes]:
    cdb = bytearray(6)
    cdb[0] = 0xD8
    return bytes(cdb), 0, b""


def build_start_paper_request() -> tuple[bytes, int, bytes]:
    cdb = bytearray(6)
    cdb[0] = 0xE0
    return bytes(cdb), 0, b""


def build_get_hardware_status_request() -> tuple[bytes, int, bytes]:
    cdb = bytearray(10)
    cdb[0] = 0xC2
    cdb[8] = 0x20
    return bytes(cdb), 0x20, b""


def build_request_sense_request() -> tuple[bytes, int, bytes]:
    cdb = bytearray(6)
    cdb[0] = 0x03
    cdb[4] = 0x12
    return bytes(cdb), 0x12, b""


def build_read_cdb(read_params: ReadParams) -> bytes:
    cdb = bytearray(12)
    cdb[0] = 0x28
    cdb[1] = 0x00
    cdb[2] = read_params.nDataType & 0xFF
    cdb[3] = read_params.nTrasferMode & 0xFF
    cdb[4] = 0x00
    cdb[5] = 0x00 if read_params.bFront else 0x80
    cdb[6] = (read_params.nTransferLen >> 16) & 0xFF
    cdb[7] = (read_params.nTransferLen >> 8) & 0xFF
    cdb[8] = read_params.nTransferLen & 0xFF
    cdb[9] = 0x00
    cdb[10] = read_params.nPageID & 0xFF
    cdb[11] = read_params.nSequenceID & 0xFF
    return bytes(cdb)


def parse_reserve_reply(packet: bytes, *, key_code: int = DISCOVERY_KEY_IX1300) -> ReserveReply:
    if len(packet) != 0x14:
        raise ValueError(f"unexpected reserve reply length: {len(packet)}")

    length, reply_key, status, if_version = struct.unpack_from(">Iiih", packet, 0x00)
    if length != 0x14:
        raise ValueError(f"unexpected reserve reply size field: 0x{length:08X}")
    if reply_key != key_code:
        raise ValueError(f"unexpected reserve reply key: 0x{reply_key:08X}")
    if if_version < 2:
        raise ValueError(f"scanner rejected IF version: {if_version}")

    return ReserveReply(
        ok=(status == 0),
        length=length,
        key_code=reply_key,
        status=status,
        if_version=if_version,
        raw=packet,
    )


def parse_device_info_reply(packet: bytes, *, key_code: int = DISCOVERY_KEY_IX1300) -> DeviceInfoReply:
    if len(packet) != 0x70:
        raise ValueError(f"unexpected device info reply length: {len(packet)}")

    length, reply_key, status, unknown_0c = struct.unpack_from(">IIII", packet, 0x00)
    if length != 0x70:
        raise ValueError(f"unexpected device info size field: 0x{length:08X}")
    if reply_key != key_code:
        raise ValueError(f"unexpected device info key: 0x{reply_key:08X}")

    host_name = packet[0x10:0x50].split(b"\x00", 1)[0].decode("utf-8", errors="ignore").strip()
    return DeviceInfoReply(
        ok=(status == 0),
        length=length,
        key_code=reply_key,
        status=status,
        unknown_0c=unknown_0c,
        host_name=host_name,
        raw=packet,
    )


def parse_set_start_mode_reply(packet: bytes, *, key_code: int = DISCOVERY_KEY_IX1300) -> SetStartModeReply:
    if len(packet) != 0x1C:
        raise ValueError(f"unexpected set-start-mode reply length: {len(packet)}")

    length, reply_key, status = struct.unpack_from(">IIi", packet, 0x00)
    if length != 0x1C:
        raise ValueError(f"unexpected set-start-mode size field: 0x{length:08X}")
    if reply_key != key_code:
        raise ValueError(f"unexpected set-start-mode key: 0x{reply_key:08X}")

    return SetStartModeReply(
        ok=(status == 0),
        length=length,
        key_code=reply_key,
        status=status,
        raw=packet,
    )


def parse_trigger_packet(packet: bytes, *, key_code: int = DISCOVERY_KEY_IX1300) -> TriggerPacket:
    if len(packet) != 0x30:
        raise ValueError(f"unexpected trigger packet length: {len(packet)}")

    length, reply_key, cmd = struct.unpack_from(">III", packet, 0x00)
    if length != 0x30:
        raise ValueError(f"unexpected trigger size field: 0x{length:08X}")
    if reply_key != key_code:
        raise ValueError(f"unexpected trigger key: 0x{reply_key:08X}")

    sensor = packet[0x0C:0x10]
    sequence_id = packet[0x10]
    return TriggerPacket(
        length=length,
        key_code=reply_key,
        cmd=cmd,
        sensor=sensor,
        sequence_id=sequence_id,
        raw=packet,
    )


def parse_xfer_data_reply(packet: bytes, *, expected_xfer_status: int, key_code: int = DISCOVERY_KEY_IX1300) -> XferDataReply:
    if len(packet) != 0x20:
        raise ValueError(f"unexpected xfer-data reply length: {len(packet)}")

    length, reply_key = struct.unpack_from(">II", packet, 0x00)
    status = struct.unpack_from(">i", packet, 0x08)[0]
    reserved_0c, echoed_xfer_status = struct.unpack_from(">II", packet, 0x0C)
    if length != 0x20:
        raise ValueError(f"unexpected xfer-data size field: 0x{length:08X}")
    if reply_key != key_code:
        raise ValueError(f"unexpected xfer-data key: 0x{reply_key:08X}")

    return XferDataReply(
        ok=(status == 0 and expected_xfer_status == echoed_xfer_status),
        length=length,
        key_code=reply_key,
        status=status,
        reserved_0c=reserved_0c,
        echoed_xfer_status=echoed_xfer_status,
        raw=packet,
    )


def parse_scanner_if_reply(packet: bytes, *, key_code: int = DISCOVERY_KEY_IX1300) -> ScannerIFReply:
    if len(packet) != 0x10:
        raise ValueError(f"unexpected scanner-if reply length: {len(packet)}")
    length, reply_key, status = struct.unpack_from(">IIi", packet, 0x00)
    if length != 0x10:
        raise ValueError(f"unexpected scanner-if size field: 0x{length:08X}")
    if reply_key != key_code:
        raise ValueError(f"unexpected scanner-if key: 0x{reply_key:08X}")
    return ScannerIFReply(ok=(status == 0), length=length, key_code=reply_key, status=status, raw=packet)


def parse_inquiry_reply(packet: bytes, extra_data: bytes = b"", *, key_code: int = DISCOVERY_KEY_IX1300) -> InquiryReply:
    if len(packet) < 0x28:
        raise ValueError(f"unexpected inquiry reply length: {len(packet)}")
    length, reply_key, status, scan_status = struct.unpack_from(">IIii", packet, 0x00)
    if length < 0x28:
        raise ValueError(f"unexpected inquiry size field: 0x{length:08X}")
    if reply_key != key_code:
        raise ValueError(f"unexpected inquiry key: 0x{reply_key:08X}")
    fixed_block = packet[0x10:0x28]
    return InquiryReply(
        ok=(status == 0 and scan_status == 0),
        length=length,
        key_code=reply_key,
        status=status,
        scan_status=scan_status,
        fixed_block=fixed_block,
        extra_data=extra_data,
        raw=packet,
    )


def parse_hardware_status_reply(
    packet: bytes,
    extra_data: bytes = b"",
    *,
    key_code: int = DISCOVERY_KEY_IX1300,
) -> HardwareStatusReply:
    if len(packet) < 0x28:
        raise ValueError(f"unexpected hardware-status reply length: {len(packet)}")
    length, reply_key, status, scan_status = struct.unpack_from(">IIii", packet, 0x00)
    if length < 0x28:
        raise ValueError(f"unexpected hardware-status size field: 0x{length:08X}")
    if reply_key != key_code:
        raise ValueError(f"unexpected hardware-status key: 0x{reply_key:08X}")
    fixed_block = packet[0x10:0x28]
    return HardwareStatusReply(
        ok=(status == 0 and scan_status == 0 and len(extra_data) == 0x20),
        length=length,
        key_code=reply_key,
        status=status,
        scan_status=scan_status,
        fixed_block=fixed_block,
        data=extra_data,
        raw=packet,
    )


def parse_read_reply(
    packet: bytes,
    extra_data: bytes = b"",
    *,
    key_code: int = DISCOVERY_KEY_IX1300,
) -> ReadReply:
    if len(packet) < 0x28:
        raise ValueError(f"unexpected read reply length: {len(packet)}")
    length, reply_key, status, scan_status = struct.unpack_from(">IIii", packet, 0x00)
    if length < 0x28:
        raise ValueError(f"unexpected read-reply size field: 0x{length:08X}")
    if reply_key != key_code:
        raise ValueError(f"unexpected read-reply key: 0x{reply_key:08X}")
    fixed_block = packet[0x10:0x28]
    return ReadReply(
        ok=(status == 0 and scan_status == 0),
        length=length,
        key_code=reply_key,
        status=status,
        scan_status=scan_status,
        fixed_block=fixed_block,
        data=extra_data,
        raw=packet,
    )


def parse_sense_data(data: bytes) -> SenseData:
    if len(data) != 0x12:
        raise ValueError(f"unexpected request-sense payload length: {len(data)}")
    flags = data[2]
    return SenseData(
        bEOM=bool(flags & 0x40),
        bILI=bool(flags & 0x20),
        nSenseKey=flags & 0x0F,
        nInformation=struct.unpack_from(">I", data, 3)[0],
        nSenseCode=data[12],
        nSenseQualifier=data[13],
        raw=data,
    )


def analyze_sense(sense: SenseData) -> SenseOutcome:
    error_name: Optional[str] = None
    retry_read = False
    hopper_empty = False
    page_complete = False
    fatal = False

    if sense.nSenseKey == 0x02:
        error_name = "not_ready"
        fatal = True
    elif sense.nSenseKey == 0x03:
        if sense.nSenseCode == 0x80 and sense.nSenseQualifier in (0x01, 0x0B):
            error_name = "scanning_jam"
            fatal = True
        elif sense.nSenseCode == 0x80 and sense.nSenseQualifier == 0x02:
            error_name = "adf_cover_open"
            fatal = True
        elif sense.nSenseCode == 0x80 and sense.nSenseQualifier == 0x03:
            error_name = "hopper_empty"
            hopper_empty = True
        elif sense.nSenseCode == 0x80 and sense.nSenseQualifier == 0x07:
            error_name = "multifeed_detected"
            fatal = True
        elif sense.nSenseCode == 0x80 and sense.nSenseQualifier == 0x09:
            error_name = "carrier_sheet_detected"
            fatal = True
        elif sense.nSenseCode == 0x80 and sense.nSenseQualifier == 0x13:
            error_name = "lack_data"
            retry_read = True
        elif sense.nSenseCode == 0x80 and sense.nSenseQualifier == 0x20:
            error_name = "emergency_stop"
            fatal = True
        elif sense.nSenseCode == 0x80 and sense.nSenseQualifier == 0x0C:
            error_name = "duplicate_exist_of_paper"
            fatal = True
        elif sense.nSenseCode == 0x80 and sense.nSenseQualifier == 0x0D:
            error_name = "paper_protection"
            fatal = True
        elif sense.nSenseCode == 0x80 and sense.nSenseQualifier == 0x08:
            error_name = "sensor_dirty"
            fatal = True
        else:
            error_name = "scan_snap_error"
            fatal = True
    elif sense.nSenseKey == 0x04:
        if sense.nSenseCode == 0x80 and sense.nSenseQualifier == 0x06:
            error_name = "optical_error"
        elif (sense.nSenseCode == 0x44 and sense.nSenseQualifier == 0x00) or (
            sense.nSenseCode == 0x80 and sense.nSenseQualifier == 0x04
        ):
            error_name = "hardware_error"
        elif sense.nSenseCode == 0x80 and sense.nSenseQualifier == 0x22:
            error_name = "battery_changing_stop"
        else:
            error_name = "hardware_error"
        fatal = True
    elif sense.nSenseKey == 0x05:
        if (
            (sense.nSenseCode == 0x00 and sense.nSenseQualifier == 0x00)
            or (sense.nSenseCode == 0x20 and sense.nSenseQualifier == 0x00)
            or (sense.nSenseCode == 0x24 and sense.nSenseQualifier == 0x00)
            or (sense.nSenseCode == 0x26 and sense.nSenseQualifier == 0x00)
        ):
            error_name = "hardware_error"
        elif sense.nSenseCode == 0x2C and sense.nSenseQualifier == 0x00:
            error_name = "scanning_jam2"
        else:
            error_name = "scan_snap_error"
        fatal = True
    elif sense.nSenseKey == 0x0B:
        error_name = "transfer_data_error"
        fatal = True

    if sense.bEOM:
        page_complete = True

    return SenseOutcome(
        ok=not fatal,
        sense=sense,
        error_name=error_name,
        retry_read=retry_read,
        hopper_empty=hopper_empty,
        page_complete=page_complete,
        fatal=fatal,
    )


def make_generic_sense_outcome(error_name: str, *, fatal: bool = True) -> SenseOutcome:
    return SenseOutcome(
        ok=not fatal,
        sense=SenseData(False, False, 0, 0, 0, 0, b""),
        error_name=error_name,
        retry_read=False,
        hopper_empty=False,
        page_complete=False,
        fatal=fatal,
    )


def decode_hardware_status(data: bytes) -> HardwareStatus:
    if len(data) != 0x20:
        raise ValueError(f"unexpected hardware-status payload length: {len(data)}")

    b2 = data[2]
    b3 = data[3]
    b4 = data[4]
    b5 = data[5]
    b12 = data[12]
    battery = data[15]
    return HardwareStatus(
        top_cover_open=bool(b2 & 0x80),
        hopper_empty=bool(b3 & 0x80),
        adf_cover_open=bool(b3 & 0x20),
        exit_cover_open=bool(b3 & 0x01),
        sleeping=bool(b4 & 0x80),
        long_paper_switch=bool(b4 & 0x20),
        scan_button=bool(b4 & 0x01),
        double_feed=bool(b5 & 0x01),
        scan_cancel=bool(b12 & 0x08),
        non_separation=bool(b12 & 0x10),
        continue_scan=bool(b12 & 0x20),
        scan_end=bool(b12 & 0x40),
        battery_power_zero=(battery == 0),
        battery_power=battery,
        raw=data,
    )
def build_trigger_ack(value: int = 0, *, key_code: int = DISCOVERY_KEY_IX1300) -> bytes:
    return struct.pack(">IIII", 0x10, key_code, value, 0)


def build_trigger_answer(value: int = 0, *, key_code: int = DISCOVERY_KEY_IX1300) -> bytes:
    return struct.pack(">IIII", 0x10, key_code, value, 0)


def recv_frame(sock: socket.socket) -> bytes:
    header = bytearray()
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            raise RuntimeError("socket closed while reading frame header")
        header.extend(chunk)

    (frame_len,) = struct.unpack(">I", header)
    if frame_len < 4:
        raise ValueError(f"invalid frame length: {frame_len}")

    frame = bytearray(header)
    while len(frame) < frame_len:
        chunk = sock.recv(frame_len - len(frame))
        if not chunk:
            raise RuntimeError(f"socket closed while reading {frame_len}-byte frame")
        frame.extend(chunk)
    return bytes(frame)


class AppIFSession:
    def __init__(self, *, target_ip: str, port2: int, local_ip: str, timeout: float = 30.0) -> None:
        self.target_ip = target_ip
        self.port2 = port2
        self.local_ip = local_ip
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None

    def __enter__(self) -> "AppIFSession":
        self.open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def open(self) -> None:
        if self.sock is not None:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.bind((self.local_ip, 0))
        sock.connect((self.target_ip, self.port2))
        self.sock = sock

    def close(self) -> None:
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def send(self, packet: bytes) -> None:
        if self.sock is None:
            raise RuntimeError("session is not open")
        self.sock.sendall(packet)

    def recv_frame(self) -> bytes:
        if self.sock is None:
            raise RuntimeError("session is not open")
        return recv_frame(self.sock)

    def reserve(
        self,
        *,
        local_mac: str,
        if_version: int,
        trigger_port: int,
        password: bytes = b"",
    ) -> ReserveReply:
        self.send(
            build_reserve_request(
                local_mac=local_mac,
                if_version=if_version,
                trigger_port=trigger_port,
                password=password,
            )
        )
        for _ in range(4):
            frame = self.recv_frame()
            if len(frame) == 0x14:
                return parse_reserve_reply(frame)
        raise RuntimeError("did not receive reserve reply frame")

    def get_device_info(self, *, local_mac: str) -> DeviceInfoReply:
        self.send(build_get_device_info_request(local_mac=local_mac))
        for _ in range(4):
            frame = self.recv_frame()
            if len(frame) == 0x70:
                return parse_device_info_reply(frame)
        raise RuntimeError("did not receive device info reply frame")

    def set_start_mode(self, *, local_mac: str, start_mode: int) -> SetStartModeReply:
        self.send(build_set_start_mode_request(local_mac=local_mac, start_mode=start_mode))
        for _ in range(4):
            frame = self.recv_frame()
            if len(frame) == 0x1C:
                return parse_set_start_mode_reply(frame)
        raise RuntimeError("did not receive set-start-mode reply frame")

    def xfer_data(
        self,
        *,
        local_mac: str,
        xfer_status: int,
        total_length: int,
        offset: int,
        payload: bytes = b"",
    ) -> XferDataReply:
        self.send(
            build_xfer_data_request(
                local_mac=local_mac,
                xfer_status=xfer_status,
                total_length=total_length,
                offset=offset,
                payload=payload,
            )
        )
        for _ in range(4):
            frame = self.recv_frame()
            if len(frame) == 0x20:
                return parse_xfer_data_reply(frame, expected_xfer_status=xfer_status)
        raise RuntimeError("did not receive xfer-data reply frame")


class ScannerIFSession:
    def __init__(self, *, target_ip: str, port1: int, local_ip: str, timeout: float = 30.0) -> None:
        self.target_ip = target_ip
        self.port1 = port1
        self.local_ip = local_ip
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self.input = None
        self.output = None
        self._connect_reply: Optional[ScannerIFReply] = None

    def __enter__(self) -> "ScannerIFSession":
        self.open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def open(self) -> ScannerIFReply:
        if self.sock is not None:
            if self._connect_reply is None:
                return ScannerIFReply(ok=True, length=0x10, key_code=DISCOVERY_KEY_IX1300, status=0, raw=b"")
            return self._connect_reply
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.bind((self.local_ip, 0))
        sock.connect((self.target_ip, self.port1))
        self.sock = sock
        ack = recv_exact(sock, 0x10)
        reply = parse_scanner_if_reply(ack)
        self._connect_reply = reply
        if not reply.ok:
            sock.close()
            self.sock = None
        return reply

    def close(self) -> None:
        if self.sock is not None:
            self.sock.close()
            self.sock = None
            self._connect_reply = None

    def send(self, packet: bytes) -> None:
        if self.sock is None:
            raise RuntimeError("scanner-if session is not open")
        self.sock.sendall(packet)

    def inquiry(self, *, local_mac: str, inquiry_status: int = 0) -> InquiryReply:
        if self.sock is None:
            raise RuntimeError("scanner-if session is not open")
        cdb, transfer_length = build_inquiry_request(inquiry_status)
        packet = build_scanner_cmd_request(
            local_mac=local_mac,
            cdb=cdb,
            transfer_length=transfer_length,
            payload=b"",
            use_mode_2=False,
        )
        self.send(packet)
        header = recv_exact(self.sock, 0x28)
        length = struct.unpack_from(">I", header, 0x00)[0]
        extra_len = max(0, length - 0x28)
        extra = recv_exact(self.sock, extra_len) if extra_len else b""
        return parse_inquiry_reply(header, extra)

    def cancel_read(self, *, local_mac: str) -> InquiryReply:
        if self.sock is None:
            raise RuntimeError("scanner-if session is not open")
        cdb, transfer_length, payload = build_cancel_read_request()
        packet = build_scanner_cmd_request(
            local_mac=local_mac,
            cdb=cdb,
            transfer_length=transfer_length,
            payload=payload,
            use_mode_2=False,
        )
        self.send(packet)
        header = recv_exact(self.sock, 0x28)
        length = struct.unpack_from(">I", header, 0x00)[0]
        extra_len = max(0, length - 0x28)
        extra = recv_exact(self.sock, extra_len) if extra_len else b""
        return parse_inquiry_reply(header, extra)

    def set_params(self, *, local_mac: str, scan_params: ScanParams) -> InquiryReply:
        if self.sock is None:
            raise RuntimeError("scanner-if session is not open")
        cdb, transfer_length, payload = build_set_params_request(scan_params)
        packet = build_scanner_cmd_request(
            local_mac=local_mac,
            cdb=cdb,
            transfer_length=transfer_length,
            payload=payload,
            use_mode_2=False,
        )
        self.send(packet)
        header = recv_exact(self.sock, 0x28)
        length = struct.unpack_from(">I", header, 0x00)[0]
        extra_len = max(0, length - 0x28)
        extra = recv_exact(self.sock, extra_len) if extra_len else b""
        return parse_inquiry_reply(header, extra)

    def start_paper(self, *, local_mac: str) -> InquiryReply:
        if self.sock is None:
            raise RuntimeError("scanner-if session is not open")
        cdb, transfer_length, payload = build_start_paper_request()
        packet = build_scanner_cmd_request(
            local_mac=local_mac,
            cdb=cdb,
            transfer_length=transfer_length,
            payload=payload,
            use_mode_2=False,
        )
        self.send(packet)
        header = recv_exact(self.sock, 0x28)
        length = struct.unpack_from(">I", header, 0x00)[0]
        extra_len = max(0, length - 0x28)
        extra = recv_exact(self.sock, extra_len) if extra_len else b""
        return parse_inquiry_reply(header, extra)

    def get_hardware_status(self, *, local_mac: str) -> tuple[HardwareStatusReply, HardwareStatus]:
        if self.sock is None:
            raise RuntimeError("scanner-if session is not open")
        cdb, transfer_length, payload = build_get_hardware_status_request()
        packet = build_scanner_cmd_request(
            local_mac=local_mac,
            cdb=cdb,
            transfer_length=transfer_length,
            payload=payload,
            use_mode_2=False,
        )
        self.send(packet)
        header = recv_exact(self.sock, 0x28)
        length = struct.unpack_from(">I", header, 0x00)[0]
        extra_len = max(0, length - 0x28)
        extra = recv_exact(self.sock, extra_len) if extra_len else b""
        reply = parse_hardware_status_reply(header, extra)
        status = decode_hardware_status(reply.data)
        return reply, status

    def start_job(self, *, local_mac: str, job_id: int, ix15xx_special: bool = False) -> InquiryReply:
        if self.sock is None:
            raise RuntimeError("scanner-if session is not open")
        cdb, transfer_length, payload = build_start_job_request(job_id, ix15xx_special=ix15xx_special)
        packet = build_scanner_cmd_request(
            local_mac=local_mac,
            cdb=cdb,
            transfer_length=transfer_length,
            payload=payload,
            use_mode_2=False,
        )
        self.send(packet)
        header = recv_exact(self.sock, 0x28)
        length = struct.unpack_from(">I", header, 0x00)[0]
        extra_len = max(0, length - 0x28)
        extra = recv_exact(self.sock, extra_len) if extra_len else b""
        return parse_inquiry_reply(header, extra)

    def read_block(self, *, local_mac: str, read_params: ReadParams) -> ReadReply:
        if self.sock is None:
            raise RuntimeError("scanner-if session is not open")
        packet = build_scanner_cmd_request(
            local_mac=local_mac,
            cdb=build_read_cdb(read_params),
            transfer_length=read_params.nTransferLen,
            payload=b"",
            use_mode_2=False,
        )
        self.send(packet)
        header = recv_exact(self.sock, 0x28)
        length = struct.unpack_from(">I", header, 0x00)[0]
        extra_len = max(0, length - 0x28)
        extra = recv_exact(self.sock, extra_len) if extra_len else b""
        return parse_read_reply(header, extra)

    def request_sense(self, *, local_mac: str) -> SenseData:
        if self.sock is None:
            raise RuntimeError("scanner-if session is not open")
        cdb, transfer_length, payload = build_request_sense_request()
        packet = build_scanner_cmd_request(
            local_mac=local_mac,
            cdb=cdb,
            transfer_length=transfer_length,
            payload=payload,
            use_mode_2=False,
        )
        self.send(packet)
        header = recv_exact(self.sock, 0x28)
        length = struct.unpack_from(">I", header, 0x00)[0]
        extra_len = max(0, length - 0x28)
        extra = recv_exact(self.sock, extra_len) if extra_len else b""
        reply = parse_inquiry_reply(header, extra)
        if reply.status != 0 or reply.scan_status != 0:
            raise RuntimeError(f"request-sense failed status={reply.status} scan_status={reply.scan_status}")
        return parse_sense_data(reply.extra_data)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    buf = bytearray()
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise RuntimeError(f"socket closed while reading {size} bytes")
        buf.extend(chunk)
    return bytes(buf)


def status_name(status: int) -> str:
    mapping = {
        0: "ok",
        STATUS_AI_PARAMETER_NG: "parameter_ng",
        STATUS_AI_PASSWORD_AVAIL_NG: "password_avail_ng",
        STATUS_AI_PASSWORD_NG: "password_ng",
        STATUS_AI_USED_BY_OTHER: "used_by_other",
        STATUS_AI_IF_VER_NG: "if_version_ng",
    }
    return mapping.get(status, f"unknown({status})")


def reserve(
    *,
    target_ip: str,
    port2: int,
    local_ip: str,
    local_mac: str,
    if_version: int,
    trigger_port: int,
    password: bytes = b"",
    timeout: float = 30.0,
) -> ReserveReply:
    with AppIFSession(target_ip=target_ip, port2=port2, local_ip=local_ip, timeout=timeout) as session:
        return session.reserve(
            local_mac=local_mac,
            if_version=if_version,
            trigger_port=trigger_port,
            password=password,
        )


def get_device_info(
    *,
    target_ip: str,
    port2: int,
    local_ip: str,
    local_mac: str,
    if_version: int,
    trigger_port: int,
    password: bytes = b"",
    timeout: float = 30.0,
) -> DeviceInfoReply:
    with AppIFSession(target_ip=target_ip, port2=port2, local_ip=local_ip, timeout=timeout) as session:
        reserve_reply = session.reserve(
            local_mac=local_mac,
            if_version=if_version,
            trigger_port=trigger_port,
            password=password,
        )
        if not reserve_reply.ok:
            raise RuntimeError(f"reserve failed with status {reserve_reply.status}")
        return session.get_device_info(local_mac=local_mac)


def monitor_trigger_once(
    *,
    local_ip: str,
    trigger_port: int,
    timeout: float = 30.0,
) -> TriggerPacket:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((local_ip, trigger_port))
    server.listen(1)
    server.settimeout(timeout)

    try:
        conn, _addr = server.accept()
        with conn:
            conn.settimeout(timeout)
            conn.sendall(build_trigger_ack())
            packet = recv_frame(conn)
            trigger = parse_trigger_packet(packet)
            conn.sendall(build_trigger_answer())
            return trigger
    finally:
        server.close()


def monitor_trigger_udp_once(
    *,
    local_ip: str,
    trigger_port: int,
    timeout: float = 30.0,
) -> TriggerPacket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((local_ip, trigger_port))
    sock.settimeout(timeout)
    try:
        while True:
            packet, addr = sock.recvfrom(2048)
            try:
                trigger = parse_trigger_packet(packet)
            except ValueError:
                continue
            try:
                sock.sendto(build_trigger_answer(), addr)
            except OSError:
                pass
            return trigger
    finally:
        sock.close()


def wait_for_trigger_once_async(
    *,
    local_ip: str,
    trigger_port: int,
    timeout: float = 30.0,
) -> tuple[threading.Thread, TriggerWaitResult]:
    result = TriggerWaitResult(trigger=None, error=None)
    lock = threading.Lock()
    errors: list[str] = []

    def record_success(trigger: TriggerPacket, transport: str) -> None:
        with lock:
            if result.trigger is None and result.error is None:
                result.trigger = trigger
                result.transport = transport

    def record_error(error: str) -> None:
        with lock:
            errors.append(error)

    def tcp_runner() -> None:
        try:
            record_success(
                monitor_trigger_once(
                    local_ip=local_ip,
                    trigger_port=trigger_port,
                    timeout=timeout,
                ),
                "tcp",
            )
        except Exception as exc:
            record_error(str(exc))

    def udp_runner() -> None:
        try:
            record_success(
                monitor_trigger_udp_once(
                    local_ip=local_ip,
                    trigger_port=trigger_port,
                    timeout=timeout,
                ),
                "udp",
            )
        except Exception as exc:
            record_error(str(exc))

    def runner() -> None:
        tcp_thread = threading.Thread(target=tcp_runner, name="ix1300-trigger-tcp", daemon=True)
        udp_thread = threading.Thread(target=udp_runner, name="ix1300-trigger-udp", daemon=True)
        tcp_thread.start()
        udp_thread.start()
        tcp_thread.join(timeout + 1.0)
        udp_thread.join(timeout + 1.0)
        with lock:
            if result.trigger is None and result.error is None:
                result.error = errors[0] if errors else "timed out"

    thread = threading.Thread(target=runner, name="ix1300-trigger-once", daemon=True)
    thread.start()
    return thread, result


def xfer_data(
    *,
    target_ip: str,
    port2: int,
    local_ip: str,
    local_mac: str,
    if_version: int,
    trigger_port: int,
    xfer_status: int,
    total_length: int,
    offset: int,
    payload: bytes = b"",
    password: bytes = b"",
    timeout: float = 30.0,
) -> XferDataReply:
    with AppIFSession(target_ip=target_ip, port2=port2, local_ip=local_ip, timeout=timeout) as session:
        reserve_reply = session.reserve(
            local_mac=local_mac,
            if_version=if_version,
            trigger_port=trigger_port,
            password=password,
        )
        if not reserve_reply.ok:
            raise RuntimeError(f"reserve failed with status {reserve_reply.status}")
        return session.xfer_data(
            local_mac=local_mac,
            xfer_status=xfer_status,
            total_length=total_length,
            offset=offset,
            payload=payload,
        )


def scanner_inquiry(
    *,
    target_ip: str,
    port1: int,
    local_ip: str,
    local_mac: str,
    inquiry_status: int = 0,
    timeout: float = 30.0,
) -> tuple[ScannerIFReply, InquiryReply]:
    session = ScannerIFSession(target_ip=target_ip, port1=port1, local_ip=local_ip, timeout=timeout)
    try:
        ack = session.open()
        reply = session.inquiry(local_mac=local_mac, inquiry_status=inquiry_status)
        return ack, reply
    finally:
        session.close()


def scanner_set_params(
    *,
    target_ip: str,
    port1: int,
    local_ip: str,
    local_mac: str,
    scan_params: ScanParams,
    timeout: float = 30.0,
) -> tuple[ScannerIFReply, InquiryReply]:
    session = ScannerIFSession(target_ip=target_ip, port1=port1, local_ip=local_ip, timeout=timeout)
    try:
        ack = session.open()
        _ = session.cancel_read(local_mac=local_mac)
        reply = session.set_params(local_mac=local_mac, scan_params=scan_params)
        return ack, reply
    finally:
        session.close()


def scanner_start_job(
    *,
    target_ip: str,
    port1: int,
    local_ip: str,
    local_mac: str,
    job_id: int,
    ix15xx_special: bool = False,
    timeout: float = 30.0,
) -> tuple[ScannerIFReply, InquiryReply]:
    session = ScannerIFSession(target_ip=target_ip, port1=port1, local_ip=local_ip, timeout=timeout)
    try:
        ack = session.open()
        reply = session.start_job(local_mac=local_mac, job_id=job_id, ix15xx_special=ix15xx_special)
        return ack, reply
    finally:
        session.close()


def scanner_prepare(
    *,
    target_ip: str,
    port1: int,
    local_ip: str,
    local_mac: str,
    scan_params: ScanParams,
    job_id: int,
    ix15xx_special: bool = False,
    timeout: float = 30.0,
) -> tuple[ScannerIFReply, InquiryReply, InquiryReply]:
    session = ScannerIFSession(target_ip=target_ip, port1=port1, local_ip=local_ip, timeout=timeout)
    try:
        ack = session.open()
        _ = session.cancel_read(local_mac=local_mac)
        set_reply = session.set_params(local_mac=local_mac, scan_params=scan_params)
        start_reply = session.start_job(local_mac=local_mac, job_id=job_id, ix15xx_special=ix15xx_special)
        return ack, set_reply, start_reply
    finally:
        session.close()


def scanner_hardware_status(
    *,
    target_ip: str,
    port1: int,
    local_ip: str,
    local_mac: str,
    timeout: float = 30.0,
) -> tuple[ScannerIFReply, HardwareStatusReply, HardwareStatus]:
    session = ScannerIFSession(target_ip=target_ip, port1=port1, local_ip=local_ip, timeout=timeout)
    try:
        ack = session.open()
        reply, status = session.get_hardware_status(local_mac=local_mac)
        return ack, reply, status
    finally:
        session.close()


def poll_hardware_status_after_start(
    *,
    target_ip: str,
    port1: int,
    port2: int,
    local_ip: str,
    local_mac: str,
    if_version: int,
    trigger_port: int,
    scan_params: ScanParams,
    job_id: int,
    poll_count: int = 5,
    poll_interval: float = 0.5,
    password: bytes = b"",
    timeout: float = 30.0,
) -> tuple[ReserveReply, ScannerIFReply, InquiryReply, InquiryReply, InquiryReply, InquiryReply, list[tuple[HardwareStatusReply, HardwareStatus]]]:
    results: list[tuple[HardwareStatusReply, HardwareStatus]] = []
    with AppIFSession(target_ip=target_ip, port2=port2, local_ip=local_ip, timeout=timeout) as app_session:
        reserve_reply = app_session.reserve(
            local_mac=local_mac,
            if_version=if_version,
            trigger_port=trigger_port,
            password=password,
        )
        if not reserve_reply.ok:
            raise RuntimeError(f"reserve failed with status {reserve_reply.status}")
        with ScannerIFSession(target_ip=target_ip, port1=port1, local_ip=local_ip, timeout=timeout) as scanner_session:
            ack = scanner_session.open()
            cancel_reply = scanner_session.cancel_read(local_mac=local_mac)
            set_reply = scanner_session.set_params(local_mac=local_mac, scan_params=scan_params)
            start_reply = scanner_session.start_job(local_mac=local_mac, job_id=job_id)
            paper_reply = scanner_session.start_paper(local_mac=local_mac)
            for idx in range(poll_count):
                if idx:
                    time.sleep(poll_interval)
                results.append(scanner_session.get_hardware_status(local_mac=local_mac))
            return reserve_reply, ack, cancel_reply, set_reply, start_reply, paper_reply, results


def prepare_scan_channels(
    *,
    target_ip: str,
    port1: int,
    port2: int,
    local_ip: str,
    local_mac: str,
    if_version: int,
    trigger_port: int,
    scan_params: ScanParams,
    job_id: int,
    password: bytes = b"",
    ix15xx_special: bool = False,
    timeout: float = 30.0,
) -> tuple[ReserveReply, ScannerIFReply, InquiryReply, InquiryReply, InquiryReply, InquiryReply]:
    with AppIFSession(target_ip=target_ip, port2=port2, local_ip=local_ip, timeout=timeout) as app_session:
        reserve_reply = app_session.reserve(
            local_mac=local_mac,
            if_version=if_version,
            trigger_port=trigger_port,
            password=password,
        )
        if not reserve_reply.ok:
            raise RuntimeError(f"reserve failed with status {reserve_reply.status}")
        with ScannerIFSession(target_ip=target_ip, port1=port1, local_ip=local_ip, timeout=timeout) as scanner_session:
            ack = scanner_session.open()
            cancel_reply = scanner_session.cancel_read(local_mac=local_mac)
            set_reply = scanner_session.set_params(local_mac=local_mac, scan_params=scan_params)
            start_reply = scanner_session.start_job(
                local_mac=local_mac,
                job_id=job_id,
                ix15xx_special=ix15xx_special,
            )
            paper_reply = scanner_session.start_paper(local_mac=local_mac)
            return reserve_reply, ack, cancel_reply, set_reply, start_reply, paper_reply


def default_read_params_for_host(host_name: str = "") -> ReadParams:
    transfer_len = 0x300000 if "ix1300" in host_name.lower() else 0x3E800
    return ReadParams(
        bFront=True,
        nDataType=0,
        nPageID=0,
        nSequenceID=0,
        nTransferLen=transfer_len,
        nTrasferMode=2,
        bMultiFeedDetect=False,
    )


def normalize_extracted_image(data: bytes) -> tuple[bytes, str]:
    signatures = (
        (b"\xff\xd8\xff", "jpeg"),
        (b"%PDF-", "pdf"),
        (b"II*\x00", "tiff"),
        (b"MM\x00*", "tiff"),
        (b"\x89PNG\r\n\x1a\n", "png"),
    )
    for magic, image_type in signatures:
        offset = data.find(magic)
        if offset != -1:
            trimmed = data[offset:]
            return trimmed, image_type
    return data, "bin"


def output_path_for_page(output_path: str, page_number: int, image_type: str = "jpg") -> str:
    if "{page}" in output_path:
        return output_path.format(page=page_number)
    dot = output_path.rfind(".")
    if dot == -1:
        base = output_path
        ext = f".{image_type}"
    else:
        base = output_path[:dot]
        ext = output_path[dot:]
    return f"{base}_{page_number:04d}{ext}"


def save_page_image(output_path: str, page_number: int, image_bytes: bytes, image_type: str) -> tuple[Optional[str], int]:
    is_real_image = image_type in {"jpeg", "pdf", "tiff", "png"} and len(image_bytes) > 128
    if not is_real_image:
        return None, 0
    ext = "jpg" if image_type == "jpeg" else image_type
    path = output_path_for_page(output_path, page_number, ext)
    with open(path, "wb") as fh:
        fh.write(image_bytes)
    return path, len(image_bytes)


def extract_one_page(
    *,
    scanner_session: ScannerIFSession,
    local_mac: str,
    read_params: ReadParams,
    page_number: int,
    output_path: str,
) -> ScanPageResult:
    paper_reply = scanner_session.start_paper(local_mac=local_mac)
    page_replies: list[ReadReply] = []
    page_chunks: list[bytes] = []
    page_sense: Optional[SenseData] = None
    page_outcome: Optional[SenseOutcome] = None

    while True:
        try:
            reply = scanner_session.read_block(local_mac=local_mac, read_params=read_params)
        except socket.timeout:
            page_outcome = make_generic_sense_outcome("read_timeout")
            break

        page_replies.append(reply)
        if reply.data:
            page_chunks.append(reply.data)

        if reply.ok:
            read_params.nSequenceID = (read_params.nSequenceID + 1) & 0xFF
            continue

        if reply.status != 0:
            page_outcome = make_generic_sense_outcome(f"status_{reply.status}")
            break

        if reply.scan_status != 2:
            page_outcome = make_generic_sense_outcome(f"scan_status_{reply.scan_status}")
            break

        page_sense = scanner_session.request_sense(local_mac=local_mac)
        page_outcome = analyze_sense(page_sense)
        if page_outcome.retry_read:
            continue
        break

    page_bytes, image_type = normalize_extracted_image(b"".join(page_chunks))
    path, image_bytes = save_page_image(output_path, page_number, page_bytes, image_type)
    return ScanPageResult(
        page_number=page_number,
        paper_reply=paper_reply,
        replies=page_replies,
        sense=page_sense,
        outcome=page_outcome,
        image_type=image_type,
        image_bytes=image_bytes,
        path=path,
    )


def extract_image_once(
    *,
    target_ip: str,
    port1: int,
    port2: int,
    local_ip: str,
    local_mac: str,
    if_version: int,
    trigger_port: int,
    scan_params: ScanParams,
    output_path: str,
    job_id: int,
    password: bytes = b"",
    ix15xx_special: bool = False,
    read_timeout: float = 5.0,
    timeout: float = 30.0,
) -> tuple[ReserveReply, ScannerIFReply, InquiryReply, InquiryReply, InquiryReply, InquiryReply, list[ReadReply]]:
    replies: list[ReadReply] = []
    with AppIFSession(target_ip=target_ip, port2=port2, local_ip=local_ip, timeout=timeout) as app_session:
        reserve_reply = app_session.reserve(
            local_mac=local_mac,
            if_version=if_version,
            trigger_port=trigger_port,
            password=password,
        )
        if not reserve_reply.ok:
            raise RuntimeError(f"reserve failed with status {reserve_reply.status}")
        with ScannerIFSession(target_ip=target_ip, port1=port1, local_ip=local_ip, timeout=timeout) as scanner_session:
            ack = scanner_session.open()
            cancel_reply = scanner_session.cancel_read(local_mac=local_mac)
            set_reply = scanner_session.set_params(local_mac=local_mac, scan_params=scan_params)
            start_reply = scanner_session.start_job(
                local_mac=local_mac,
                job_id=job_id,
                ix15xx_special=ix15xx_special,
            )
            paper_reply = scanner_session.start_paper(local_mac=local_mac)
            scanner_session.sock.settimeout(read_timeout)
            read_params = default_read_params_for_host("ix1300")
            chunks: list[bytes] = []
            for _ in range(32):
                try:
                    reply = scanner_session.read_block(local_mac=local_mac, read_params=read_params)
                except socket.timeout:
                    break
                replies.append(reply)
                if reply.data:
                    chunks.append(reply.data)
                read_params.nSequenceID = (read_params.nSequenceID + 1) & 0xFF
                if not reply.ok:
                    break
                if not reply.data:
                    break
                if len(reply.data) < read_params.nTransferLen:
                    break
            image = b"".join(chunks)
            image, _image_type = normalize_extracted_image(image)
            total_bytes = len(image)
            if total_bytes:
                with open(output_path, "wb") as fh:
                    fh.write(image)
            if total_bytes == 0:
                try:
                    import os

                    os.unlink(output_path)
                except OSError:
                    pass
            return reserve_reply, ack, cancel_reply, set_reply, start_reply, paper_reply, replies


def extract_images_multi(
    *,
    target_ip: str,
    port1: int,
    port2: int,
    local_ip: str,
    local_mac: str,
    if_version: int,
    trigger_port: int,
    scan_params: ScanParams,
    output_path: str,
    job_id: int,
    password: bytes = b"",
    ix15xx_special: bool = False,
    read_timeout: float = 5.0,
    timeout: float = 30.0,
) -> ScanSessionResult:
    with AppIFSession(target_ip=target_ip, port2=port2, local_ip=local_ip, timeout=timeout) as app_session:
        reserve_reply = app_session.reserve(
            local_mac=local_mac,
            if_version=if_version,
            trigger_port=trigger_port,
            password=password,
        )
        if not reserve_reply.ok:
            raise RuntimeError(f"reserve failed with status {reserve_reply.status}")
        return extract_images_multi_with_reservation(
            reserve_reply=reserve_reply,
            target_ip=target_ip,
            port1=port1,
            local_ip=local_ip,
            local_mac=local_mac,
            scan_params=scan_params,
            output_path=output_path,
            job_id=job_id,
            ix15xx_special=ix15xx_special,
            read_timeout=read_timeout,
            timeout=timeout,
        )


def extract_images_multi_with_reservation(
    *,
    reserve_reply: ReserveReply,
    target_ip: str,
    port1: int,
    local_ip: str,
    local_mac: str,
    scan_params: ScanParams,
    output_path: str,
    job_id: int,
    ix15xx_special: bool = False,
    read_timeout: float = 5.0,
    timeout: float = 30.0,
) -> ScanSessionResult:
    pages: list[ScanPageResult] = []
    with ScannerIFSession(target_ip=target_ip, port1=port1, local_ip=local_ip, timeout=timeout) as scanner_session:
        ack = scanner_session.open()
        cancel_reply = scanner_session.cancel_read(local_mac=local_mac)
        set_reply = scanner_session.set_params(local_mac=local_mac, scan_params=scan_params)
        start_reply = scanner_session.start_job(
            local_mac=local_mac,
            job_id=job_id,
            ix15xx_special=ix15xx_special,
        )
        scanner_session.sock.settimeout(read_timeout)
        read_params = default_read_params_for_host("ix1300")
        page_number = 1
        while True:
            try:
                page_result = extract_one_page(
                    scanner_session=scanner_session,
                    local_mac=local_mac,
                    read_params=read_params,
                    page_number=page_number,
                    output_path=output_path,
                )
            except Exception as exc:
                if pages:
                    break
                raise RuntimeError(f"start-paper failed before first page: {exc}") from exc

            if page_result.image_bytes == 0 and page_result.outcome is not None and (
                page_result.outcome.fatal or page_result.outcome.hopper_empty
            ):
                break

            pages.append(page_result)

            if page_result.outcome is None:
                break
            if page_result.outcome.fatal:
                break
            if page_result.outcome.hopper_empty:
                break
            if not page_result.outcome.page_complete:
                break

            read_params.nPageID += 1
            read_params.nSequenceID = 0
            if scan_params.nPaperHanling == 2:
                read_params.bFront = not read_params.bFront
            page_number += 1

        return ScanSessionResult(
            reserve_reply=reserve_reply,
            ack=ack,
            cancel_reply=cancel_reply,
            set_reply=set_reply,
            start_reply=start_reply,
            pages=pages,
        )


def scan_once(
    *,
    target_ip: str,
    port1: int,
    port2: int,
    local_ip: str,
    local_mac: str,
    if_version: int,
    trigger_port: int,
    scan_params: ScanParams,
    job_id: int,
    trigger_timeout: float,
    password: bytes = b"",
    ix15xx_special: bool = False,
    timeout: float = 30.0,
) -> tuple[ReserveReply, ScannerIFReply, InquiryReply, InquiryReply, InquiryReply, InquiryReply, TriggerWaitResult]:
    trigger_thread, trigger_result = wait_for_trigger_once_async(
        local_ip=local_ip,
        trigger_port=trigger_port,
        timeout=trigger_timeout,
    )
    try:
        result = prepare_scan_channels(
            target_ip=target_ip,
            port1=port1,
            port2=port2,
            local_ip=local_ip,
            local_mac=local_mac,
            if_version=if_version,
            trigger_port=trigger_port,
            scan_params=scan_params,
            job_id=job_id,
            password=password,
            ix15xx_special=ix15xx_special,
            timeout=timeout,
        )
    finally:
        trigger_thread.join(trigger_timeout + 1.0)
    return (*result, trigger_result)


def print_hosts(hosts: Iterable[HostInfo]) -> None:
    for host in hosts:
        print(
            f"{host.product_name or '?':8s} "
            f"ip={host.ip_address:<15s} "
            f"port1={host.port1:<5d} "
            f"port2={host.port2:<5d} "
            f"if=0x{host.if_version:04X} "
            f"password={'yes' if host.need_password else 'no'} "
            f"name={host.host_name or '-'}"
        )


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    discover_parser = sub.add_parser("discover", help="broadcast or unicast discovery")
    discover_parser.add_argument("--local-ip")
    discover_parser.add_argument("--local-mac")
    discover_parser.add_argument("--listen-port", type=int, default=40000)
    discover_parser.add_argument("--timeout", type=float, default=2.0)
    discover_parser.add_argument("--target-ip", help="use unicast discovery instead of broadcast")

    reserve_parser = sub.add_parser("reserve-packet", help="emit reserve request as hex")
    reserve_parser.add_argument("--local-mac", required=True)
    reserve_parser.add_argument("--if-version", type=lambda x: int(x, 0), required=True)
    reserve_parser.add_argument("--trigger-port", type=int, required=True)
    reserve_parser.add_argument("--password", default="")
    reserve_parser.add_argument("--host-type", type=int, default=1)

    reserve_run_parser = sub.add_parser("reserve", help="connect to port2 and send reserve")
    reserve_run_parser.add_argument("--target-ip", required=True)
    reserve_run_parser.add_argument("--port2", type=int, required=True)
    reserve_run_parser.add_argument("--local-ip", required=True)
    reserve_run_parser.add_argument("--local-mac", required=True)
    reserve_run_parser.add_argument("--if-version", type=lambda x: int(x, 0), required=True)
    reserve_run_parser.add_argument("--trigger-port", type=int, default=40000)
    reserve_run_parser.add_argument("--password", default="")
    reserve_run_parser.add_argument("--timeout", type=float, default=30.0)

    devinfo_parser = sub.add_parser("device-info", help="reserve app interface and read device info")
    devinfo_parser.add_argument("--target-ip", required=True)
    devinfo_parser.add_argument("--port2", type=int, required=True)
    devinfo_parser.add_argument("--local-ip", required=True)
    devinfo_parser.add_argument("--local-mac", required=True)
    devinfo_parser.add_argument("--if-version", type=lambda x: int(x, 0), required=True)
    devinfo_parser.add_argument("--trigger-port", type=int, default=40000)
    devinfo_parser.add_argument("--password", default="")
    devinfo_parser.add_argument("--timeout", type=float, default=30.0)

    trigger_parser = sub.add_parser("monitor-trigger", help="listen for one TCP trigger notification")
    trigger_parser.add_argument("--local-ip", required=True)
    trigger_parser.add_argument("--trigger-port", type=int, default=40000)
    trigger_parser.add_argument("--timeout", type=float, default=30.0)

    xfer_parser = sub.add_parser("xfer-data", help="reserve app interface and send a generic xfer-data command")
    xfer_parser.add_argument("--target-ip", required=True)
    xfer_parser.add_argument("--port2", type=int, required=True)
    xfer_parser.add_argument("--local-ip", required=True)
    xfer_parser.add_argument("--local-mac", required=True)
    xfer_parser.add_argument("--if-version", type=lambda x: int(x, 0), required=True)
    xfer_parser.add_argument("--trigger-port", type=int, default=40000)
    xfer_parser.add_argument("--xfer-status", type=lambda x: int(x, 0), required=True)
    xfer_parser.add_argument("--total-length", type=int, required=True)
    xfer_parser.add_argument("--offset", type=int, default=0)
    xfer_parser.add_argument("--payload-hex", default="")
    xfer_parser.add_argument("--password", default="")
    xfer_parser.add_argument("--timeout", type=float, default=30.0)

    inquiry_parser = sub.add_parser("scanner-inquiry", help="connect port1 and issue scanner inquiry")
    inquiry_parser.add_argument("--target-ip", required=True)
    inquiry_parser.add_argument("--port1", type=int, required=True)
    inquiry_parser.add_argument("--local-ip", required=True)
    inquiry_parser.add_argument("--local-mac", required=True)
    inquiry_parser.add_argument("--inquiry-status", type=int, default=0)
    inquiry_parser.add_argument("--timeout", type=float, default=30.0)

    hw_parser = sub.add_parser("scanner-hw-status", help="connect port1 and read scanner hardware status")
    hw_parser.add_argument("--target-ip", required=True)
    hw_parser.add_argument("--port1", type=int, required=True)
    hw_parser.add_argument("--local-ip", required=True)
    hw_parser.add_argument("--local-mac", required=True)
    hw_parser.add_argument("--timeout", type=float, default=30.0)

    set_params_parser = sub.add_parser("scanner-set-params", help="connect port1 and issue scanner set-params")
    set_params_parser.add_argument("--target-ip", required=True)
    set_params_parser.add_argument("--port1", type=int, required=True)
    set_params_parser.add_argument("--local-ip", required=True)
    set_params_parser.add_argument("--local-mac", required=True)
    set_params_parser.add_argument("--color-mode", choices=["auto", "color", "gray", "mono"], default="color")
    set_params_parser.add_argument("--quality", type=int, default=2)
    set_params_parser.add_argument("--paper-size", choices=["auto", "a4", "letter"], default="auto")
    set_params_parser.add_argument("--paper-handling", type=int, choices=[1, 2], default=1)
    set_params_parser.add_argument("--del-white-page", action="store_true")
    set_params_parser.add_argument("--bleed-through-reduction", action="store_true")
    set_params_parser.add_argument("--paper-protection", action="store_true")
    set_params_parser.add_argument("--timeout", type=float, default=30.0)

    start_job_parser = sub.add_parser("scanner-start-job", help="connect port1 and issue scanner start-job")
    start_job_parser.add_argument("--target-ip", required=True)
    start_job_parser.add_argument("--port1", type=int, required=True)
    start_job_parser.add_argument("--local-ip", required=True)
    start_job_parser.add_argument("--local-mac", required=True)
    start_job_parser.add_argument("--job-id", type=int, required=True)
    start_job_parser.add_argument("--ix15xx-special", action="store_true")
    start_job_parser.add_argument("--timeout", type=float, default=30.0)

    prepare_parser = sub.add_parser("scanner-prepare", help="connect port1 then issue set-params and start-job")
    prepare_parser.add_argument("--target-ip", required=True)
    prepare_parser.add_argument("--port1", type=int, required=True)
    prepare_parser.add_argument("--local-ip", required=True)
    prepare_parser.add_argument("--local-mac", required=True)
    prepare_parser.add_argument("--color-mode", choices=["auto", "color", "gray", "mono"], default="color")
    prepare_parser.add_argument("--quality", type=int, default=2)
    prepare_parser.add_argument("--paper-size", choices=["auto", "a4", "letter"], default="auto")
    prepare_parser.add_argument("--paper-handling", type=int, choices=[1, 2], default=1)
    prepare_parser.add_argument("--del-white-page", action="store_true")
    prepare_parser.add_argument("--bleed-through-reduction", action="store_true")
    prepare_parser.add_argument("--paper-protection", action="store_true")
    prepare_parser.add_argument("--job-id", type=int, default=0)
    prepare_parser.add_argument("--ix15xx-special", action="store_true")
    prepare_parser.add_argument("--timeout", type=float, default=30.0)

    full_prepare_parser = sub.add_parser("scan-prepare", help="reserve port2, then cancel-read, set-params, and start-job on port1")
    full_prepare_parser.add_argument("--target-ip", required=True)
    full_prepare_parser.add_argument("--port1", type=int, required=True)
    full_prepare_parser.add_argument("--port2", type=int, required=True)
    full_prepare_parser.add_argument("--local-ip", required=True)
    full_prepare_parser.add_argument("--local-mac", required=True)
    full_prepare_parser.add_argument("--if-version", type=lambda x: int(x, 0), required=True)
    full_prepare_parser.add_argument("--trigger-port", type=int, default=40000)
    full_prepare_parser.add_argument("--password", default="")
    full_prepare_parser.add_argument("--color-mode", choices=["auto", "color", "gray", "mono"], default="color")
    full_prepare_parser.add_argument("--quality", type=int, default=2)
    full_prepare_parser.add_argument("--paper-size", choices=["auto", "a4", "letter"], default="auto")
    full_prepare_parser.add_argument("--paper-handling", type=int, choices=[1, 2], default=1)
    full_prepare_parser.add_argument("--del-white-page", action="store_true")
    full_prepare_parser.add_argument("--bleed-through-reduction", action="store_true")
    full_prepare_parser.add_argument("--paper-protection", action="store_true")
    full_prepare_parser.add_argument("--job-id", type=int, default=0)
    full_prepare_parser.add_argument("--ix15xx-special", action="store_true")
    full_prepare_parser.add_argument("--timeout", type=float, default=30.0)

    hw_poll_parser = sub.add_parser("scan-hw-poll", help="arm the scanner then poll hardware status on port1")
    hw_poll_parser.add_argument("--target-ip", required=True)
    hw_poll_parser.add_argument("--port1", type=int, required=True)
    hw_poll_parser.add_argument("--port2", type=int, required=True)
    hw_poll_parser.add_argument("--local-ip", required=True)
    hw_poll_parser.add_argument("--local-mac", required=True)
    hw_poll_parser.add_argument("--if-version", type=lambda x: int(x, 0), required=True)
    hw_poll_parser.add_argument("--trigger-port", type=int, default=40000)
    hw_poll_parser.add_argument("--password", default="")
    hw_poll_parser.add_argument("--color-mode", choices=["auto", "color", "gray", "mono"], default="color")
    hw_poll_parser.add_argument("--quality", type=int, default=2)
    hw_poll_parser.add_argument("--paper-size", choices=["auto", "a4", "letter"], default="auto")
    hw_poll_parser.add_argument("--paper-handling", type=int, choices=[1, 2], default=1)
    hw_poll_parser.add_argument("--del-white-page", action="store_true")
    hw_poll_parser.add_argument("--bleed-through-reduction", action="store_true")
    hw_poll_parser.add_argument("--paper-protection", action="store_true")
    hw_poll_parser.add_argument("--job-id", type=int, default=0)
    hw_poll_parser.add_argument("--poll-count", type=int, default=5)
    hw_poll_parser.add_argument("--poll-interval", type=float, default=0.5)
    hw_poll_parser.add_argument("--timeout", type=float, default=30.0)

    scan_once_parser = sub.add_parser("scan-once", help="arm the scanner and wait for one TCP trigger notification")
    scan_once_parser.add_argument("--target-ip", required=True)
    scan_once_parser.add_argument("--port1", type=int, required=True)
    scan_once_parser.add_argument("--port2", type=int, required=True)
    scan_once_parser.add_argument("--local-ip", required=True)
    scan_once_parser.add_argument("--local-mac", required=True)
    scan_once_parser.add_argument("--if-version", type=lambda x: int(x, 0), required=True)
    scan_once_parser.add_argument("--trigger-port", type=int, default=40000)
    scan_once_parser.add_argument("--trigger-timeout", type=float, default=30.0)
    scan_once_parser.add_argument("--password", default="")
    scan_once_parser.add_argument("--color-mode", choices=["auto", "color", "gray", "mono"], default="color")
    scan_once_parser.add_argument("--quality", type=int, default=2)
    scan_once_parser.add_argument("--paper-size", choices=["auto", "a4", "letter"], default="auto")
    scan_once_parser.add_argument("--paper-handling", type=int, choices=[1, 2], default=1)
    scan_once_parser.add_argument("--del-white-page", action="store_true")
    scan_once_parser.add_argument("--bleed-through-reduction", action="store_true")
    scan_once_parser.add_argument("--paper-protection", action="store_true")
    scan_once_parser.add_argument("--job-id", type=int, default=0)
    scan_once_parser.add_argument("--ix15xx-special", action="store_true")
    scan_once_parser.add_argument("--timeout", type=float, default=30.0)

    extract_parser = sub.add_parser("scan-extract", help="arm the scanner and extract one or more pages from port1")
    extract_parser.add_argument("--target-ip", required=True)
    extract_parser.add_argument("--port1", type=int, required=True)
    extract_parser.add_argument("--port2", type=int, required=True)
    extract_parser.add_argument("--local-ip", required=True)
    extract_parser.add_argument("--local-mac", required=True)
    extract_parser.add_argument("--if-version", type=lambda x: int(x, 0), required=True)
    extract_parser.add_argument("--trigger-port", type=int, default=40000)
    extract_parser.add_argument("--password", default="")
    extract_parser.add_argument("--color-mode", choices=["auto", "color", "gray", "mono"], default="color")
    extract_parser.add_argument("--quality", type=int, default=2)
    extract_parser.add_argument("--paper-size", choices=["auto", "a4", "letter"], default="auto")
    extract_parser.add_argument("--paper-handling", type=int, choices=[1, 2], default=1)
    extract_parser.add_argument("--del-white-page", action="store_true")
    extract_parser.add_argument("--bleed-through-reduction", action="store_true")
    extract_parser.add_argument("--paper-protection", action="store_true")
    extract_parser.add_argument("--job-id", type=int, default=0)
    extract_parser.add_argument("--ix15xx-special", action="store_true")
    extract_parser.add_argument("--output", required=True, help="base output path; pages are saved as suffixed files unless {page} is present")
    extract_parser.add_argument("--read-timeout", type=float, default=5.0)
    extract_parser.add_argument("--timeout", type=float, default=30.0)

    args = parser.parse_args(argv)

    if args.cmd == "discover":
        local_ip = args.local_ip or guess_local_ip_for_target(args.target_ip or "255.255.255.255")
        local_mac = args.local_mac or guess_local_mac()
        hosts = discover(
            local_ip=local_ip,
            local_mac=local_mac,
            listen_port=args.listen_port,
            timeout=args.timeout,
            target_ip=args.target_ip,
        )
        print_hosts(hosts)
        return 0

    if args.cmd == "reserve-packet":
        packet = build_reserve_request(
            local_mac=args.local_mac,
            if_version=args.if_version,
            trigger_port=args.trigger_port,
            password=args.password.encode("utf-8"),
            host_type=args.host_type,
        )
        print(packet.hex())
        return 0

    if args.cmd == "reserve":
        reply = reserve(
            target_ip=args.target_ip,
            port2=args.port2,
            local_ip=args.local_ip,
            local_mac=args.local_mac,
            if_version=args.if_version,
            trigger_port=args.trigger_port,
            password=args.password.encode("utf-8"),
            timeout=args.timeout,
        )
        print(f"raw={reply.raw.hex()}")
        print(f"status={reply.status} ({status_name(reply.status)}) if_version=0x{reply.if_version:04X} ok={reply.ok}")
        return 0 if reply.ok else 2

    if args.cmd == "device-info":
        reply = get_device_info(
            target_ip=args.target_ip,
            port2=args.port2,
            local_ip=args.local_ip,
            local_mac=args.local_mac,
            if_version=args.if_version,
            trigger_port=args.trigger_port,
            password=args.password.encode("utf-8"),
            timeout=args.timeout,
        )
        print(f"raw={reply.raw.hex()}")
        print(f"status={reply.status} ({status_name(reply.status)}) host_name={reply.host_name!r} ok={reply.ok}")
        return 0 if reply.ok else 2

    if args.cmd == "monitor-trigger":
        trigger = monitor_trigger_once(
            local_ip=args.local_ip,
            trigger_port=args.trigger_port,
            timeout=args.timeout,
        )
        print(
            f"cmd=0x{trigger.cmd:08X} sequence={trigger.sequence_id} "
            f"sensor={trigger.sensor.hex()} raw={trigger.raw.hex()}"
        )
        return 0

    if args.cmd == "xfer-data":
        payload = bytes.fromhex(args.payload_hex) if args.payload_hex else b""
        reply = xfer_data(
            target_ip=args.target_ip,
            port2=args.port2,
            local_ip=args.local_ip,
            local_mac=args.local_mac,
            if_version=args.if_version,
            trigger_port=args.trigger_port,
            xfer_status=args.xfer_status,
            total_length=args.total_length,
            offset=args.offset,
            payload=payload,
            password=args.password.encode("utf-8"),
            timeout=args.timeout,
        )
        print(f"raw={reply.raw.hex()}")
        print(
            f"status={reply.status} ({status_name(reply.status)}) "
            f"echoed_xfer_status=0x{reply.echoed_xfer_status:08X} ok={reply.ok}"
        )
        return 0 if reply.ok else 2

    if args.cmd == "scanner-inquiry":
        ack, reply = scanner_inquiry(
            target_ip=args.target_ip,
            port1=args.port1,
            local_ip=args.local_ip,
            local_mac=args.local_mac,
            inquiry_status=args.inquiry_status,
            timeout=args.timeout,
        )
        print(f"ack_raw={ack.raw.hex()} ack_ok={ack.ok} ack_status={ack.status}")
        print(
            f"inquiry_ok={reply.ok} status={reply.status} scan_status={reply.scan_status} "
            f"fixed={reply.fixed_block.hex()} extra={reply.extra_data.hex()} raw={reply.raw.hex()}"
        )
        return 0 if reply.ok else 2

    if args.cmd == "scanner-hw-status":
        ack, reply, status = scanner_hardware_status(
            target_ip=args.target_ip,
            port1=args.port1,
            local_ip=args.local_ip,
            local_mac=args.local_mac,
            timeout=args.timeout,
        )
        print(f"ack_raw={ack.raw.hex()} ack_ok={ack.ok} ack_status={ack.status}")
        print(
            f"hw_ok={reply.ok} status={reply.status} scan_status={reply.scan_status} "
            f"fixed={reply.fixed_block.hex()} data={reply.data.hex()} raw={reply.raw.hex()}"
        )
        print(
            f"flags hopper_empty={status.hopper_empty} adf_cover_open={status.adf_cover_open} "
            f"scan_button={status.scan_button} continue_scan={status.continue_scan} "
            f"scan_end={status.scan_end} battery={status.battery_power}"
        )
        return 0 if reply.ok else 2

    if args.cmd == "scanner-set-params":
        scan_params = build_default_scan_params(
            color_mode=args.color_mode,
            quality=args.quality,
            paper_size=args.paper_size,
            paper_handling=args.paper_handling,
            del_white_page=args.del_white_page,
            bleed_through_reduction=args.bleed_through_reduction,
            ix1300_paper_protection=args.paper_protection,
        )
        ack, reply = scanner_set_params(
            target_ip=args.target_ip,
            port1=args.port1,
            local_ip=args.local_ip,
            local_mac=args.local_mac,
            scan_params=scan_params,
            timeout=args.timeout,
        )
        print(f"ack_raw={ack.raw.hex()} ack_ok={ack.ok} ack_status={ack.status}")
        print(
            f"set_params_ok={reply.ok} status={reply.status} scan_status={reply.scan_status} "
            f"fixed={reply.fixed_block.hex()} extra={reply.extra_data.hex()} raw={reply.raw.hex()}"
        )
        return 0 if reply.ok else 2

    if args.cmd == "scanner-start-job":
        ack, reply = scanner_start_job(
            target_ip=args.target_ip,
            port1=args.port1,
            local_ip=args.local_ip,
            local_mac=args.local_mac,
            job_id=args.job_id,
            ix15xx_special=args.ix15xx_special,
            timeout=args.timeout,
        )
        print(f"ack_raw={ack.raw.hex()} ack_ok={ack.ok} ack_status={ack.status}")
        print(
            f"start_job_ok={reply.ok} status={reply.status} scan_status={reply.scan_status} "
            f"fixed={reply.fixed_block.hex()} extra={reply.extra_data.hex()} raw={reply.raw.hex()}"
        )
        return 0 if reply.ok else 2

    if args.cmd == "scanner-prepare":
        scan_params = build_default_scan_params(
            color_mode=args.color_mode,
            quality=args.quality,
            paper_size=args.paper_size,
            paper_handling=args.paper_handling,
            del_white_page=args.del_white_page,
            bleed_through_reduction=args.bleed_through_reduction,
            ix1300_paper_protection=args.paper_protection,
        )
        ack, set_reply, start_reply = scanner_prepare(
            target_ip=args.target_ip,
            port1=args.port1,
            local_ip=args.local_ip,
            local_mac=args.local_mac,
            scan_params=scan_params,
            job_id=args.job_id,
            ix15xx_special=args.ix15xx_special,
            timeout=args.timeout,
        )
        print(f"ack_raw={ack.raw.hex()} ack_ok={ack.ok} ack_status={ack.status}")
        print(
            f"set_params_ok={set_reply.ok} status={set_reply.status} scan_status={set_reply.scan_status} "
            f"fixed={set_reply.fixed_block.hex()} extra={set_reply.extra_data.hex()} raw={set_reply.raw.hex()}"
        )
        print(
            f"start_job_ok={start_reply.ok} status={start_reply.status} scan_status={start_reply.scan_status} "
            f"fixed={start_reply.fixed_block.hex()} extra={start_reply.extra_data.hex()} raw={start_reply.raw.hex()}"
        )
        return 0 if (set_reply.ok and start_reply.ok) else 2

    if args.cmd == "scan-prepare":
        scan_params = build_default_scan_params(
            color_mode=args.color_mode,
            quality=args.quality,
            paper_size=args.paper_size,
            paper_handling=args.paper_handling,
            del_white_page=args.del_white_page,
            bleed_through_reduction=args.bleed_through_reduction,
            ix1300_paper_protection=args.paper_protection,
        )
        reserve_reply, ack, cancel_reply, set_reply, start_reply, paper_reply = prepare_scan_channels(
            target_ip=args.target_ip,
            port1=args.port1,
            port2=args.port2,
            local_ip=args.local_ip,
            local_mac=args.local_mac,
            if_version=args.if_version,
            trigger_port=args.trigger_port,
            scan_params=scan_params,
            job_id=args.job_id,
            password=args.password.encode("utf-8"),
            ix15xx_special=args.ix15xx_special,
            timeout=args.timeout,
        )
        print(f"reserve_raw={reserve_reply.raw.hex()} reserve_ok={reserve_reply.ok} reserve_status={reserve_reply.status}")
        print(f"ack_raw={ack.raw.hex()} ack_ok={ack.ok} ack_status={ack.status}")
        print(
            f"cancel_ok={cancel_reply.ok} status={cancel_reply.status} scan_status={cancel_reply.scan_status} "
            f"fixed={cancel_reply.fixed_block.hex()} extra={cancel_reply.extra_data.hex()} raw={cancel_reply.raw.hex()}"
        )
        print(
            f"set_params_ok={set_reply.ok} status={set_reply.status} scan_status={set_reply.scan_status} "
            f"fixed={set_reply.fixed_block.hex()} extra={set_reply.extra_data.hex()} raw={set_reply.raw.hex()}"
        )
        print(
            f"start_job_ok={start_reply.ok} status={start_reply.status} scan_status={start_reply.scan_status} "
            f"fixed={start_reply.fixed_block.hex()} extra={start_reply.extra_data.hex()} raw={start_reply.raw.hex()}"
        )
        print(
            f"start_paper_ok={paper_reply.ok} status={paper_reply.status} scan_status={paper_reply.scan_status} "
            f"fixed={paper_reply.fixed_block.hex()} extra={paper_reply.extra_data.hex()} raw={paper_reply.raw.hex()}"
        )
        return 0 if (reserve_reply.ok and cancel_reply.ok and set_reply.ok and start_reply.ok and paper_reply.ok) else 2

    if args.cmd == "scan-hw-poll":
        scan_params = build_default_scan_params(
            color_mode=args.color_mode,
            quality=args.quality,
            paper_size=args.paper_size,
            paper_handling=args.paper_handling,
            del_white_page=args.del_white_page,
            bleed_through_reduction=args.bleed_through_reduction,
            ix1300_paper_protection=args.paper_protection,
        )
        reserve_reply, ack, cancel_reply, set_reply, start_reply, paper_reply, hw_results = poll_hardware_status_after_start(
            target_ip=args.target_ip,
            port1=args.port1,
            port2=args.port2,
            local_ip=args.local_ip,
            local_mac=args.local_mac,
            if_version=args.if_version,
            trigger_port=args.trigger_port,
            scan_params=scan_params,
            job_id=args.job_id,
            poll_count=args.poll_count,
            poll_interval=args.poll_interval,
            password=args.password.encode("utf-8"),
            timeout=args.timeout,
        )
        print(f"reserve_raw={reserve_reply.raw.hex()} reserve_ok={reserve_reply.ok} reserve_status={reserve_reply.status}")
        print(f"ack_raw={ack.raw.hex()} ack_ok={ack.ok} ack_status={ack.status}")
        print(f"cancel_ok={cancel_reply.ok} set_ok={set_reply.ok} start_ok={start_reply.ok} paper_ok={paper_reply.ok}")
        for idx, (reply, status) in enumerate(hw_results, start=1):
            print(
                f"hw[{idx}] ok={reply.ok} status={reply.status} scan_status={reply.scan_status} "
                f"hopper_empty={status.hopper_empty} adf_cover_open={status.adf_cover_open} "
                f"scan_button={status.scan_button} continue_scan={status.continue_scan} "
                f"scan_end={status.scan_end} data={reply.data.hex()}"
            )
        return 0

    if args.cmd == "scan-once":
        scan_params = build_default_scan_params(
            color_mode=args.color_mode,
            quality=args.quality,
            paper_size=args.paper_size,
            paper_handling=args.paper_handling,
            del_white_page=args.del_white_page,
            bleed_through_reduction=args.bleed_through_reduction,
            ix1300_paper_protection=args.paper_protection,
        )
        reserve_reply, ack, cancel_reply, set_reply, start_reply, paper_reply, trigger_result = scan_once(
            target_ip=args.target_ip,
            port1=args.port1,
            port2=args.port2,
            local_ip=args.local_ip,
            local_mac=args.local_mac,
            if_version=args.if_version,
            trigger_port=args.trigger_port,
            scan_params=scan_params,
            job_id=args.job_id,
            trigger_timeout=args.trigger_timeout,
            password=args.password.encode("utf-8"),
            ix15xx_special=args.ix15xx_special,
            timeout=args.timeout,
        )
        print(f"reserve_raw={reserve_reply.raw.hex()} reserve_ok={reserve_reply.ok} reserve_status={reserve_reply.status}")
        print(f"ack_raw={ack.raw.hex()} ack_ok={ack.ok} ack_status={ack.status}")
        print(
            f"cancel_ok={cancel_reply.ok} status={cancel_reply.status} scan_status={cancel_reply.scan_status} "
            f"fixed={cancel_reply.fixed_block.hex()} extra={cancel_reply.extra_data.hex()} raw={cancel_reply.raw.hex()}"
        )
        print(
            f"set_params_ok={set_reply.ok} status={set_reply.status} scan_status={set_reply.scan_status} "
            f"fixed={set_reply.fixed_block.hex()} extra={set_reply.extra_data.hex()} raw={set_reply.raw.hex()}"
        )
        print(
            f"start_job_ok={start_reply.ok} status={start_reply.status} scan_status={start_reply.scan_status} "
            f"fixed={start_reply.fixed_block.hex()} extra={start_reply.extra_data.hex()} raw={start_reply.raw.hex()}"
        )
        print(
            f"start_paper_ok={paper_reply.ok} status={paper_reply.status} scan_status={paper_reply.scan_status} "
            f"fixed={paper_reply.fixed_block.hex()} extra={paper_reply.extra_data.hex()} raw={paper_reply.raw.hex()}"
        )
        if trigger_result.trigger is not None:
            print(
                f"trigger_ok=True cmd=0x{trigger_result.trigger.cmd:08X} sequence={trigger_result.trigger.sequence_id} "
                f"sensor={trigger_result.trigger.sensor.hex()} raw={trigger_result.trigger.raw.hex()}"
            )
            return 0
        if trigger_result.error is not None:
            print(f"trigger_ok=False error={trigger_result.error}")
        else:
            print("trigger_ok=False error=unknown")
        return 3

    if args.cmd == "scan-extract":
        scan_params = build_default_scan_params(
            color_mode=args.color_mode,
            quality=args.quality,
            paper_size=args.paper_size,
            paper_handling=args.paper_handling,
            del_white_page=args.del_white_page,
            bleed_through_reduction=args.bleed_through_reduction,
            ix1300_paper_protection=args.paper_protection,
        )
        scan_result = extract_images_multi(
            target_ip=args.target_ip,
            port1=args.port1,
            port2=args.port2,
            local_ip=args.local_ip,
            local_mac=args.local_mac,
            if_version=args.if_version,
            trigger_port=args.trigger_port,
            scan_params=scan_params,
            output_path=args.output,
            job_id=args.job_id,
            password=args.password.encode("utf-8"),
            ix15xx_special=args.ix15xx_special,
            read_timeout=args.read_timeout,
            timeout=args.timeout,
        )
        print(
            f"reserve_raw={scan_result.reserve_reply.raw.hex()} "
            f"reserve_ok={scan_result.reserve_reply.ok} reserve_status={scan_result.reserve_reply.status}"
        )
        print(f"ack_raw={scan_result.ack.raw.hex()} ack_ok={scan_result.ack.ok} ack_status={scan_result.ack.status}")
        print(
            f"cancel_ok={scan_result.cancel_reply.ok} "
            f"set_ok={scan_result.set_reply.ok} start_ok={scan_result.start_reply.ok}"
        )
        total_bytes = sum(page.image_bytes for page in scan_result.pages)
        print(f"pages={len(scan_result.pages)} total_bytes={total_bytes} output_base={args.output}")
        for page in scan_result.pages:
            outcome = page.outcome
            sense = page.sense
            paper_reply = page.paper_reply
            sense_text = "none"
            if isinstance(sense, SenseData):
                sense_text = (
                    f"key=0x{sense.nSenseKey:02X} asc=0x{sense.nSenseCode:02X} "
                    f"ascq=0x{sense.nSenseQualifier:02X} eom={sense.bEOM} ili={sense.bILI}"
                )
            outcome_text = "none"
            if isinstance(outcome, SenseOutcome):
                outcome_text = (
                    f"error={outcome.error_name} retry={outcome.retry_read} "
                    f"hopper_empty={outcome.hopper_empty} page_complete={outcome.page_complete} fatal={outcome.fatal}"
                )
            print(
                f"page[{page.page_number}] paper_ok={paper_reply.ok} bytes={page.image_bytes} type={page.image_type} "
                f"path={page.path} sense={sense_text} outcome={outcome_text}"
            )
            for idx, reply in enumerate(page.replies, start=1):
                print(
                    f"page[{page.page_number}].read[{idx}] ok={reply.ok} status={reply.status} "
                    f"scan_status={reply.scan_status} len={len(reply.data)}"
                )
        return 0 if total_bytes > 0 else 4

    return 1


if __name__ == "__main__":
    sys.exit(main())
