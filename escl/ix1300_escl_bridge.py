#!/usr/bin/env python3
"""Minimal eSCL bridge for the iX1300 Wi-Fi protocol."""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional


REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sane.runtime import Ix1300SaneAdapter, SaneScanOptions

try:
    from PIL import Image
except ImportError:  # pragma: no cover - optional dependency
    Image = None


NS_SCAN = "http://schemas.hp.com/imaging/escl/2011/05/03"
NS_PWG = "http://www.pwg.org/schemas/2010/12/sm"
ET.register_namespace("scan", NS_SCAN)
ET.register_namespace("pwg", NS_PWG)


def qname(ns: str, tag: str) -> str:
    return f"{{{ns}}}{tag}"


def text_or_none(element: Optional[ET.Element]) -> Optional[str]:
    if element is None or element.text is None:
        return None
    return element.text.strip()


@dataclass(slots=True)
class EsclJob:
    job_id: str
    options: SaneScanOptions
    document_format: str
    state: str = "Pending"
    state_reason: str = "JobQueued"
    paths: list[str] = field(default_factory=list)
    document_path: Optional[str] = None
    error: Optional[str] = None
    document_served: bool = False


class EsclServerState:
    def __init__(
        self,
        *,
        adapter: Ix1300SaneAdapter,
        output_dir: Path,
        base_url: str,
    ) -> None:
        self.adapter = adapter
        self.output_dir = output_dir
        self.base_url = base_url.rstrip("/")
        self.jobs: dict[str, EsclJob] = {}
        self.lock = threading.Lock()
        self.active_job_id: Optional[str] = None
        self.last_error_reason: Optional[str] = None
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def scanner_state(self) -> str:
        with self.lock:
            if self.active_job_id is not None:
                return "Processing"
            if self.last_error_reason == "MediaJam":
                return "Stopped"
            return "Idle"

    def create_job(self, *, options: SaneScanOptions, document_format: str) -> EsclJob:
        job_id = uuid.uuid4().hex
        job = EsclJob(job_id=job_id, options=options, document_format=document_format)
        with self.lock:
            self.jobs[job_id] = job
        thread = threading.Thread(target=self._run_job, args=(job_id,), daemon=True)
        thread.start()
        return job

    def _run_job(self, job_id: str) -> None:
        with self.lock:
            job = self.jobs[job_id]
            self.active_job_id = job_id
            self.last_error_reason = None
            job.state = "Processing"
            job.state_reason = "JobScanning"

        try:
            job_dir = self.output_dir / job_id
            _scan_result, summary = self.adapter.scan_to_jpeg_pages(
                options=job.options,
                output_dir=job_dir,
                job_id=0,
            )
            with self.lock:
                job.paths = summary.paths

            document_path = self._materialize_document(job)
            with self.lock:
                job.document_path = str(document_path)
                job.state = "Completed"
                job.state_reason = "JobCompletedSuccessfully"
        except Exception as exc:
            with self.lock:
                job.error = str(exc)
                if "scan produced no pages" in job.error:
                    job.state = "Canceled"
                    job.state_reason = "ResourcesAreNotReady"
                    self.last_error_reason = "InputTrayEmpty"
                else:
                    job.state = "Aborted"
                    job.state_reason = "JobCanceledBySystem"
                    self.last_error_reason = "JobCanceledBySystem"
        finally:
            with self.lock:
                if self.active_job_id == job_id:
                    self.active_job_id = None

    def _materialize_document(self, job: EsclJob) -> Path:
        if not job.paths:
            raise RuntimeError("scan produced no pages")
        if job.document_format == "application/pdf":
            if Image is None:
                raise RuntimeError("PDF output requires Pillow")
            image_paths = [Path(path) for path in job.paths]
            output_path = self.output_dir / job.job_id / "document.pdf"
            with Image.open(image_paths[0]) as first:
                converted = first.convert("RGB")
                rest = []
                for path in image_paths[1:]:
                    with Image.open(path) as image:
                        rest.append(image.convert("RGB"))
                converted.save(output_path, "PDF", save_all=True, append_images=rest)
            return output_path
        return Path(job.paths[0])

    def get_job(self, job_id: str) -> Optional[EsclJob]:
        with self.lock:
            return self.jobs.get(job_id)

    def delete_job(self, job_id: str) -> bool:
        with self.lock:
            return self.jobs.pop(job_id, None) is not None

    def claim_document(self, job_id: str) -> tuple[Optional[EsclJob], Optional[str], Optional[str]]:
        with self.lock:
            job = self.jobs.get(job_id)
            if job is None:
                return None, None, None
            if job.document_path is None:
                return job, None, None
            if job.document_served:
                return job, None, "served"
            job.document_served = True
            return job, job.document_path, None


def parse_scan_settings(xml_bytes: bytes) -> tuple[SaneScanOptions, str]:
    root = ET.fromstring(xml_bytes)
    source = text_or_none(root.find(f".//{qname(NS_SCAN, 'InputSource')}")) or "ADF"
    color_mode = text_or_none(root.find(f".//{qname(NS_SCAN, 'ColorMode')}")) or "RGB24"
    x_res = text_or_none(root.find(f".//{qname(NS_SCAN, 'XResolution')}")) or "200"
    document_format = text_or_none(root.find(f".//{qname(NS_PWG, 'DocumentFormat')}")) or "image/jpeg"

    mode_map = {
        "RGB24": "Color",
        "Grayscale8": "Gray",
        "BlackAndWhite1": "Lineart",
    }
    source_map = {
        "ADF": "ADF",
        "Feeder": "ADF",
        "ADFDuplex": "ADF",
        "Platen": "ADF",
        "Return": "Return",
    }

    options = SaneScanOptions(
        mode=mode_map.get(color_mode, "Color"),
        resolution=int(x_res),
        source=source_map.get(source, "ADF"),
        page_size="auto",
        blank_page_skip=False,
        bleed_through_reduction=False,
        paper_protection=False,
    )
    return options, document_format


def build_capabilities_xml(base_url: str) -> bytes:
    def add_setting_profile(parent: ET.Element) -> None:
        profiles = ET.SubElement(parent, qname(NS_SCAN, "SettingProfiles"))
        profile = ET.SubElement(profiles, qname(NS_SCAN, "SettingProfile"))

        color_modes = ET.SubElement(profile, qname(NS_SCAN, "ColorModes"))
        for mode in ("RGB24", "Grayscale8", "BlackAndWhite1"):
            ET.SubElement(color_modes, qname(NS_SCAN, "ColorMode")).text = mode

        formats = ET.SubElement(profile, qname(NS_SCAN, "DocumentFormats"))
        for fmt in ("image/jpeg", "application/pdf"):
            ET.SubElement(formats, qname(NS_PWG, "DocumentFormat")).text = fmt
            ET.SubElement(formats, qname(NS_SCAN, "DocumentFormatExt")).text = fmt

        supported = ET.SubElement(profile, qname(NS_SCAN, "SupportedResolutions"))
        discrete = ET.SubElement(supported, qname(NS_SCAN, "DiscreteResolutions"))
        for dpi in ("150", "200", "300", "600"):
            resolution = ET.SubElement(discrete, qname(NS_SCAN, "DiscreteResolution"))
            ET.SubElement(resolution, qname(NS_SCAN, "XResolution")).text = dpi
            ET.SubElement(resolution, qname(NS_SCAN, "YResolution")).text = dpi

        intents = ET.SubElement(parent, qname(NS_SCAN, "SupportedIntents"))
        for intent in ("Document", "TextAndGraphic", "Photo"):
            ET.SubElement(intents, qname(NS_SCAN, "Intent")).text = intent

    root = ET.Element(qname(NS_SCAN, "ScannerCapabilities"))
    ET.SubElement(root, qname(NS_PWG, "Version")).text = "2.5"
    ET.SubElement(root, qname(NS_PWG, "MakeAndModel")).text = "PFU ScanSnap iX1300"
    ET.SubElement(root, qname(NS_PWG, "SerialNumber")).text = "ix1300-escl-bridge"
    ET.SubElement(root, qname(NS_SCAN, "UUID")).text = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, base_url)}"
    ET.SubElement(root, qname(NS_SCAN, "AdminURI")).text = f"{base_url}/eSCL"

    platen = ET.SubElement(root, qname(NS_SCAN, "Platen"))
    platen_caps = ET.SubElement(platen, qname(NS_SCAN, "PlatenInputCaps"))
    ET.SubElement(platen_caps, qname(NS_SCAN, "MinWidth")).text = "1"
    ET.SubElement(platen_caps, qname(NS_SCAN, "MaxWidth")).text = "2550"
    ET.SubElement(platen_caps, qname(NS_SCAN, "MinHeight")).text = "1"
    ET.SubElement(platen_caps, qname(NS_SCAN, "MaxHeight")).text = "4200"
    ET.SubElement(platen_caps, qname(NS_SCAN, "MaxOpticalXResolution")).text = "600"
    ET.SubElement(platen_caps, qname(NS_SCAN, "MaxOpticalYResolution")).text = "600"
    add_setting_profile(platen_caps)

    feeder = ET.SubElement(root, qname(NS_SCAN, "Adf"))
    feeder_caps = ET.SubElement(feeder, qname(NS_SCAN, "AdfSimplexInputCaps"))
    ET.SubElement(feeder_caps, qname(NS_SCAN, "MinWidth")).text = "1"
    ET.SubElement(feeder_caps, qname(NS_SCAN, "MaxWidth")).text = "2550"
    ET.SubElement(feeder_caps, qname(NS_SCAN, "MinHeight")).text = "1"
    ET.SubElement(feeder_caps, qname(NS_SCAN, "MaxHeight")).text = "4200"
    ET.SubElement(feeder_caps, qname(NS_SCAN, "MaxOpticalXResolution")).text = "600"
    ET.SubElement(feeder_caps, qname(NS_SCAN, "MaxOpticalYResolution")).text = "600"
    add_setting_profile(feeder_caps)
    ET.SubElement(feeder, qname(NS_SCAN, "FeederCapacity")).text = "20"
    adf_options = ET.SubElement(feeder, qname(NS_SCAN, "AdfOptions"))
    ET.SubElement(adf_options, qname(NS_SCAN, "AdfOption")).text = "DetectPaperLoaded"

    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def build_status_xml(state: EsclServerState) -> bytes:
    root = ET.Element(qname(NS_SCAN, "ScannerStatus"))
    ET.SubElement(root, qname(NS_PWG, "Version")).text = "2.5"
    ET.SubElement(root, qname(NS_PWG, "State")).text = state.scanner_state()
    if state.last_error_reason is not None:
        reasons = ET.SubElement(root, qname(NS_PWG, "StateReasons"))
        ET.SubElement(reasons, qname(NS_PWG, "StateReason")).text = state.last_error_reason

    active_job_id = state.active_job_id
    if active_job_id is not None:
        job = state.get_job(active_job_id)
        if job is not None:
            jobs = ET.SubElement(root, qname(NS_SCAN, "Jobs"))
            info = ET.SubElement(jobs, qname(NS_SCAN, "JobInfo"))
            ET.SubElement(info, qname(NS_PWG, "JobUri")).text = f"/eSCL/ScanJobs/{job.job_id}"
            ET.SubElement(info, qname(NS_PWG, "JobState")).text = job.state
            reasons = ET.SubElement(info, qname(NS_PWG, "JobStateReasons"))
            ET.SubElement(reasons, qname(NS_PWG, "JobStateReason")).text = job.state_reason

    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def build_job_info_xml(job: EsclJob) -> bytes:
    root = ET.Element(qname(NS_SCAN, "JobInfo"))
    ET.SubElement(root, qname(NS_PWG, "JobUri")).text = f"/eSCL/ScanJobs/{job.job_id}"
    ET.SubElement(root, qname(NS_PWG, "JobState")).text = job.state
    reasons = ET.SubElement(root, qname(NS_PWG, "JobStateReasons"))
    ET.SubElement(reasons, qname(NS_PWG, "JobStateReason")).text = job.state_reason
    if job.document_path:
        ET.SubElement(root, qname(NS_SCAN, "DocumentUri")).text = f"/eSCL/ScanJobs/{job.job_id}/NextDocument"
    if job.error:
        ET.SubElement(root, qname(NS_SCAN, "ErrorMessage")).text = job.error
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


class EsclHandler(BaseHTTPRequestHandler):
    server_version = "ix1300-escl/0.1"

    @property
    def state(self) -> EsclServerState:
        return self.server.state  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        if self.path == "/eSCL/ScannerCapabilities":
            self._send_xml(build_capabilities_xml(self.state.base_url))
            return
        if self.path == "/eSCL/ScannerStatus":
            self._send_xml(build_status_xml(self.state))
            return
        if self.path.startswith("/eSCL/ScanJobs/"):
            self._handle_job_get()
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        if self.path == "/eSCL/ScanJobs":
            self._handle_create_job()
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_DELETE(self) -> None:
        if self.path.startswith("/eSCL/ScanJobs/"):
            self._handle_job_delete()
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def _handle_create_job(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        options, document_format = parse_scan_settings(body)
        job = self.state.create_job(options=options, document_format=document_format)
        location = f"/eSCL/ScanJobs/{job.job_id}"
        self.send_response(HTTPStatus.CREATED)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _handle_job_get(self) -> None:
        parts = self.path.split("/")
        if len(parts) < 4:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        job_id = parts[3]
        job = self.state.get_job(job_id)
        if job is None:
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        if len(parts) == 5 and parts[4] == "NextDocument":
            claimed_job, document_path_str, claim_error = self.state.claim_document(job_id)
            if claimed_job is None:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            if document_path_str is None:
                if job.state == "Aborted":
                    self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, job.error or "scan failed")
                elif claim_error == "served":
                    self.send_error(HTTPStatus.NOT_FOUND, "no more documents")
                else:
                    self.send_error(HTTPStatus.SERVICE_UNAVAILABLE, "document not ready")
                return
            document_path = Path(document_path_str)
            payload = document_path.read_bytes()
            content_type = "application/pdf" if document_path.suffix.lower() == ".pdf" else "image/jpeg"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        self._send_xml(build_job_info_xml(job))

    def _handle_job_delete(self) -> None:
        parts = self.path.split("/")
        if len(parts) < 4:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        job_id = parts[3]
        if not self.state.delete_job(job_id):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _send_xml(self, payload: bytes) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/xml; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args) -> None:
        message = format % args
        sys.stderr.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--target-ip", required=True)
    parser.add_argument("--port1", type=int, required=True)
    parser.add_argument("--port2", type=int, required=True)
    parser.add_argument("--local-ip", required=True)
    parser.add_argument("--local-mac", required=True)
    parser.add_argument("--if-version", type=lambda x: int(x, 0), required=True)
    parser.add_argument("--trigger-port", type=int, default=40000)
    parser.add_argument("--password", default="")
    parser.add_argument("--output-dir", default="escl_scans")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--read-timeout", type=float, default=8.0)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    adapter = Ix1300SaneAdapter(
        target_ip=args.target_ip,
        port1=args.port1,
        port2=args.port2,
        local_ip=args.local_ip,
        local_mac=args.local_mac,
        if_version=args.if_version,
        trigger_port=args.trigger_port,
        timeout=args.timeout,
        read_timeout=args.read_timeout,
        password=args.password.encode("utf-8"),
    )
    base_url = f"http://{args.bind}:{args.port}"
    state = EsclServerState(
        adapter=adapter,
        output_dir=Path(args.output_dir),
        base_url=base_url,
    )

    server = ThreadingHTTPServer((args.bind, args.port), EsclHandler)
    server.state = state  # type: ignore[attr-defined]
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
