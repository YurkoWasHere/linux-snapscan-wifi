# eSCL Bridge Prototype

This directory contains a small eSCL-style HTTP bridge for the iX1300.

It translates a subset of the Mopria eSCL/AirScan model onto the working iX1300 Wi-Fi protocol implementation in this repo.

## What It Provides

- `GET /eSCL/ScannerCapabilities`
- `GET /eSCL/ScannerStatus`
- `POST /eSCL/ScanJobs`
- `GET /eSCL/ScanJobs/<id>`
- `GET /eSCL/ScanJobs/<id>/NextDocument`

## Current Scope

This is a bridge prototype, not a certification-level eSCL implementation.

What works:

- create a scan job over HTTP
- map basic scan settings:
  - input source
  - color mode
  - resolution
  - document format
- return a scanned document when the job is complete

Current limitations:

- no DNS-SD / mDNS advertising yet
- no TLS / authentication
- no platen support
- JPEG output returns the first scanned page
- PDF output can combine multiple pages if Pillow is available

## Run

```bash
python3 escl/ix1300_escl_bridge.py \
  --bind 127.0.0.1 \
  --port 8080 \
  --target-ip 192.168.40.63 \
  --port1 53218 \
  --port2 53219 \
  --local-ip 192.168.40.62 \
  --local-mac fc:b3:aa:c7:b4:1f \
  --if-version 0x10 \
  --trigger-port 40000 \
  --output-dir ./escl_scans
```

Then inspect:

```bash
curl -s http://127.0.0.1:8080/eSCL/ScannerCapabilities
curl -s http://127.0.0.1:8080/eSCL/ScannerStatus
```

## Notes

The next step for real AirScan compatibility would be:

1. add DNS-SD advertisement for `_uscan._tcp`
2. broaden XML compatibility with existing eSCL clients
3. validate against `sane-airscan`
