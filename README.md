# ScanSnap iX1300 Wi-Fi Reverse Engineering

This repository contains a working Python prototype for talking to a Fujitsu/PFU ScanSnap iX1300 over its private Wi-Fi protocol.

Current status:

- discovery works
- app-interface reserve works
- scanner-interface control works
- image extraction works
- multi-page extraction works
- basic `REQUEST SENSE` end-of-page/error handling works

This is not a SANE backend yet. It is a protocol implementation and test harness.

## Files

- `ix1300_proto.py`: main protocol client and CLI
- `ix1300_button_service.py`: background listener for scanner button triggers
- `ix1300_bridge.py`: local HTTP/JSON bridge
- `README.protocol.md`: protocol-level notes and packet structure

## Requirements

- Python 3.10+
- network access to the scanner on Wi-Fi
- scanner IP, `port1`, `port2`, local IP, and local MAC

No third-party Python packages are required.

## Quick Start

Discovery:

```bash
cd /home/user/snapscan
python3 ix1300_proto.py discover \
  --listen-port 40000
```

Typical output:

```text
cjyah26000 ip=192.168.40.63   port1=53218 port2=53219 if=0x0010 password=no name=iX1300-CJYAH20000
```

Single or multi-page scan extraction:

```bash
python3 ix1300_proto.py scan-extract \
  --target-ip 192.168.40.63 \
  --port1 53218 \
  --port2 53219 \
  --if-version 0x10 \
  --trigger-port 40000 \
  --color-mode color \
  --quality 2 \
  --paper-size auto \
  --paper-handling 1 \
  --job-id 0 \
  --output /tmp/ix1300_scan.jpg
```

For multiple sheets, the command saves:

- `/tmp/ix1300_scan_0001.jpg`
- `/tmp/ix1300_scan_0002.jpg`
- ...

If you want a page template explicitly:

```bash
python3 ix1300_proto.py scan-extract \
  ... \
  --output '/tmp/page_{page}.jpg'
```

Button-trigger service:

```bash
python3 ix1300_button_service.py \
  --local-ip 192.168.40.62 \
  --local-mac fc:b3:aa:c7:b4:1f \
  --if-version 0x10 \
  --target-ip 192.168.40.63 \
  --port1 53218 \
  --port2 53219 \
  --trigger-port 40000 \
  --start-mode quick \
  --paper-handling uturn \
  --output-dir ./scans
```

When the scanner sends trigger command `0x1` for `scan papers`, the service starts a scan and saves pages under a timestamped subdirectory in `./scans`.

## Practical Workflow

1. Run `discover` to confirm the scanner IP and ports.
2. Load one or more pages in the ADF.
3. Run `scan-extract`.
4. Collect the generated JPEG files.
5. If you want the physical scanner button to start scans, run `ix1300_button_service.py` and leave it running.

## Important Commands

Reserve only:

```bash
python3 ix1300_proto.py reserve \
  --target-ip 192.168.40.63 \
  --port2 53219 \
  --local-ip 192.168.40.62 \
  --local-mac fc:b3:aa:c7:00:00 \
  --if-version 0x10 \
  --trigger-port 40000
```

Device info:

```bash
python3 ix1300_proto.py device-info \
  --target-ip 192.168.40.63 \
  --port2 53219 \
  --local-ip 192.168.40.62 \
  --local-mac fc:b3:aa:c7:00:00 \
  --if-version 0x10 \
  --trigger-port 40000
```

Hardware status:

```bash
python3 ix1300_proto.py scanner-hw-status \
  --target-ip 192.168.40.63 \
  --port1 53218 \
  --local-ip 192.168.40.62 \
  --local-mac fc:b3:aa:c7:00:00
```

## Scan Options

The current `scan-extract` command exposes these scan-related options.

### Paper Size

Supported values:

- `auto`
- `a4`
- `letter`

Example:

```bash
--paper-size auto
```

### Color Mode

Supported values:

- `color`
- `gray`
- `mono`
- `auto`

Notes:

- `color`, `gray`, and `mono` are the most practically validated.
- `auto` is mapped into the parameter block, but the extraction path has been tested mostly with standard image settings.

Example:

```bash
--color-mode color
```

### Quality

Supported values:

- `0`
- `1`
- `2`
- `3`

These map to internal resolution presets used in the parameter block.

Example:

```bash
--quality 2
```

### Paper Handling

Supported values:

- `1` = `U-turn Scan`
- `2` = `Return Scan`

This controls the iX1300 paper path mode and affects scan parameters.

Meaning:

- `1` / `U-turn Scan`
  - batch scanning from the ADF paper chute
  - paper is fed through the scanner and ejected onto the stacker
  - suited for scanning multiple sheets at once

- `2` / `Return Scan`
  - one sheet at a time through the manual feeder
  - paper is returned toward you from the same opening
  - suited for thick documents such as plastic cards, business cards, and postcards

Example:

```bash
--paper-handling 1
```

### Image Cleanup / Protection Flags

Supported flags:

- `--del-white-page`
- `--bleed-through-reduction`
- `--paper-protection`

Example:

```bash
--del-white-page --bleed-through-reduction
```

## Duplex And Output Format Status

### Duplex

The protocol and APK clearly support front/back scan state through page and side tracking.

Current state in this repository:

- multi-page ADF extraction works
- page state and side toggling are partially implemented internally
- a clean user-facing duplex option is not exposed yet
- duplex needs more live validation before it should be treated as a finished feature

### Output Formats

Currently validated:

- JPEG extraction

Not implemented yet as finished user-facing outputs:

- PDF assembly
- TIFF output
- combined multi-page PDF export

So the practical answer today is:

- use JPEG output
- expect files like `scan_0001.jpg`, `scan_0002.jpg`, etc.

## Bridge

There is also a local bridge:

```bash
python3 ix1300_bridge.py --bind 127.0.0.1 --port 18080
```

That bridge is useful for integration work, but `ix1300_proto.py scan-extract` is the simplest path for direct scanning.

## Button Service

`ix1300_button_service.py` keeps a reservation open on `port2`, listens on the trigger port, and starts a scan when the scanner sends `TRIGGER_COMMAND_SCAN_PAPER (0x1)`.

Notes:

- it listens on both TCP and UDP trigger transport
- it sets the scanner start mode before waiting; `quick` is the default
- it reconnects if the scanner sends a release trigger
- each button-initiated scan is written into its own timestamped directory
- a sample `systemd` unit is provided in `ix1300-button-scan.service`

To install as a service on a Linux host, adjust the addresses in `ix1300-button-scan.service`, then copy it into your systemd unit directory and enable it.

## What Works

- UDP discovery
- manual-IP discovery
- `port2` reserve
- `port2` device info
- `port1` inquiry
- `port1` cancel-read
- `port1` set-params
- `port1` start-job
- `port1` start-paper
- `port1` read blocks
- `port1` request sense
- multi-page ADF extraction to JPEG files
- background button-trigger listener that starts scans

## Known Gaps

- not packaged as a SANE backend
- sense/error mapping is partial, not exhaustive
- output is currently focused on JPEG image extraction
- duplex and PDF assembly need more validation
- service is still a simple foreground Python daemon, not a packaged install

## SANE Direction

This scanner does not use eSCL/AirScan. It uses PFU’s private binary protocol.

So SANE support will require one of:

- a native SANE backend that speaks this protocol
- a local bridge/adapter that exposes a SANE-friendly interface

The current code is enough to start that work, because it can already reserve the scanner, arm a job, and extract image data from multiple pages.

## Protocol Notes

See [README.protocol.md](README.protocol.md) for packet and flow details.
