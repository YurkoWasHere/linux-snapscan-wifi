# ScanSnap iX1300 Wi-Fi Protocol

This document describes the PFU private Wi-Fi protocol used by the ScanSnap iX1300 as implemented in this repository and mapped from the Android app.

Primary implementation:

- `ix1300_proto.py`

Primary reverse-engineering source:

- `apktool-out/`

## Overview

The iX1300 does not use eSCL/AirScan, IPP Scan, or WSD.

It uses:

- UDP discovery on `52217`
- TCP app interface on `port2`
- TCP scanner interface on `port1`
- binary PFU frames with key code `0x56454E53` (`VENS`)

## Roles

- `port2`: app interface
  - reserve
  - device info
  - other PFU app commands
- `port1`: scanner interface
  - inquiry
  - scan parameter setup
  - start paper/feed
  - read image blocks
  - request sense

## Discovery

Discovery request:

- transport: UDP
- destination: `255.255.255.255:52217`
- family key: `0x56454E53`
- request length: `0x20`

Discovery request layout:

| Offset | Size | Meaning |
|---|---:|---|
| `0x00` | 4 | key code |
| `0x04` | 4 | password flag |
| `0x08` | 4 | local IPv4 |
| `0x0C` | 6 | local MAC |
| `0x12` | 2 | padding |
| `0x14` | 4 | callback/listen port |
| `0x18` | 2 | status word, observed `0x0010` |
| `0x1A` | 2 | zero |
| `0x1C` | 4 | zero |

Discovery response:

- source: scanner UDP `52217`
- destination: sender UDP source port

Observed response fields:

| Offset | Size | Meaning |
|---|---:|---|
| `0x00` | 4 | key code |
| `0x04` | 2 | notify code |
| `0x06` | 2 | status |
| `0x08` | 2 | interface version |
| `0x0A` | 2 | host type |
| `0x0C` | 4 | password-required |
| `0x10` | 4 | scanner IPv4 |
| `0x14` | 4 | `port1` |
| `0x18` | 4 | `port2` |
| `0x1C` | 6 | scanner MAC |
| `0x28` | 64 | host name |
| later | variable | product name |

Observed iX1300 values:

- host type: `0x0030`
- IF version: `0x0010`

## App Interface (`port2`)

### Reserve

Command:

- command ID: `0x11`

Observed request length:

- `0x80`

Important request fields:

| Offset | Size | Meaning |
|---|---:|---|
| `0x00` | 4 | packet length |
| `0x04` | 4 | key code |
| `0x08` | 4 | command `0x11` |
| `0x10` | 6 | local MAC |
| `0x20` | 2 | IF version |
| `0x22` | 1 | trigger port low byte in current prototype layout |
| `0x24` | 4 | host type |
| `0x28` | 4 | password-present flag |
| `0x2C` | 4 | trigger port |
| `0x34` | 0x30 | password field |

Reserve reply:

- length: `0x14`

Observed layout:

| Offset | Size | Meaning |
|---|---:|---|
| `0x00` | 4 | length |
| `0x04` | 4 | key code |
| `0x08` | 4 | status |
| `0x0C` | 2 | IF version |

Observed success:

- status `0`

### Device Info

Command:

- command ID: `0x13`

Reply length:

- `0x70`

Useful field:

- host name at `0x10..0x50`

## Scanner Interface (`port1`)

When TCP connects to `port1`, the scanner immediately sends a 16-byte ACK frame:

```text
00000010 56454e53 00000000 00000000
```

General scanner command transport:

- send PFU scanner frame
- receive at least `0x28` bytes
- if reply length is larger than `0x28`, read trailing data payload

## Scanner Commands

### Inquiry

CDB:

- `0x12`

Variants:

- standard inquiry
- VPD/JBMS inquiry

### Cancel Read

CDB:

- `0xD8`

### Set Params

CDB:

- `0xD4`

Payload:

- `0x50` or `0x80` bytes depending on auto-color block

This configures:

- color mode
- resolution
- paper size handling
- white-page deletion
- bleed-through reduction
- paper handling mode
- window/image format parameters

### Start Job

CDB:

- `0xD5`

Payload:

- 8 bytes
- contains job id

### Start Paper

CDB:

- `0xE0`

This advances the feeder for the next page.

### Get Hardware Status

CDB:

- 10 bytes
- opcode `0xC2`
- byte `8 = 0x20`

Expected payload:

- `0x20` bytes

Currently decoded:

- hopper empty
- cover/open style bits
- scan button
- continue-scan
- scan-end
- battery value

### Read Image/Data Block

CDB:

- 12 bytes
- opcode `0x28`

Read CDB layout:

| Offset | Size | Meaning |
|---|---:|---|
| `0x00` | 1 | `0x28` |
| `0x01` | 1 | zero |
| `0x02` | 1 | data type |
| `0x03` | 1 | transfer mode |
| `0x04` | 1 | zero |
| `0x05` | 1 | front/back flag |
| `0x06` | 1 | transfer length high |
| `0x07` | 1 | transfer length mid |
| `0x08` | 1 | transfer length low |
| `0x09` | 1 | zero |
| `0x0A` | 1 | page id |
| `0x0B` | 1 | sequence id |

Observed working values for image extraction:

- `data type = 0`
- `transfer mode = 2`
- `front = true`
- `page id = 0, 1, 2...`
- `sequence id = 0` per page, increment each successful read
- `transfer length = 0x300000` on iX1300

Read reply behavior:

- `status = 0`, `scan_status = 0`: normal data
- `status = 0`, `scan_status = 2`: check condition, follow with `REQUEST SENSE`

Returned image payloads are raw image streams. For JPEG pages, the scanner may prepend a small non-image prefix before `FF D8`; the implementation trims to the first known image signature.

## Request Sense

CDB:

- 6 bytes
- `03 00 00 00 12 00`

Expected sense payload:

- `0x12` bytes

Parsed fields:

| Byte/Field | Meaning |
|---|---|
| byte 2 bit `0x40` | `EOM` |
| byte 2 bit `0x20` | `ILI` |
| byte 2 low nibble | sense key |
| bytes `3..6` | information |
| byte `12` | sense code |
| byte `13` | sense qualifier |

Current mapped handling:

- `sense key 0x03, ASC 0x80, ASCQ 0x03`: hopper empty
- `sense key 0x03, ASC 0x80, ASCQ 0x13`: lack data, retry
- `sense key 0x03, ASC 0x80, ASCQ 0x01/0x0B`: jam
- `sense key 0x03, ASC 0x80, ASCQ 0x02`: ADF cover open
- `sense key 0x03, ASC 0x80, ASCQ 0x07`: multifeed
- `sense key 0x03, ASC 0x80, ASCQ 0x0D`: paper protection
- `sense key 0x04 ...`: hardware/battery/optical class errors
- `sense key 0x05 ...`: invalid request / some hardware conditions
- `sense key 0x0B ...`: transfer/data errors

The important page-completion bit is:

- `EOM = true`

## Scan Flow

Working scan flow in this repository:

1. discover scanner
2. connect app interface `port2`
3. reserve scanner
4. connect scanner interface `port1`
5. `cancelRead`
6. `setParams`
7. `startJob`
8. per page:
   - `startPaper`
   - `READ` until check-condition
   - `REQUEST SENSE`
   - if `EOM`, finish page
   - if retry condition, repeat read
   - if hopper empty or fatal error, stop
9. save returned image payload(s)

## Multiple Pages

The APK loops pages using:

- `nPageID += 1`
- `nSequenceID = 0`

For duplex-like flows it also toggles:

- `bFront`

This repository now follows the same pattern for repeated ADF pages.

## Output Formats

Currently validated:

- JPEG

Saved files are generated as:

- `base_0001.jpg`
- `base_0002.jpg`

or through a template path containing `{page}`.

## Known Limits

- not all sense/error branches are mapped yet
- hardware-status bit mapping is partial
- PDF/TIFF-specific assembly paths are not fully implemented
- duplex behavior needs more live validation

## Implementation Reference

See:

- [ix1300_proto.py](/home/user/snapscan/ix1300_proto.py)
- [README.md](/home/user/snapscan/README.md)
