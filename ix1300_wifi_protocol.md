# ScanSnap iX1300 Wi-Fi Protocol Notes

This document maps the PFU/ScanSnap Wi-Fi protocol as implemented by the Android app in `ScanSnap Connect Application 2.8.21`.

It is based on static analysis of the APK under `apktool-out/`.

## Scope

This is not a complete protocol specification yet.

What is mapped here:

- Device discovery
- Discovery packet structure
- Connection stages
- Known service ports and channel roles
- Reserve request structure
- Trigger channel behavior
- Transfer entry points

What remains partially unknown:

- Full reserve response layout
- Full scanner-interface command formats
- Full transfer-data request/response layouts
- Complete trigger payload semantics

## Python Bridge

There is now a local HTTP/JSON bridge in `ix1300_bridge.py`.

Purpose:

- keep an app-interface session open across calls
- expose read-only protocol operations to other processes
- provide a cleaner integration point for a future SANE backend or adapter

It currently supports:

- `POST /discover`
- `POST /sessions`
- `GET /sessions`
- `POST /sessions/<id>/device-info`
- `DELETE /sessions/<id>`
- `POST /trigger/monitor-once`
- `GET /healthz`

### Start The Bridge

```bash
python3 ix1300_bridge.py --bind 127.0.0.1 --port 18080
```

### Discover

```bash
curl -s http://127.0.0.1:18080/discover \
  -H 'Content-Type: application/json' \
  -d '{
    "local_ip": "192.168.40.62",
    "local_mac": "fc:b3:aa:c7:b4:1f",
    "listen_port": 40000
  }'
```

### Open A Reserved Session

```bash
curl -s http://127.0.0.1:18080/sessions \
  -H 'Content-Type: application/json' \
  -d '{
    "target_ip": "192.168.40.63",
    "port2": 53219,
    "local_ip": "192.168.40.62",
    "local_mac": "fc:b3:aa:c7:b4:1f",
    "if_version": "0x10",
    "trigger_port": 40000
  }'
```

### Query Device Info Through A Session

```bash
curl -s http://127.0.0.1:18080/sessions/<session-id>/device-info \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### Close A Session

```bash
curl -s -X DELETE http://127.0.0.1:18080/sessions/<session-id>
```

### Trigger Monitor

This listens for one TCP trigger notification, sends the standard ACK, parses one
`0x30`-byte trigger packet, sends the standard trigger answer, and returns the packet
fields as JSON.

```bash
curl -s http://127.0.0.1:18080/trigger/monitor-once \
  -H 'Content-Type: application/json' \
  -d '{
    "local_ip": "192.168.40.62",
    "trigger_port": 40000,
    "timeout": 30
  }'
```

## High-Level Architecture

The app uses a custom PFU binary protocol over Wi-Fi.

It does not appear to use:

- eSCL / AirScan
- IPP Scan
- WSD Scan
- SOAP / WS-* scanner discovery
- mDNS/Bonjour scanner services

Instead, it uses:

- UDP broadcast/unicast for discovery
- TCP for two persistent scanner channels
- TCP and/or UDP for asynchronous trigger notifications

## Main Components In The APK

- `com.fujitsu.pfu.net.DeviceFinder`
- `com.fujitsu.pfu.net.SSDevCtl`
- `com.fujitsu.pfu.net.HostInfo`
- `com.fujitsu.pfu.net.SSDef`
- `com.fujitsu.pfu.net.ConnectionManager`

## Discovery

### Broadcast Port

Discovery uses UDP broadcast port:

- `52217` decimal
- `0xCBF9` hex

The app sends discovery packets to:

- `255.255.255.255:52217`

It also supports unicast/manual-IP discovery.

### Discovery Transport

Two response paths are implemented:

- UDP discovery response handling
- TCP callback-style discovery response handling

The app listens locally on a user-configurable receive port and parses returned `HostInfo` records.

### Discovery Packet Families

The app uses different 32-bit key codes depending on product family:

- `0x56454E53` for `ix100`, `ix500`, `ix1300`
- `0x73734E52` for `ix1500`, `ix1600`
- `0x53574642` for PC-origin packets

For the iX1300, use:

- `0x56454E53`

### Discovery Request Layout

The request is built by `DeviceFinder.PrepareSendData(...)`.

There are two request sizes:

- `0x1C` bytes for non-scanner/PC-side packets
- `0x20` bytes for scanner-family packets

For iX1300 discovery, the relevant format is:

| Offset | Size | Meaning |
|---|---:|---|
| `0x00` | 4 | key code (`0x56454E53`) |
| `0x04` | 4 | password-required flag |
| `0x08` | 4 | local IPv4 address as int |
| `0x0C` | 6 | local MAC bytes |
| `0x12` | 2 | padding |
| `0x14` | 4 | callback port / receive port |
| `0x18` | 2 | notify code or command code |
| `0x1A` | 2 | status |
| `0x1C` | 4 | extra field present for scanner-family packets; varies by family/IF version |

Observed notify codes in discovery-related parsing:

- `0x0000` not connected
- `0x0001` connected
- `0x8001` keepalive (`-0x7fff` as signed short)

### Discovery Response Layout

Parsed by `DeviceFinder.ParseRecvSearchData(...)`.

The canonical response size is:

- TCP: `0x68` bytes
- UDP: `0x7C` bytes, but the embedded search record is still parsed as the same structure

Parsed fields:

| Offset | Size | Meaning |
|---|---:|---|
| `0x00` | 4 | key code |
| `0x04` | 2 | notify code |
| `0x06` | 2 | status, must be `0` |
| `0x08` | 2 | interface version |
| `0x0A` | 2 | host type |
| `0x0C` | 4 | needs-password flag |
| `0x10` | 4 | scanner IPv4 address |
| `0x14` | 4 | `port1` |
| `0x18` | 4 | `port2` |
| `0x1C` | 8 | MAC address bytes |
| `0x24` | 4 or split fields | status/action info depending on IF version |
| `0x28` | 64 | hostname |
| `0x68` | 16 | product name for scanner hosts |

Notes:

- `hostType == 0x30` indicates scanner.
- Product name is lowercased by the app.
- For scanner devices the product string includes values like `ix1300`.

### Meaning of `port1` and `port2`

From `SSDevCtl`:

- `port1` is used by `connectScannerIF(...)`
- `port2` is used by `connectAppIF(...)`

The APK’s error enums strongly suggest:

- `port1` = scanner interface (`SI`)
- `port2` = app interface (`AI`)

## Connection Flow

The observed connection sequence is:

1. Discover scanner via UDP broadcast or manual IP/unicast.
2. Parse discovery reply into `HostInfo`.
3. Extract scanner IP, `port1`, `port2`, IF version, product name, password flag.
4. Connect TCP app interface to `port2`.
5. Send reserve request over app interface.
6. Reserve request includes a local trigger port.
7. Start local trigger server on that trigger port.
8. Connect scanner interface to `port1`.
9. Use scanner/app channels for commands and transfer.
10. Receive scan events and release notices on the trigger channel.

## App Interface vs Scanner Interface

### App Interface (`port2`)

Used for:

- reserve/release
- app-side binary requests
- transfer-data entry point (`doXferData`)

### Scanner Interface (`port1`)

Used for:

- inquiry
- sense/status operations
- scanner control operations

## Known Command IDs

From `SSDef`:

| Command | Hex | Meaning |
|---|---:|---|
| `CMD_RESERVE` | `0x11` | reserve scanner |
| `CMD_RELEASE` | `0x12` | release scanner |
| `CMD_GET_DEV_INFO` | `0x13` | get device info |
| `CMD_SET_DEV_INFO` | `0x14` | set device info |
| `CMD_UPDATE_PSW` | `0x15` | update password |
| `CMD_GET_WIFI_STATUS` | `0x30` | get Wi-Fi status |
| `CMD_SET_WIFI_MODE` | `0x31` | set Wi-Fi mode |
| `CMD_XFER_DATA` | `0x50` | transfer data |
| `CMD_FIRM_UPDATE` | `0x51` | firmware update |
| `CMD_SET_START_MODE` | `0x62` | set startup mode |

## Reserve Request

Reserve is constructed by `prepareReserveRequest(...)` and sent over the app interface.

The reserve packet size depends on IF version and product family:

- default older size: `0x80`
- IF version `0x100..0x1FF`: `0x180`
- IF version `0x10`: special-case path
- iX1300 forces packet size back to `0x80`

### Reserve Request Fields

Observed layout prefix:

| Offset | Size | Meaning |
|---|---:|---|
| `0x00` | 4 | total packet length |
| `0x04` | 4 | key code (`SSDef.KEY_CODE`) |
| `0x08` | 4 | command = `0x11` |
| `0x0C` | 4 | status/reserved = `0` |
| `0x10` | 6 | local MAC |
| `0x16` | 2 | padding |
| `0x18` | 4 | reserved |
| `0x1C` | 4 | reserved |
| `0x20` | 2 | IF version |
| `0x22` | 1 | trigger port low 8 bits? stored as byte from caller arg |
| `0x23` | 1 | padding |
| `0x24` | 4 | host type |
| `0x28` | 4 | password-present flag |
| `0x2C` | 4 | trigger port |
| `0x30` | 4 | second integer from caller, likely timeout / mode / sequence field |
| `0x34` | 0x30 | password buffer |
| ... | ... | timestamp and trailing fields |

Observed host types in reserve request:

- `1` = mobile
- `2` = Wi-Fi tool
- `3` = firmware update tool

For the Android app, reserve uses:

- host type `1`

The app passes:

- password bytes
- password length
- local trigger port
- a constant `0x1E`
- host type `1`

That constant may be a timeout, lease time, or reservation mode.

## Trigger Channel

The reserve request includes a trigger port, and the app starts a local trigger server after reserving.

The trigger channel is used for asynchronous events such as:

- scan-paper notification
- release-scanner normal
- release-scanner enforce
- release-scanner battery-save-mode

Known trigger command values from `SSDef`:

| Trigger Command | Hex |
|---|---:|
| `SCAN_PAPER` | `0x01` |
| `RELEASE_SCANNER_NORMAL` | `0x10` |
| `RELEASE_SCANNER_ENFORCE` | `0x11` |
| `RELEASE_SCANNER_ORDER` | `0x12` |
| `RELEASE_SCANNER_BATTERY_SAVE_MODE` | `0x22` |

The app implements:

- TCP trigger server loop
- UDP trigger server loop

It also sends ACK/answer packets for trigger messages.

## Data Transfer

Image/data transfer is entered through:

- `SSDevCtl.doXferData(...)`

That path:

1. Connects app interface
2. Sends `CMD_XFER_DATA`
3. Reads structured answer packets

Related flags from `SSDef`:

- `XFER_DATA_STATUS_START = 0x80`
- `XFER_DATA_STATUS_MID = 0x40`
- `XFER_DATA_STATUS_END = 0x20`

This suggests segmented transfer blocks with explicit phase flags.

## Direct Connect / SoftAP Mode

The app and help docs confirm iX1300 supports direct-connect mode.

Operationally this is still the same PFU protocol, just over the scanner’s direct Wi‑Fi link rather than through an access point.

## Manual IP Support

The app explicitly supports:

- entering a scanner IP manually

That means full discovery can be bypassed if the scanner IP is known, but the custom control protocol still remains the same after that.

## Practical Python Implementation Plan

Recommended implementation order:

1. UDP discovery request builder
2. UDP discovery response parser
3. Manual-IP unicast discovery
4. TCP connection to `port1` and `port2`
5. Reserve request builder
6. Trigger server listener
7. Minimal status command
8. Transfer-data command

## Current Python Prototype

The companion file:

- `ix1300_proto.py`

implements:

- discovery request encoding
- discovery response parsing
- UDP discovery CLI
- reserve request encoding prototype

## Source Pointers

Main analysis references:

- `apktool-out/smali_classes2/com/fujitsu/pfu/net/DeviceFinder.smali`
- `apktool-out/smali_classes2/com/fujitsu/pfu/net/SSDevCtl.smali`
- `apktool-out/smali_classes2/com/fujitsu/pfu/net/SSDef.smali`
- `apktool-out/smali_classes2/com/fujitsu/pfu/net/HostInfo.smali`
- `apktool-out/smali_classes2/com/fujitsu/pfu/net/ConnectionManager.smali`
