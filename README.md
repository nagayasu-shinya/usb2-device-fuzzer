usb2-device-fuzzer
==================

Fuzzing tools for **USB 2.0** devices.  USB 3.x is out of scope.

Forked from [ollseg/usb-device-fuzzing](https://github.com/ollseg/usb-device-fuzzing).
The original code was released at T2 Infosec 2012: http://www.t2.fi/2012/

This fork adds a Docker-based Python 2.7 environment, renames and significantly
improves the control transfer fuzzer, and reorganises the directory layout to
follow PEP 8 conventions.


Changes from upstream
---------------------

- **Docker environment** — Added `docker/Dockerfile` (Python 2.7-slim) so the
  tools can run without installing Python 2 on the host.
- **control_transfer_fuzzer.py** — Renamed from `simple_ctrl_fuzzer.py` and
  rewritten with numerous bug-fixes and improvements:
  - Structured CSV output (timestamp, direction, result, all Setup fields, detail)
  - Correct bmRequestType direction-bit masking for OUT transfers
  - Precise TEST_MODE skip conditions per USB 2.0 spec §9.4.9
  - Expanded bmRequestType Recipient range (0–31) per spec §9.3.1
  - USB 2.0 spec-aligned wLength boundary values (8, 64, 255, 256, 65535)
  - Reactive liveness checks with automatic device reset and recovery
  - Consolidated libusb error code handling
  - `--fill-byte` option, VID:PID validation, argparse-based CLI
- **Directory reorganisation** — `USBFuzz/` → `usbfuzz/`, `examples/` → `fuzzers/`,
  PEP 8 snake_case naming throughout.


Requirements
------------

- Linux host with USB passthrough capability
- A **USB 2.0** target device (USB 3.x devices are not supported)
- Docker (recommended), or a native Python 2.7 environment with:
  - [pyusb](https://github.com/pyusb/pyusb) 1.1.0
  - [scapy](https://scapy.net/) 2.5.0
  - libusb-1.0


Quick start with Docker
-----------------------

### Build the image

```bash
docker build -t usb2-device-fuzzer docker/
```

### Find the target device

```bash
lsusb
# Bus 001 Device 042: ID 16c0:05dc ...
```

### Run a fuzzer

The repository is bind-mounted into the container.  The `--privileged` flag
(or a more targeted `--device` / cgroup rule) is required so that libusb can
access the USB bus from inside the container.

```bash
docker run --rm -it --privileged \
  -v /dev/bus/usb:/dev/bus/usb \
  -v "$(pwd)":/app \
  usb2-device-fuzzer \
  python fuzzers/control_transfer_fuzzer.py 16c0:05dc
```

To save results to a CSV file:

```bash
docker run --rm -it --privileged \
  -v /dev/bus/usb:/dev/bus/usb \
  -v "$(pwd)":/app \
  usb2-device-fuzzer \
  python fuzzers/control_transfer_fuzzer.py 16c0:05dc > results.csv
```

Progress is printed to stderr; CSV data goes to stdout.


control_transfer_fuzzer.py
--------------------------

Exhaustively enumerates the USB 2.0 Setup packet parameter space
(bmRequestType, bRequest, wValue, wIndex, wLength) and sends each
combination as both an IN and OUT transfer to the target device on EP0
(USB 2.0 Specification, Section 9.3).

### Usage

```
python fuzzers/control_transfer_fuzzer.py [OPTIONS] VID:PID
```

### Options

| Option | Default | Description |
|---|---|---|
| `VID:PID` | *(required)* | Target device in hex (e.g. `16c0:05dc`) |
| `--start-b-request HEX` | `0x00` | bRequest range start |
| `--end-b-request HEX` | `0xFF` | bRequest range end (inclusive) |
| `--start-w-value HEX` | `0x0000` | wValue range start |
| `--end-w-value HEX` | `0xFFFF` | wValue range end (inclusive) |
| `--start-w-index HEX` | `0x0000` | wIndex range start |
| `--end-w-index HEX` | `0xFFFF` | wIndex range end (inclusive) |
| `--fill-byte HEX` | `0xFF` | Byte value to fill OUT payloads |

### Output format

CSV with the following columns:

```
timestamp,dir,result,bmRequestType,bRequest,wValue,wIndex,wLength,detail
```

- **dir** — `IN` or `OUT`
- **result** — `OK`, `STALL`, `IO_ERROR`, `TIMEOUT`, etc.
- **detail** — `data=<hex>` for IN success, `bytes_written=<n>` for OUT success

Non-transfer events (liveness checks, resets) use `-` for transfer-specific
fields.

### Notes

- The fuzzer iterates over the full parameter space including reserved and
  invalid combinations.  libusb rejects some of these at the host side
  before they reach the device — these appear in the CSV as `INVALID_PARAM`
  (libusb error code −2).  This is expected behaviour and does not indicate
  a device-side issue.
- SET_FEATURE(TEST_MODE) combinations that would put the device into USB 2.0
  electrical test mode (requiring a power cycle to exit) are automatically
  skipped (USB 2.0 spec §9.4.9, Table 9-7).

### Example: fuzz only vendor requests

```bash
python fuzzers/control_transfer_fuzzer.py \
  --start-b-request 0x00 --end-b-request 0x0F \
  --start-w-value 0x0000 --end-w-value 0x00FF \
  --start-w-index 0x0000 --end-w-index 0x0000 \
  16c0:05dc > vendor_fuzz.csv
```


Other fuzzers
-------------

These fuzzers require the `usbfuzz` package and `scapy`:

```bash
python fuzzers/ccid_fuzzer.py VID:PID    # USB CCID (smart card reader)
python fuzzers/msc_fuzzer.py VID:PID     # USB Mass Storage (Bulk-Only)
python fuzzers/mtp_fuzzer.py VID:PID     # USB MTP (Media Transfer Protocol)
python fuzzers/qcdm_fuzzer.py VID:PID    # Qualcomm DIAG protocol
```


Project structure
-----------------

```
docker/Dockerfile          Docker image definition (Python 2.7 + libusb + pyusb + scapy)
fuzzers/                   Fuzzing scripts
  control_transfer_fuzzer.py   EP0 control transfer fuzzer (standalone, pyusb only)
  ccid_fuzzer.py               CCID device fuzzer
  msc_fuzzer.py                Mass Storage Class fuzzer
  mtp_fuzzer.py                MTP device fuzzer
  qcdm_fuzzer.py               Qualcomm DIAG fuzzer
usbfuzz/                   Python package for building USB device fuzzers
  device.py                    Base classes: USBDevice, BulkPipe
  exceptions.py                USBException, USBStalled, USBTimeout
  msc.py                       USB Bulk-Only Mass Storage support
  scsi.py                      SCSI command layers
  ccid.py                      USB CCID support
  mtp.py                       USB MTP support
  qcdm.py                      Qualcomm DIAG support
USB-specification/         Reference copies of USB specification documents
```

