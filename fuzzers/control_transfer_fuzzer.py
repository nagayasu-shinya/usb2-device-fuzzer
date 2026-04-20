#!/usr/bin/env python
"""USB 2.0 control transfer fuzzer.

Exhaustively enumerates the Setup packet parameter space of USB 2.0
control transfers and sends each combination to a target device.

A USB control transfer begins with a Setup stage that carries an 8-byte
Setup packet (USB 2.0 Specification, Section 9.3, Table 9-2).  This fuzzer iterates
over the five fields that the host can vary:

    bmRequestType  (Type + Recipient bits)
    bRequest       (0x00 - 0xFF)
    wValue         (0x0000 - 0xFFFF)
    wIndex         (0x0000 - 0xFFFF)
    wLength        (selected representative sizes)

For every parameter combination, both an IN (device-to-host) and an OUT
(host-to-device) transfer are attempted so that device behaviour can be
observed in both data-phase directions.

Periodically a GET_STATUS request (USB 2.0 Specification, Section 9.4.5) is issued
to verify that the device is still responsive; if not, the device is
reset before continuing.

Usage::

    python control_transfer_fuzzer.py 16c0:05dc
"""

import argparse
import binascii
import sys
import time

import usb.core

# ---------------------------------------------------------------------------
# libusb error codes (subset used for control-transfer error handling)
# ---------------------------------------------------------------------------
LIBUSB_ERROR_IO        = -1
LIBUSB_ERROR_ACCESS    = -3
LIBUSB_ERROR_NO_DEVICE = -4
LIBUSB_ERROR_PIPE      = -9  # STALL (device rejected the request)

# bmRequestType bit 7 — Data transfer direction
# (USB 2.0 Specification, Section 9.3.1, Table 9-2)
#   D7 = 0: Host-to-device (OUT)
#   D7 = 1: Device-to-host (IN)
DIRECTION_OUT = 0x00
DIRECTION_IN  = 0x80

# Representative wLength values used for fuzzing.
# A zero-length transfer has no Data stage; the others exercise
# progressively larger payload sizes up to near the control-transfer
# maximum for full-speed devices.
FUZZ_SIZES = (
    0,      # no data stage
    1,      # minimum transfer
    8,      # Low Speed EP0 max packet size (bMaxPacketSize0 = 8)
    64,     # Full/High Speed EP0 max packet size (bMaxPacketSize0 = 64)
    255,    # uint8_t max: catches firmware that parses wLength as 8-bit
    256,    # uint8_t overflow boundary (0x100)
    65535,  # uint16_t max: maximum wLength value
)


def hex_int(value):
    """Parse a hexadecimal string into an integer (for argparse type)."""
    return int(value, 16)


def vid_pid_type(value):
    """Validate and return a ``VID:PID`` string in hexadecimal notation.

    Raises:
        argparse.ArgumentTypeError: If *value* is not in ``XXXX:XXXX`` hex form.
    """
    parts = value.split(':')
    if len(parts) != 2:
        raise argparse.ArgumentTypeError("must be VID:PID (e.g. 16c0:05dc)")
    try:
        int(parts[0], 16)
        int(parts[1], 16)
    except ValueError:
        raise argparse.ArgumentTypeError("must be VID:PID in hex (e.g. 16c0:05dc)")
    return value


def is_alive(device):
    """Check whether the device still responds on the Default Control Pipe.

    Sends a GET_STATUS device request (bRequest = 0, wLength = 2) which
    every compliant USB device must handle (USB 2.0 Specification, Section 9.4.5).
    A valid response is exactly two bytes indicating device status.

    Returns:
        bool: ``True`` if the device returned a valid 2-byte status.
    """
    try:
        # GET_STATUS (bmRequestType=0x80, bRequest=0, wValue=0, wIndex=0)
        res = device.ctrl_transfer(DIRECTION_IN, 0, 0, 0, 2)
    except usb.core.USBError as e:
        if e.backend_error_code == LIBUSB_ERROR_NO_DEVICE:
            print "\nDevice not found!"
            sys.exit()
        if e.backend_error_code == LIBUSB_ERROR_ACCESS:
            print "\nAccess denied to device!"
            sys.exit()
        print "\nGET_STATUS returned error %i" % e.backend_error_code
        return False

    if len(res) != 2:
        print "\nGET_STATUS returned %u bytes: %s" % (len(res), binascii.hexlify(res))
        return False

    return True


def _do_transfer(device, direction_label, bm_request_type, b_request, w_value, w_index, size, fill_byte=0xff):
    """Issue a single control transfer and log the result.

    Builds the final ``bmRequestType`` byte by setting or clearing the
    direction bit (D7) according to *direction_label*, then performs the
    transfer via :pymod:`usb.core`.

    For IN transfers, *size* is passed as ``data_or_wLength`` (the host
    requests up to *size* bytes from the device).  For OUT transfers a
    buffer of *size* bytes filled with *fill_byte* is sent to the device.

    STALL (``LIBUSB_ERROR_PIPE``) and I/O errors are silently ignored
    because they are the *expected* response for most invalid requests
    (USB 2.0 Specification, Section 9.2.7 — Request Error).  Only unexpected error
    codes are printed.

    Args:
        device: :class:`usb.core.Device` handle.
        direction_label: ``'IN '`` or ``'OUT'`` — also determines D7.
        bm_request_type: Base bmRequestType (Type + Recipient bits only).
        b_request: bRequest value  (USB 2.0 Specification, Table 9-4).
        w_value:   wValue field    (USB 2.0 Specification, Section 9.3.3).
        w_index:   wIndex field    (USB 2.0 Specification, Section 9.3.4).
        size:      wLength / payload size.
        fill_byte: Byte value used to fill OUT payloads (default 0xFF).
    """
    is_in = (direction_label == 'IN ')
    # Set D7 (direction bit) of bmRequestType.
    bm_rt = bm_request_type | DIRECTION_IN if is_in else bm_request_type & ~DIRECTION_IN
    fmt_args = (bm_rt, b_request, w_value, w_index)
    # IN: pass integer (requested byte count); OUT: pass payload bytes.
    data  = size if is_in else bytearray([fill_byte] * size)

    try:
        res = device.ctrl_transfer(bm_rt, b_request, w_value, w_index, data, timeout=250)
        if is_in:
            print '%s %0.2x %0.2x %0.4x %0.4x data(%u) len(%u):\t%s' % (
                (direction_label,) + fmt_args + (len(res), size, binascii.hexlify(res)))
        else:
            print '%s %0.2x %0.2x %0.4x %0.4x res(%u) len(%u)' % (
                (direction_label,) + fmt_args + (res, size))
    except usb.core.USBError as e:
        # STALL and I/O errors are normal for unsupported requests;
        # only log truly unexpected error codes.
        if e.backend_error_code not in (LIBUSB_ERROR_PIPE, LIBUSB_ERROR_IO):
            print '%s %0.2x %0.2x %0.4x %0.4x err(%i) len(%u)' % (
                (direction_label,) + fmt_args + (e.backend_error_code, size))


def test_ctrl_transfer(device, bm_request_type, b_request, w_value, w_index, fill_byte=0xff):
    """Test one (bmRequestType, bRequest, wValue, wIndex) combination.

    For each representative wLength in :data:`FUZZ_SIZES`, both an OUT
    and an IN transfer are attempted so that device behaviour is observed
    in both data-phase directions (USB 2.0 Specification, Section 9.3.1, D7 bit).

    Every 10th wIndex iteration a liveness check (:func:`is_alive`) is
    performed.  If the device has become unresponsive — e.g. due to an
    unhandled request causing a firmware fault — a USB reset is issued
    and the fuzzer waits for re-enumeration before continuing.
    """
    for size in FUZZ_SIZES:
        sys.stdout.write('TRY %0.2x %0.2x %0.4x %0.4x len(%0.4u)\r' % (
            bm_request_type, b_request, w_value, w_index, size))
        _do_transfer(device, 'OUT', bm_request_type, b_request, w_value, w_index, size)
        _do_transfer(device, 'IN ', bm_request_type, b_request, w_value, w_index, size)

        # Periodic liveness probe — reset device if it stopped responding.
        if w_index % 10 == 0:
            if not is_alive(device):
                device.reset()
                time.sleep(1)


def parse_args():
    """Parse command-line arguments and return the ``Namespace``."""
    parser = argparse.ArgumentParser(description='USB control transfer fuzzer')
    parser.add_argument('vid_pid', metavar='VID:PID', type=vid_pid_type,
                        help='Target USB device vendor:product IDs in hex (e.g. 16c0:05dc)')
    parser.add_argument('--start-b-request', dest='start_b_request',
                        type=hex_int, default=0x0000, metavar='HEX',
                        help='bRequest start value (default: 0x00)')
    parser.add_argument('--end-b-request',   dest='end_b_request',
                        type=hex_int, default=0x00FF, metavar='HEX',
                        help='bRequest end value inclusive (default: 0xFF)')
    parser.add_argument('--start-w-value',   dest='start_w_value',
                        type=hex_int, default=0x0000, metavar='HEX',
                        help='wValue start (default: 0x0000)')
    parser.add_argument('--end-w-value',     dest='end_w_value',
                        type=hex_int, default=0xFFFF, metavar='HEX',
                        help='wValue end inclusive (default: 0xFFFF)')
    parser.add_argument('--start-w-index',   dest='start_w_index',
                        type=hex_int, default=0x0000, metavar='HEX',
                        help='wIndex start (default: 0x0000)')
    parser.add_argument('--end-w-index',     dest='end_w_index',
                        type=hex_int, default=0xFFFF, metavar='HEX',
                        help='wIndex end inclusive (default: 0xFFFF)')
    parser.add_argument('--fill-byte',        dest='fill_byte',
                        type=hex_int, default=0xFF, metavar='HEX',
                        help='Byte value used to fill OUT data payloads (default: 0xFF, e.g. 00, aa, 55)')
    return parser.parse_args()


def iter_params(args):
    """Yield ``(bmRequestType, bRequest, wValue, wIndex)`` tuples.

    Enumerates the full parameter space defined by the CLI ranges:

    * **bRequest** — the standard request code or any vendor / class
      code  (USB 2.0 Specification, Section 9.3.2, Table 9-4).
    * **wValue** — request-specific parameter (USB 2.0 Specification, Section 9.3.3).
    * **wIndex** — typically an interface or endpoint index
      (USB 2.0 Specification, Section 9.3.4, Figures 9-2 / 9-3).
    * **bmRequestType** — the Type (D6..5: Standard / Class / Vendor /
      Reserved) and Recipient (D4..0: Device / Interface / Endpoint /
      Other / Reserved) sub-fields are iterated independently
      (USB 2.0 Specification, Section 9.3.1, Table 9-2).  The Direction bit (D7)
      is *not* set here; it is applied later inside :func:`_do_transfer`.

    Safety: SET_FEATURE (bRequest = 3) with the TEST_MODE feature
    selector (wValue = 0x0002) and a valid test-mode selector in the
    high byte of wIndex is unconditionally skipped.  Entering test mode
    requires a device power-cycle to exit and would halt the fuzzing
    session (USB 2.0 Specification, Section 9.4.9, Table 9-7).
    """
    for b_request in range(args.start_b_request, args.end_b_request + 1):
        for w_value in range(args.start_w_value, args.end_w_value + 1):
            for w_index in range(args.start_w_index, args.end_w_index + 1):
                # bmRequestType D6..5: Type (0=Standard, 1=Class,
                #                           2=Vendor,   3=Reserved)
                for req_type in range(0x00, 0x04):
                    # bmRequestType D4..0: Recipient
                    # (0=Device, 1=Interface, 2=Endpoint, 3=Other,
                    #  4-31=Reserved — included for completeness)
                    for req_recipient in range(0x00, 0x20):
                        bm_request_type = (req_type << 5) | req_recipient
                        # Skip SET_FEATURE(TEST_MODE) with conditions that actually
                        # transition the device into test mode, requiring a power cycle
                        # to recover (USB 2.0 spec Section 9.4.9, Table 9-7).
                        # Triggering conditions (all must be true):
                        #   - bmRequestType == 0x00 (Standard, OUT, Device recipient)
                        #   - bRequest == 3 (SET_FEATURE)
                        #   - wValue == 0x0002 (TEST_MODE feature selector)
                        #   - wIndex low byte == 0x00 (required by spec)
                        #   - wIndex high byte in 0x01-0x05 or 0xC0-0xFF (valid test selector)
                        if (bm_request_type == 0x00
                                and b_request == 3
                                and w_value == 0x0002
                                and (w_index & 0x00FF) == 0x00
                                and ((0x01 <= (w_index >> 8) <= 0x05)
                                     or (0xC0 <= (w_index >> 8) <= 0xFF))):
                            continue
                        yield (
                            (req_type << 5) | req_recipient,
                            b_request,
                            w_value,
                            w_index,
                        )


def main():
    """Entry point — locate the target device and start fuzzing."""
    args = parse_args()
    vid_pid = args.vid_pid.split(':')
    device = usb.core.find(idVendor=int(vid_pid[0], 16), idProduct=int(vid_pid[1], 16))
    if device is None:
        print "Device %s not found!" % args.vid_pid
        sys.exit(1)

    for bm_request_type, b_request, w_value, w_index in iter_params(args):
        test_ctrl_transfer(device, bm_request_type, b_request, w_value, w_index, args.fill_byte)


if __name__ == '__main__':
    main()
