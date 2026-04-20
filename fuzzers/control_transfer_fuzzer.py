#!/usr/bin/env python

import argparse
import binascii
import sys
import time

import usb.core

# libusb error codes
LIBUSB_ERROR_IO        = -1
LIBUSB_ERROR_ACCESS    = -3
LIBUSB_ERROR_NO_DEVICE = -4
LIBUSB_ERROR_PIPE      = -9  # STALL

# bmRequestType direction bits
DIRECTION_OUT = 0x00
DIRECTION_IN  = 0x80

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
    return int(value, 16)


def vid_pid_type(value):
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
    try:
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
    is_in = (direction_label == 'IN ')
    bm_rt = bm_request_type | DIRECTION_IN if is_in else bm_request_type & ~DIRECTION_IN
    fmt_args = (bm_rt, b_request, w_value, w_index)
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
        if e.backend_error_code not in (LIBUSB_ERROR_PIPE, LIBUSB_ERROR_IO):
            print '%s %0.2x %0.2x %0.4x %0.4x err(%i) len(%u)' % (
                (direction_label,) + fmt_args + (e.backend_error_code, size))


def test_ctrl_transfer(device, bm_request_type, b_request, w_value, w_index, fill_byte=0xff):
    for size in FUZZ_SIZES:
        sys.stdout.write('TRY %0.2x %0.2x %0.4x %0.4x len(%0.4u)\r' % (
            bm_request_type, b_request, w_value, w_index, size))
        _do_transfer(device, 'OUT', bm_request_type, b_request, w_value, w_index, size, fill_byte)
        _do_transfer(device, 'IN ', bm_request_type, b_request, w_value, w_index, size, fill_byte)

        if w_index % 10 == 0:
            if not is_alive(device):
                device.reset()
                time.sleep(1)


def parse_args():
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
    for b_request in range(args.start_b_request, args.end_b_request + 1):
        for w_value in range(args.start_w_value, args.end_w_value + 1):
            for w_index in range(args.start_w_index, args.end_w_index + 1):
                for req_type in range(0x00, 0x04):       # bmRequestType.Type
                    for req_recipient in range(0x00, 0x20):  # bmRequestType.Recipient (0-3: defined, 4-31: reserved)
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
