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

FUZZ_SIZES = (0, 10, 100, 4000)


def hex_int(value):
    return int(value, 16)


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


def _do_transfer(device, direction_label, bm_request_type, b_request, w_value, w_index, size):
    fmt_args = (bm_request_type, b_request, w_value, w_index)
    is_in = (direction_label == 'IN ')
    bm_rt = bm_request_type | DIRECTION_IN if is_in else bm_request_type & ~DIRECTION_IN
    data  = size if is_in else bytearray(b'\xff' * size)

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


def test_ctrl_transfer(device, bm_request_type, b_request, w_value, w_index):
    for size in FUZZ_SIZES:
        sys.stdout.write('TRY %0.2x %0.2x %0.4x %0.4x len(%0.4u)\r' % (
            bm_request_type, b_request, w_value, w_index, size))
        _do_transfer(device, 'OUT', bm_request_type, b_request, w_value, w_index, size)
        _do_transfer(device, 'IN ', bm_request_type, b_request, w_value, w_index, size)

        if w_index % 10 == 0:
            if not is_alive(device):
                device.reset()
                time.sleep(1)


def parse_args():
    parser = argparse.ArgumentParser(description='USB control transfer fuzzer')
    parser.add_argument('vid_pid', metavar='VID:PID',
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
    return parser.parse_args()


def iter_params(args):
    for b_request in range(args.start_b_request, args.end_b_request + 1):
        for w_value in range(args.start_w_value, args.end_w_value + 1):
            for w_index in range(args.start_w_index, args.end_w_index + 1):
                if b_request == 3 and (w_value & 0x00FF) == 2 and (w_index >> 8) == 0:
                    continue  # avoid SET_FEATURE TEST_MODE
                for req_type in range(0x00, 0x04):       # bmRequestType.Type
                    for req_recipient in range(0x00, 0x04):  # bmRequestType.Recipient
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

    for bm_request_type, b_request, w_value, w_index in iter_params(args):
        test_ctrl_transfer(device, bm_request_type, b_request, w_value, w_index)


if __name__ == '__main__':
    main()
