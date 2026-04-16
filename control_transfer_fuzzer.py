#!/usr/bin/env python

import sys
import time
import usb.core
import binascii


def is_alive(device):
    try:
        res = device.ctrl_transfer(0x80, 0, 0, 0, 2)
    except usb.core.USBError as e:
        if e.backend_error_code == -4:  # LIBUSB_ERROR_NO_DEVICE
            print "\nDevice not found!"
            sys.exit()
        if e.backend_error_code == -3:  # LIBUSB_ERROR_ACCESS
            print "\nAccess denied to device!"
            sys.exit()
        print "\nGET_STATUS returned error %i" % e.backend_error_code
        return False

    if len(res) != 2:
        print "\nGET_STATUS returned %u bytes: %s" % (len(res), binascii.hexlify(res))
        return False

    return True


def test_ctrl_transfer(device, bm_request_type, b_request, w_value, w_index):
    for size in (0, 10, 100, 4000):
        sys.stdout.write('TRY %0.2x %0.2x %0.4x %0.4x len(%0.4u)\r' % (bm_request_type, b_request, w_value, w_index, size))

        try:
            res = device.ctrl_transfer(bm_request_type & 0x80, b_request, w_value, w_index,
                                       bytearray().fromhex(u'ff' * size), timeout=250)
            print 'OUT %0.2x %0.2x %0.4x %0.4x res(%u) len(%u)' % (bm_request_type, b_request, w_value, w_index, res, size)
        except usb.core.USBError as e:
            if e.backend_error_code != -9 and e.backend_error_code != -1:  # ignore LIBUSB_ERROR_PIPE and LIBUSB_ERROR_IO
                print 'OUT %0.2x %0.2x %0.4x %0.4x err(%i) len(%u)' % (bm_request_type, b_request, w_value, w_index, e.backend_error_code, size)

        try:
            res = device.ctrl_transfer(bm_request_type | 0x80, b_request, w_value, w_index, size, timeout=250)
            print 'IN  %0.2x %0.2x %0.4x %0.4x data(%u) len(%u):\t%s' % (bm_request_type, b_request, w_value, w_index, len(res), size, binascii.hexlify(res))
        except usb.core.USBError as e:
            if e.backend_error_code != -9 and e.backend_error_code != -1:  # ignore LIBUSB_ERROR_PIPE and LIBUSB_ERROR_IO
                print 'IN  %0.2x %0.2x %0.4x %0.4x err(%i) len(%u)' % (bm_request_type, b_request, w_value, w_index, e.backend_error_code, size)

        if w_index % 10 == 0:
            if not is_alive(device):
                device.reset()
                time.sleep(1)


def main():
    if len(sys.argv) < 2:
        print "Usage: %s VID:PID [start_b_request [start_w_value_hi [start_w_value_lo]]]" % sys.argv[0]
        sys.exit(1)

    vid_pid = sys.argv[1].split(':')
    device = usb.core.find(idVendor=int(vid_pid[0], 16), idProduct=int(vid_pid[1], 16))

    start_b_request = 0
    start_w_value_hi = 0
    start_w_value_lo = 0
    if len(sys.argv) > 2:
        start_b_request = int(sys.argv[2], 16)
    if len(sys.argv) > 3:
        start_w_value_hi = int(sys.argv[3], 16)
    if len(sys.argv) > 4:
        start_w_value_lo = int(sys.argv[4], 16)

    for b_request in range(start_b_request, 0x100):
        for w_value_hi in range(start_w_value_hi, 0x10):
            for w_value_lo in range(start_w_value_lo, 0x10):
                for w_index_hi in range(0, 0x10):
                    if b_request == 3 and w_value_lo == 2 and w_index_hi == 0:  # avoid SET_FEATURE TEST_MODE
                        continue
                    for w_index_lo in range(0, 0x10):
                        for req_type in range(0, 0x04):       # bmRequestType.Type
                            for req_recipient in range(0, 0x04):  # bmRequestType.Recipient
                                test_ctrl_transfer(
                                    device,
                                    (req_type << 5) | req_recipient,
                                    b_request,
                                    (w_value_hi << 8) | w_value_lo,
                                    (w_index_hi << 8) | w_index_lo,
                                )


if __name__ == '__main__':
    main()

