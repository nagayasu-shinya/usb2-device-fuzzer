usb-device-fuzzing
==================

Some tools for testing USB devices

This code was first released at T2 Infosec 2012: http://www.t2.fi/2012/

fuzzers/: fuzzing scripts (run as `python fuzzers/<script>.py VID:PID`)

  fuzzers/control_transfer_fuzzer.py: exhaustive fuzzer for USB control transfers (EP0); no library dependency

  fuzzers/ccid_fuzzer.py: fuzzer for USB CCID (smart card reader) devices

  fuzzers/msc_fuzzer.py: fuzzer for USB Mass Storage Class (Bulk-Only Transport) devices

  fuzzers/mtp_fuzzer.py: fuzzer for USB MTP (Media Transfer Protocol) devices

  fuzzers/qcdm_fuzzer.py: fuzzer for Qualcomm baseband DIAG protocol devices

usbfuzz/: Python package for building USB fuzzers

  usbfuzz.exceptions: common exception definitions (USBException, USBStalled, USBTimeout)

  usbfuzz.device: base classes for USB device access (USBDevice, BulkPipe)

  usbfuzz.msc: scapy layers and BOMSDevice class for USB Bulk-Only Mass Storage Class

  usbfuzz.scsi: scapy layers for SCSI primary and bulk commands, used by usbfuzz.msc

  usbfuzz.ccid: scapy layers and CCIDDevice class for USB Integrated Circuit Cards Interface Device Class

  usbfuzz.mtp: scapy layers and MTPDevice class for USB Media Transfer Protocol (based on PTP)

  usbfuzz.qcdm: scapy layers and QCDMDevice class for Qualcomm baseband DIAG protocol

