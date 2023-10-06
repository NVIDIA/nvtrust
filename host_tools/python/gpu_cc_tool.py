#!/usr/bin/env python3

#
# Copyright (c) 2018-2023, NVIDIA CORPORATION.  All rights reserved.
#
# NVIDIA CORPORATION and its licensors retain all intellectual property
# and proprietary rights in and to this software, related documentation
# and any modifications thereto.  Any use, reproduction, disclosure or
# distribution of this software and related documentation without an express
# license agreement from NVIDIA CORPORATION is strictly prohibited.
#

from __future__ import print_function
from enum import Enum
import os
import mmap
import struct
from struct import Struct
import time
import sys
import random
import optparse
import traceback
from logging import debug, info, warning, error
import logging
from collections import namedtuple
import zlib
from pathlib import Path

#import debugpy

import ctypes
c_uint8 = ctypes.c_uint8
c_uint16 = ctypes.c_uint16
c_uint32 = ctypes.c_uint32

# Use SystemRandom() as the default rng, --weak-random option can switch it
# back to the default.
rng = random.SystemRandom()

if hasattr(time, "perf_counter"):
    perf_counter = time.perf_counter
else:
    perf_counter = time.time

import platform
is_windows = platform.system() == "Windows"
is_linux = platform.system() == "Linux"

is_sysfs_available = is_linux

use_nvpex = False

# By default use /dev/mem for MMIO, can be changed with --mmio-access-type sysfs
mmio_access_type = "devmem"

VERSION = "535.86.06"
GPU_BAR0_SIZE = 16 * 1024 * 1024
NVSWITCH_BAR0_SIZE = 32 * 1024 * 1024

NV_PMC_ENABLE = 0x200
NV_PMC_DEVICE_ENABLE = 0x600

NV_PMC_BOOT_0 = 0x0
NV_PROM_DATA = 0x300000
def NV_PPWR_NPU_IMEMD(i):
    return 0x10a184 + i * 16

def NV_PPWR_NPU_IMEMC(i):
    return 0x10a180 + i * 16

NV_PPWR_NPU_IMEMC_AINCW_TRUE = 1 << 24
NV_PPWR_NPU_IMEMC_AINCR_TRUE = 1 << 25
NV_PPWR_NPU_IMEMC_SECURE_ENABLED = 1 << 28

def NV_PPWR_NPU_IMEMT(i):
    return 0x10a188 + i * 16

def NV_PPWR_NPU_DMEMC(i):
    return 0x0010a1c0 + i * 8
NV_PPWR_NPU_CPUCTL = 0x10a100
NV_PPWR_NPU_HWCFG = 0x10a108
NV_PPWR_NPU_HWCFG1 = 0x10a12c
SYS_DEVICES = "/sys/bus/pci/devices/"

def sysfs_find_parent(device):
    device = os.path.basename(device)
    for device_dir in os.listdir(SYS_DEVICES):
        dev_path = os.path.join(SYS_DEVICES, device_dir)
        for f in os.listdir(dev_path):
            if f == device:
                return dev_path
    return None

def find_gpus_sysfs(bdf_pattern=None):
    gpus = []
    other = []
    dev_paths = []
    for device_dir in os.listdir("/sys/bus/pci/devices/"):
        dev_path = os.path.join("/sys/bus/pci/devices/", device_dir)
        bdf = device_dir
        if bdf_pattern:
            if bdf_pattern not in bdf:
                continue
        vendor = open(os.path.join(dev_path, "vendor")).readlines()
        vendor = vendor[0].strip()
        if vendor != "0x10de":
            continue
        cls = open(os.path.join(dev_path, "class")).readlines()
        cls = cls[0].strip()
        if cls != "0x030000" and cls != "0x030200" and cls != "0x068000":
            continue
        dev_paths.append(dev_path)
    def devpath_to_id(dev_path):
        bdf = os.path.basename(dev_path)
        return int(bdf.replace(":","").replace(".",""), base=16)

    dev_paths = sorted(dev_paths, key=devpath_to_id)
    for dev_path in dev_paths:
        gpu = None
        cls = open(os.path.join(dev_path, "class")).readlines()
        cls = cls[0].strip()
        try:
            if cls == "0x068000":
                dev = NvSwitch(dev_path=dev_path)
            else:
                dev = Gpu(dev_path=dev_path)
        except UnknownGpuError as err:
            error("Unknown Nvidia device %s: %s", dev_path, str(err))
            dev = NvidiaDevice(dev_path=dev_path)
            other.append(dev)
            continue
        except Exception as err:
            _, _, tb = sys.exc_info()
            traceback.print_tb(tb)
            error("GPU %s broken: %s", dev_path, str(err))
            dev = BrokenGpu(dev_path=dev_path)
        gpus.append(dev)

    return (gpus, other)

global_nvpex = None

def find_gpus(bdf=None):
    if is_sysfs_available:
        return find_gpus_sysfs(bdf)
    else:
        assert bdf != None
        return find_gpus_one_bdf_only(bdf)

def _struct_fmt(size):
   if size == 1:
       return "B"
   elif size == 2:
       return "=H"
   elif size == 4:
       return "=I"
   elif size == 8:
       return "=Q"
   else:
       assert 0, "Unhandled size %d" % size

def ints_from_data(data, size):
    fmt = _struct_fmt(size)
    # Wrap data in bytes() for python 2.6 compatibility
    data = bytes(data)
    ints = []
    for offset in range(0, len(data), size):
        ints.append(struct.unpack(fmt, data[offset : offset + size])[0])

    return ints

def int_from_data(data, size):
    fmt = _struct_fmt(size)
    # Wrap data in bytes() for python 2.6 compatibility
    return struct.unpack(fmt, bytes(data))[0]

def data_from_int(integer, size):
    fmt = _struct_fmt(size)
    return struct.pack(fmt, integer)
class FileRaw(object):
    def __init__(self, path, offset, size):
        self.fd = os.open(path, os.O_RDWR | os.O_SYNC)
        self.base_offset = offset
        self.size = size

    def __del__(self):
        if hasattr(self, "fd"):
            os.close(self.fd)

    def write(self, offset, data, size):
        os.lseek(self.fd, offset, os.SEEK_SET)
        os.write(self.fd, data_from_int(data, size))

    def write8(self, offset, data):
        self.write(offset, data, 1)

    def write16(self, offset, data):
        self.write(offset, data, 2)

    def write32(self, offset, data):
        self.write(offset, data, 4)

    def read(self, offset, size):
        os.lseek(self.fd, offset, os.SEEK_SET)
        data = os.read(self.fd, size)
        assert data, "offset %s size %d %s" % (hex(offset), size, data)
        return int_from_data(data, size)

    def read8(self, offset):
        return self.read(offset, 1)

    def read16(self, offset):
        return self.read(offset, 2)

    def read32(self, offset):
        return self.read(offset, 4)

    def read_format(self, fmt, offset):
        size = struct.calcsize(fmt)
        os.lseek(self.fd, offset, os.SEEK_SET)
        data = os.read(self.fd, size)
        return struct.unpack(fmt, data)
class FileMap(object):
    # At least with python 2.7 and 3.4, writing to an mmap.mmap() region (or
    # ctypes pointer for it) results in the writes being duplicated which
    # breaks GPU MMIO semantics. Creating a numpy array WARs this issue. The
    # suspicion is that without numpy, memcpy() is used for the writes and its
    # optimization results in the writes being duplicated. On python 2.6 this
    # has not been observed so far and the numpy wrapper is skipped to lessen
    # the support requirements.
    use_numpy = sys.version_info[0] != 2 or sys.version_info[1] != 6

    def __init__(self, path, offset, size):
        self.size = size
        with open(path, "r+b") as f:
            prot = mmap.PROT_READ | mmap.PROT_WRITE
            # Try mmap.mmap() first for error checking even if we end up using numpy
            mapped = mmap.mmap(f.fileno(), size, mmap.MAP_SHARED, prot, offset=offset)
            if self.__class__.use_numpy:
                import ctypes
                import numpy

                mapped = libc.mmap(ctypes.c_void_p(None), ctypes.c_size_t(size), ctypes.c_int(prot),
                                  ctypes.c_int(mmap.MAP_SHARED), ctypes.c_int(f.fileno()), ctypes.c_long(offset))
                if mapped == 0xffffffffffffffff:
                    raise GpuError("Can't mmap '{0}'".format(path))
                self.mapped = mapped
                self.map_8 = ctypes.cast(mapped, ctypes.POINTER(ctypes.c_uint8))
                self.map_16 = ctypes.cast(mapped, ctypes.POINTER(ctypes.c_uint16))
                self.map_32 = ctypes.cast(mapped, ctypes.POINTER(ctypes.c_uint32))

                self.map_8 = numpy.ctypeslib.as_array(self.map_8, shape=(size,))
                self.map_16 = numpy.ctypeslib.as_array(self.map_16, shape=(size//2,))
                self.map_32 = numpy.ctypeslib.as_array(self.map_32, shape=(size//4,))
            else:
                self.mapped = mapped

    def __del__(self):
        if self.__class__.use_numpy:
            if hasattr(self, "mapped"):
                libc.munmap(self.mapped, ctypes.c_size_t(self.size))

    if use_numpy:
        def write32(self, offset, data):
            self.map_32[offset // 4] = data

        def write16(self, offset, data):
            self.map_16[offset // 2] = data

        def write8(self, offset, data):
            self.map_8[offset // 1] = data
    else:
        def write32(self, offset, data):
            self.mapped[offset : offset + 4] = struct.pack("=I", data)

    if use_numpy:
        def read(self, offset, size):
            if size == 1:
                return self.map_8[offset // 1]
            elif size == 2:
                return self.map_16[offset // 2]
            elif size == 4:
                return self.map_32[offset // 4]
            else:
                assert 0, "Unhandled size %d" % size
    else:
        def read(self, offset, size):
            fmt = _struct_fmt(size)
            return struct.unpack(fmt, self.mapped[offset : offset + size])[0]

    def read8(self, offset):
        return self.read(offset, 1)

    def read16(self, offset):
        return self.read(offset, 2)

    def read32(self, offset):
        return self.read(offset, 4)

# Check that modules needed to access devices on the system are available
def check_device_module_deps():
    if not use_nvpex and FileMap.use_numpy:
        import numpy
class NvPexError(Exception):
    pass
GPU_ARCHES = ["kepler", "maxwell", "pascal", "volta", "turing", "ampere", "ada", "hopper"]
# For architectures with multiple products, match by device id as well. The
# values from this map are what's used in the GPU_MAP.
GPU_MAP_MULTIPLE = {
    0x180000a1: {
        "devids": {
            0x2330: "H100-SXM",
            0x2336: "H100-SXM",
        },
        "default": "H100-PCIE",
    },

}
GPU_MAP = {
    "H100-PCIE": {
        "name": "H100-PCIE",
        "arch": "hopper",
        "pmu_reset_in_pmc": False,
        "memory_clear_supported": True,
        "forcing_ecc_on_after_reset_supported": True,
        "nvdec": [],
        "nvenc": [],
        "other_npus": ["fsp"],
        "nvlink": {
            "number": 18,
            "links_per_group": 6,
            "base_offset": 0xa00000,
            "per_group_offset": 0x40000,
        },
        "needs_npus_cfg": False,
    },
    "H100-SXM": {
        "name": "H100-SXM",
        "arch": "hopper",
        "pmu_reset_in_pmc": False,
        "memory_clear_supported": True,
        "forcing_ecc_on_after_reset_supported": True,
        "nvdec": [],
        "nvenc": [],
        "other_npus": ["fsp"],
        "nvlink": {
            "number": 18,
            "links_per_group": 6,
            "base_offset": 0xa00000,
            "per_group_offset": 0x40000,
        },
        "needs_npus_cfg": False,
    },
}

PCI_CFG_SPACE_SIZE = 256
PCI_CFG_SPACE_EXP_SIZE = 4096

PCI_CAPABILITY_LIST = 0x34
# PCI Express
PCI_CAP_ID_EXP = 0x10
# Power management
PCI_CAP_ID_PM  = 0x01

CAP_ID_MASK = 0xff

# Advanced Error Reporting
PCI_EXT_CAP_ID_ERR = 0x01

# SRIOV
PCI_EXT_CAP_ID_SRIOV = 0x10

# Uncorrectable Error Status
PCI_ERR_UNCOR_STATUS = 4
# Uncorrectable Error Mask
PCI_ERR_UNCOR_MASK = 8
# Uncorrectable Error Severity
PCI_ERR_UNCOR_SEVER = 12

# Use libc's ffs() on Linux and fall back to a native implementation otherwise.
if is_linux:
    import ctypes
    libc = ctypes.cdll.LoadLibrary('libc.so.6')

    # Set the mmap and munmap arg and return types.
    # last mmap arg is off_t which ctypes doesn't have. Assume it's long as that what gcc defines it to.
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
    libc.mmap.restype = ctypes.c_void_p
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    libc.munmap.restype = ctypes.c_int

    def ffs(n):
        return libc.ffs(n)
else:
    def ffs(n):
        return (n & (-n)).bit_length()
class Bitfield(object):
    """Wrapper around bitfields, see PciUncorrectableErrors for an example"""
    fields = {}

    def __init__(self, raw, name=None):
        self.raw = raw
        if name is None:
            name = self.__class__.__name__
        self.name = name

    def __field_get_mask(self, field):
        bits = self.__class__.fields[field]
        if isinstance(bits, int):
            return bits

        assert isinstance(bits, tuple)
        high_bit = bits[0]
        low_bit = bits[1]

        mask = (1 << (high_bit - low_bit + 1)) - 1
        mask <<= low_bit
        return mask

    def __field_get_shift(self, field):
        mask = self.__field_get_mask(field)
        assert mask != 0
        return ffs(mask) - 1

    def __getitem__(self, field):
        mask = self.__field_get_mask(field)
        shift = self.__field_get_shift(field)
        return (self.raw & mask) >> shift

    def __setitem__(self, field, val):
        mask = self.__field_get_mask(field)
        shift = self.__field_get_shift(field)

        val = val << shift
        assert (val & ~mask) == 0, "value 0x%x mask 0x%x" % (val, mask)

        self.raw = (self.raw & ~mask) | val

    def __str__(self):
        return self.name + " " + str(self.values()) + " raw " + hex(self.raw)

    def values(self):
        vals = {}
        for f in self.__class__.fields:
            vals[f] = self[f]

        return vals

    def non_zero(self):
        ret = {}
        for k, v in self.values().items():
            if v != 0:
                ret[k] = v
        return ret

    def non_zero_fields(self):
        ret = []
        for k, v in self.values().items():
            if v != 0:
                ret.append(k)
        return ret


class PciUncorrectableErrors(Bitfield):
    size = 4
    fields = {
    # Undefined
    "UND": 0x00000001,

    # Data Link Protocol
    "DLP": 0x00000010,

    # Surprise Down
    "SURPDN":  0x00000020,

    # Poisoned TLP
    "POISON_TLP": 0x00001000,

    # Flow Control Protocol
    "FCP": 0x00002000,

    # Completion Timeout
    "COMP_TIME": 0x00004000,

    # Completer Abort
    "COMP_ABORT": 0x00008000,

    # Unexpected Completion
    "UNX_COMP": 0x00010000,

    # Receiver Overflow
    "RX_OVER": 0x00020000,

    # Malformed TLP
    "MALF_TLP": 0x00040000,

    # ECRC Error Status
    "ECRC": 0x00080000,

    # Unsupported Request
    "UNSUP": 0x00100000,

    # ACS Violation
    "ACSV": 0x00200000,

    # internal error
    "INTN": 0x00400000,

    # MC blocked TLP
    "MCBTLP": 0x00800000,

    # Atomic egress blocked
    "ATOMEG": 0x01000000,

    # TLP prefix blocked
    "TLPPRE": 0x02000000,
    }

    def __str__(self):
        # Print only the non zero bits
        return "%s %s" % (self.name, str(self.non_zero_fields()))

PCI_EXP_DEVCAP2 = 36
PCI_EXP_DEVCTL2 = 40
class PciDevCtl2(Bitfield):
    size = 2
    fields = {
        # Completion Timeout Value
        "COMP_TIMEOUT":         0x000f,

        # Completion Timeout Disable
        "COMP_TMOUT_DIS":       0x0010,

        # Alternative Routing-ID
        "ARI":                  0x0020,

        # Set Atomic requests
        "ATOMIC_REQ":           0x0040,

        # Block atomic egress
        "ATOMIC_EGRESS_BLOCK":  0x0080,

        # Allow IDO for requests
        "IDO_REQ_EN":           0x0100,

        # Allow IDO for completions
        "IDO_CMP_EN":           0x0200,

        # Enable LTR mechanism
        "LTR_EN":               0x0400,

        # Enable OBFF Message type A
        "OBFF_MSGA_EN":         0x2000,

        # Enable OBFF Message type B
        "OBFF_MSGB_EN":         0x4000,

        # OBFF using WAKE# signaling
        "OBFF_WAKE_EN":         0x6000,
    }

# Access Control Services
PCI_EXT_CAP_ID_ACS = 0x0D

# ACS control
PCI_EXT_ACS_CTL = 6
class AcsCtl(Bitfield):
    size = 2
    fields = {
    "SOURCE_VALIDATION":    0x0001,
    "TRANSLATION_BLOCKING": 0x0002,
    "P2P_REQUEST_REDIRECT": 0x0004,
    "P2P_COMPLETION_REDIRECT": 0x0008,
    "UPSTREAM_FORWARDING": 0x0010,
    "P2P_EGRESS_CONTROL": 0x0020,
    "DIRECT_TRANSLATED_P2P": 0x0040,
    }

# Downstream Port Containment
PCI_EXT_CAP_ID_DPC = 0x1D

# DPC control
PCI_EXP_DPC_CTL = 6
class DpcCtl(Bitfield):
    size = 2
    fields = {

    # Enable trigger on ERR_FATAL message
    "EN_FATAL": 0x0001,

    # Enable trigger on ERR_NONFATAL message
    "EN_NONFATAL": 0x0002,

    # DPC Interrupt Enable
    "INT_EN": 0x0008,
    }

# DPC Status
PCI_EXP_DPC_STATUS = 8
class DpcStatus(Bitfield):
    size = 2
    fields = {
    # Trigger Status
    "STATUS_TRIGGER":         0x0001,
    # Trigger Reason
    "STATUS_TRIGGER_RSN":     0x0006,
    # Interrupt Status
    "STATUS_INTERRUPT":       0x0008,
    # Root Port Busy
    "RP_BUSY":                0x0010,
    # Trig Reason Extension
    "STATUS_TRIGGER_RSN_EXT": 0x0060,
    }

class DeviceField(object):
    """Wrapper for a device register/setting defined by a bitfield class and
    accessible with dev.read()/write() at the specified offset"""
    def __init__(self, bitfield_class, dev, offset, name=None):
        self.dev = dev
        self.offset = offset
        self.bitfield_class = bitfield_class
        self.size = bitfield_class.size
        if name is None:
            name = bitfield_class.__name__
        self.name = name
        self._read()

    def _read(self):
        raw = self.dev.read(self.offset, self.size)
        self.value = self.bitfield_class(raw, name=self.name)
        return self.value

    def _write(self):
        self.dev.write(self.offset, self.value.raw, self.size)

    def __getitem__(self, field):
        self._read()
        return self.value[field]

    def __setitem__(self, field, val):
        self._read()
        self.value[field] = val
        self._write()

    def write_only(self, field, val):
        """Write to the device with only the field set as specified. Useful for W1C bits"""

        bf = self.bitfield_class(0)
        bf[field] = val
        self.dev.write(self.offset, bf.raw, self.size)
        self._read()

    def __str__(self):
        self._read()
        return str(self.value)

PCI_COMMAND = 0x04
class PciCommand(Bitfield):
    size = 2
    fields = {
        "MEMORY": 0x0002,
        "MASTER": 0x0004,
        "PARITY": 0x0040,
        "SERR":   0x0100,
    }

PCI_EXP_FLAGS = 2
class PciExpFlags(Bitfield):
    size = 2
    fields = {
        # Capability version
        "VERS": 0x000f,

        # Device/Port type
        "TYPE": 0x00f0,
#define   PCI_EXP_TYPE_ENDPOINT	   0x0	/* Express Endpoint */
#define   PCI_EXP_TYPE_LEG_END	   0x1	/* Legacy Endpoint */
#define   PCI_EXP_TYPE_ROOT_PORT   0x4	/* Root Port */
#define   PCI_EXP_TYPE_UPSTREAM	   0x5	/* Upstream Port */
#define   PCI_EXP_TYPE_DOWNSTREAM  0x6	/* Downstream Port */
#define   PCI_EXP_TYPE_PCI_BRIDGE  0x7	/* PCIe to PCI/PCI-X Bridge */
#define   PCI_EXP_TYPE_PCIE_BRIDGE 0x8	/* PCI/PCI-X to PCIe Bridge */
#define   PCI_EXP_TYPE_RC_END	   0x9	/* Root Complex Integrated Endpoint */
#define   PCI_EXP_TYPE_RC_EC	   0xa	/* Root Complex Event Collector */

        # Slot implemented
        "SLOT": 0x0100,

        # Interrupt message number
        "IRQ": 0x3e00,
    }

PCI_EXP_RTCTL = 28
class PciRootControl(Bitfield):
    size = 2
    fields = {
        # System Error on Correctable Error
        "SECEE": 0x0001,

        # System Error on Non-Fatal Error
        "SENFEE": 0x0002,

        # System Error on Fatal Error
        "SEFEE": 0x0004,

        # PME Interrupt Enable
        "PMEIE": 0x0008,

        # CRS Software Visibility Enable
        "CRSSVE": 0x0010,
    }

PCI_EXP_DEVCAP = 4
class PciDevCap(Bitfield):
    size = 4
    fields = {
        # Max payload
        "PAYLOAD":  0x00000007,

        # Phantom functions
        "PHANTOM":  0x00000018,

        # Extended tags
        "EXT_TAG":  0x00000020,

        # L0s acceptable latency
        "L0S":      0x000001c0,

        # L1 acceptable latency
        "L1":       0x00000e00,

        # Attention Button Present
        "ATN_BUT":  0x00001000,

        # Attention indicator present
        "ATN_IND":  0x00002000,

        # Power indicator present
        "PWR_IND":  0x00004000,

        # Role-based error reporting
        "RBER":     0x00008000,

        # Slot power limit value
        "PWR_VAL":  0x03fc0000,

        # Slot Power Limit Scale
        "PWR_SCL":  0x0c000000,

        # Function level reset
        "FLR":      0x10000000,
    }

PCI_EXP_DEVCTL = 8
class PciDevCtl(Bitfield):
    size = 4
    fields = {
        # /* Correctable Error Reporting En. */
        "CERE": 0x0001,

        # /* Non-Fatal Error Reporting Enable */
        "NFERE": 0x0002,

        # /* Fatal Error Reporting Enable */
        "FERE": 0x0004,

        # /* Unsupported Request Reporting En. */
        "URRE": 0x0008,

        # /* Enable relaxed ordering */
        "RELAX_EN": 0x0010,
        # /* Max_Payload_Size */
        "PAYLOAD": 0x00e0,

        # /* Extended Tag Field Enable */
        "EXT_TAG": 0x0100,

        # /* Phantom Functions Enable */
        "PHANTOM": 0x0200,

        # /* Auxiliary Power PM Enable */
        "AUX_PME": 0x0400,

        # /* Enable No Snoop */
        "NOSNOOP_EN": 0x0800,

        # /* Max_Read_Request_Size */
        #"READRQ_128B  0x0000 /* 128 Bytes */
        #"READRQ_256B  0x1000 /* 256 Bytes */
        #"READRQ_512B  0x2000 /* 512 Bytes */
        #"READRQ_1024B 0x3000 /* 1024 Bytes */
        "READRQ": 0x7000,

        # /* Bridge Configuration Retry / FLR */
        "BCR_FLR": 0x8000,
    }

PCI_EXP_LNKCAP = 12
class PciLinkCap(Bitfield):
    size = 4
    fields = {
        # Maximum Link Width
        "MLW":   0x000003f0,

        # Surprise Down Error Reporting Capable
        "SDERC": 0x00080000,

        # Port Number
        "PN":    0xff000000,
    }

    def __str__(self):
        return "{ Link cap " + str(self.values()) + " raw " + hex(self.raw) + " }"



# Link Control
PCI_EXP_LNKCTL = 16
class PciLinkControl(Bitfield):
    size = 2
    fields = {
        # ASPM Control
        "ASPMC": 0x0003,

        # Read Completion Boundary
        "RCB": 0x0008,

        # Link Disable
        "LD": 0x0010,

        # Retrain Link
        "RL": 0x0020,

        # Common Clock Configuration
        "CCC": 0x0040,

        # Extended Synch
        "ES": 0x0080,

        # Hardware Autonomous Width Disable
        "HAWD": 0x0200,

        # Enable clkreq
        "CLKREQ_EN": 0x100,

        # Link Bandwidth Management Interrupt Enable
        "LBMIE": 0x0400,

        # Lnk Autonomous Bandwidth Interrupt Enable
        "LABIE": 0x0800,
    }

    def __str__(self):
        return "{ Link control " + str(self.values()) + " raw " + hex(self.raw) + " }"

# Link Status
PCI_EXP_LNKSTA = 18
class PciLinkStatus(Bitfield):
    size = 2
    fields = {
        # Current Link Speed
        # CLS_2_5GB 0x01 Current Link Speed 2.5GT/s
        # CLS_5_0GB 0x02 Current Link Speed 5.0GT/s
        "CLS": 0x000f,

        # Nogotiated Link Width
        "NLW": 0x03f0,

        # Link Training
        "LT": 0x0800,

        # Slot Clock Configuration
        "SLC": 0x1000,

        # Data Link Layer Link Active
        "DLLLA": 0x2000,

        # Link Bandwidth Management Status
        "LBMS": 0x4000,

        # Link Autonomous Bandwidth Status */
        "LABS": 0x8000,
    }

    def __str__(self):
        return "{ Link status " + str(self.values()) + " raw " + hex(self.raw) + " }"

PCI_EXP_SLTCAP = 20
PCI_EXP_SLTCTL = 24
class PciSlotControl(Bitfield):
    size = 2
    fields = {
        # Attention Button Pressed Enable
        "ABPE": 0x0001,

        # Power Fault Detected Enable
        "PFDE": 0x0002,

        # MRL Sensor Changed Enable
        "MRLSCE": 0x0004,

        # Presence Detect Changed Enable
        "PDCE": 0x0008,

        # Command Completed Interrupt Enable
        "CCIE": 0x0010,

        # Hot-Plug Interrupt Enable
        "HPIE": 0x0020,

        # Attention Indicator Control
        "AIC": 0x00c0,

        # Power Indicator Control
        "PIC": 0x0300,

        # Power Controller Control
        "PCC": 0x0400,

        # Electromechanical Interlock Control
        "EIC": 0x0800,

        # Data Link Layer State Changed Enable
        "DLLSCE": 0x1000,
    }

PCI_EXP_LNKCTL2 = 48
class PciLinkControl2(Bitfield):
    size = 2
    fields = {
        # Target link speed
        "TLS": 0x000f,
    }

PCI_PM_CTRL = 4
class PciPmControl(Bitfield):
    size = 2
    fields = {
        "STATE": 0x0003,
        "NO_SOFT_RESET": 0x0008,
    }

DEVICES = { }

class Device(object):
    def __init__(self):
        self.parent = None
        self.children = []

    def is_hidden(self):
        return True

    def has_aer(self):
        return False

    def is_bridge(self):
        return False

    def is_root(self):
        return self.parent == None

    def is_gpu(self):
        return False

    def is_nvswitch(self):
        return False

    def is_plx(self):
        return False

    def is_intel(self):
        return False

    def has_dpc(self):
        return False

    def has_acs(self):
        return False

    def has_exp(self):
        return False

class PciDevice(Device):
    @staticmethod
    def _open_config(dev_path):
        dev_path_config = os.path.join(dev_path, "config")
        return FileRaw(dev_path_config, 0, os.path.getsize(dev_path_config))

    @staticmethod
    def find_class_for_device(dev_path):
        pci_dev = PciDevice(dev_path)
        if pci_dev.has_exp():
            # Root port
            if pci_dev.pciflags["TYPE"] == 0x4:
                if pci_dev.vendor == 0x8086:
                    return IntelRootPort
                return PciBridge

            # Upstream port
            if pci_dev.pciflags["TYPE"] == 0x5:
                if pci_dev.vendor == 0x10b5:
                    return PlxBridge
                return PciBridge

            # Downstream port
            if pci_dev.pciflags["TYPE"] == 0x6:
                if pci_dev.vendor == 0x10b5:
                    return PlxBridge
                return PciBridge

            # Endpoint
            if pci_dev.pciflags["TYPE"] == 0x0:
                if pci_dev.vendor == 0x10de:
                    return Gpu

        if pci_dev.header_type == 0x1:
            return PciBridge
        else:
            if pci_dev.vendor == 0x10de:
                return Gpu
            return PciDevice

    @staticmethod
    def init_dispatch(dev_path):
        cls = PciDevice.find_class_for_device(dev_path)
        if cls:
            return cls(dev_path)
        return None

    @staticmethod
    def find_or_init(dev_path):
        if dev_path == None:
            if -1 not in DEVICES:
                DEVICES[-1] = Device()
            return DEVICES[-1]
        bdf = os.path.basename(dev_path)
        if bdf in DEVICES:
            return DEVICES[bdf]
        dev = PciDevice.init_dispatch(dev_path)
        DEVICES[bdf] = dev
        return dev

    def __init__(self, dev_path):
        self.parent = None
        self.children = []
        self.dev_path = dev_path
        self.bdf = os.path.basename(dev_path)
        if use_nvpex:
            self.nvpex = global_nvpex
            # Config space in nvpex is special bar 0xffffffff
            self.config = NvPexBar(self.nvpex, bar=0xffffffff, size=4096)
        else:
            self.config = self._open_config(dev_path)

        self.vendor = self.config.read16(0)
        self.device = self.config.read16(2)
        self.header_type = self.config.read8(0xe)
        self.cfg_space_broken = False
        self._init_caps()
        self._init_bars()
        if not self.cfg_space_broken:
            self.command = DeviceField(PciCommand, self.config, PCI_COMMAND)
            if self.has_exp():
                self.pciflags = DeviceField(PciExpFlags, self.config, self.caps[PCI_CAP_ID_EXP] + PCI_EXP_FLAGS)
                self.devcap = DeviceField(PciDevCap, self.config, self.caps[PCI_CAP_ID_EXP] + PCI_EXP_DEVCAP)
                self.devctl = DeviceField(PciDevCtl, self.config, self.caps[PCI_CAP_ID_EXP] + PCI_EXP_DEVCTL)
                self.devctl2 = DeviceField(PciDevCtl2, self.config, self.caps[PCI_CAP_ID_EXP] + PCI_EXP_DEVCTL2)
                self.link_cap = DeviceField(PciLinkCap, self.config, self.caps[PCI_CAP_ID_EXP] + PCI_EXP_LNKCAP)
                self.link_ctl = DeviceField(PciLinkControl, self.config, self.caps[PCI_CAP_ID_EXP] + PCI_EXP_LNKCTL)
                self.link_status = DeviceField(PciLinkStatus, self.config, self.caps[PCI_CAP_ID_EXP] + PCI_EXP_LNKSTA)
                # Root port or downstream port
                if self.pciflags["TYPE"] == 0x4 or self.pciflags["TYPE"] == 0x6:
                    self.link_ctl_2 = DeviceField(PciLinkControl2, self.config, self.caps[PCI_CAP_ID_EXP] + PCI_EXP_LNKCTL2)
                if self.pciflags["TYPE"] == 4:
                    self.rtctl = DeviceField(PciRootControl, self.config, self.caps[PCI_CAP_ID_EXP] + PCI_EXP_RTCTL)
                if self.pciflags["SLOT"] == 1:
                    self.slot_ctl = DeviceField(PciSlotControl, self.config, self.caps[PCI_CAP_ID_EXP] + PCI_EXP_SLTCTL)
            if self.has_aer():
                self.uncorr_status = DeviceField(PciUncorrectableErrors, self.config, self.ext_caps[PCI_EXT_CAP_ID_ERR] + PCI_ERR_UNCOR_STATUS, name="UNCOR_STATUS")
                self.uncorr_mask   = DeviceField(PciUncorrectableErrors, self.config, self.ext_caps[PCI_EXT_CAP_ID_ERR] + PCI_ERR_UNCOR_MASK, name="UNCOR_MASK")
                self.uncorr_sever  = DeviceField(PciUncorrectableErrors, self.config, self.ext_caps[PCI_EXT_CAP_ID_ERR] + PCI_ERR_UNCOR_SEVER, name="UNCOR_SEVER")
            if self.has_pm():
                self.pmctrl = DeviceField(PciPmControl, self.config, self.caps[PCI_CAP_ID_PM] + PCI_PM_CTRL)
            if self.has_acs():
                self.acs_ctl = DeviceField(AcsCtl, self.config, self.ext_caps[PCI_EXT_CAP_ID_ACS] + PCI_EXT_ACS_CTL)
            if self.has_dpc():
                self.dpc_ctrl   = DeviceField(DpcCtl, self.config, self.ext_caps[PCI_EXT_CAP_ID_DPC] + PCI_EXP_DPC_CTL)
                self.dpc_status = DeviceField(DpcStatus, self.config, self.ext_caps[PCI_EXT_CAP_ID_DPC] + PCI_EXP_DPC_STATUS)

        if is_sysfs_available:
            self.parent = PciDevice.find_or_init(sysfs_find_parent(dev_path))
        else:
            # Create a dummy device as the parent if sysfs is not available
            self.parent = Device()
    def is_hidden(self):
        return False

    def has_aer(self):
        return PCI_EXT_CAP_ID_ERR in self.ext_caps

    def has_sriov(self):
        return PCI_EXT_CAP_ID_SRIOV in self.ext_caps

    def has_dpc(self):
        return PCI_EXT_CAP_ID_DPC in self.ext_caps

    def has_acs(self):
        return PCI_EXT_CAP_ID_ACS in self.ext_caps

    def has_exp(self):
        return PCI_CAP_ID_EXP in self.caps

    def has_pm(self):
        return PCI_CAP_ID_PM in self.caps

    def reinit(self):
        self.__init__(self.dev_path)
    def _bar_num_to_sysfs_resource(self, barnum):
        sysfs_num = barnum
        # sysfs has gaps in case of 64-bit BARs
        for b in range(barnum):
            if self.bars[b][2]:
                sysfs_num += 1
        return sysfs_num

    def _init_bars_sysfs(self):
        self.bars = []
        resources = open(os.path.join(self.dev_path, "resource")).readlines()

        # Consider only first 6 resources
        for bar_line in resources[:6]:
            bar_line = bar_line.split(" ")
            addr = int(bar_line[0], base=16)
            end = int(bar_line[1], base=16)
            flags = int(bar_line[2], base=16)
            # Skip non-MMIO regions
            if flags & 0x1 != 0:
                continue
            if addr != 0:
                size = end - addr + 1
                is_64bit = False
                if (flags >> 1) & 0x3 == 0x2:
                    is_64bit = True
                self.bars.append((addr, size, is_64bit))
    def _init_bars(self):
        if is_sysfs_available:
            self._init_bars_sysfs()
        else:
            self._init_bars_config_space()

    def _map_bar(self, bar_num, bar_size=None):
        bar_addr = self.bars[bar_num][0]
        if not bar_size:
            bar_size = self.bars[bar_num][1]

        if use_nvpex:
            return NvPexBar(self.nvpex, bar=bar_num, size=bar_size)
        else:
            if mmio_access_type == "sysfs":
                return FileMap(os.path.join(self.dev_path, f"resource{self._bar_num_to_sysfs_resource(bar_num)}"), 0, bar_size)
            else:
                return FileMap("/dev/mem", bar_addr, bar_size)

    def _init_caps(self):
        self.caps = {}
        self.ext_caps = {}
        cap_offset = self.config.read8(PCI_CAPABILITY_LIST)
        data = 0
        if cap_offset == 0xff:
            self.cfg_space_broken = True
            error("Broken device %s", self.dev_path)
            return
        while cap_offset != 0:
            data = self.config.read32(cap_offset)
            cap_id = data & CAP_ID_MASK
            self.caps[cap_id] = cap_offset
            cap_offset = (data >> 8) & 0xff

        self._init_ext_caps()


    def _init_ext_caps(self):
        if self.config.size <= PCI_CFG_SPACE_SIZE:
            return

        offset = PCI_CFG_SPACE_SIZE
        header = self.config.read32(PCI_CFG_SPACE_SIZE)
        while offset != 0:
            cap = header & 0xffff
            self.ext_caps[cap] = offset

            offset = (header >> 20) & 0xffc
            header = self.config.read32(offset)

    def __str__(self):
        return "PCI %s %s:%s" % (self.bdf, hex(self.vendor), hex(self.device))

    def __hash__(self):
        return hash((self.bdf, self.vendor, self.device))

    def set_command_memory(self, enable):
        self.command["MEMORY"] = 1 if enable else 0
    def sanity_check_cfg_space(self):
        # Use an offset unlikely to be intercepted in case of virtualization
        vendor = self.config.read16(0xf0)
        return vendor != 0xffff
    def sysfs_reset(self):
        reset_path = os.path.join(self.dev_path, "reset")
        if not os.path.exists(reset_path):
            error("%s reset not present: '%s'", self, reset_path)
        with open(reset_path, "w") as rf:
            rf.write("1")

    def reset_with_os(self):
        if is_linux:
            return self.sysfs_reset()
    def is_flr_supported(self):
        if not self.has_exp():
            return False

        return self.devcap["FLR"] == 1

PCI_BRIDGE_CONTROL = 0x3e
class PciBridgeControl(Bitfield):
    size = 1
    fields = {
            # Enable parity detection on secondary interface
            "PARITY": 0x01,

            # The same for SERR forwarding
            "SERR": 0x02,

            # Enable ISA mode
            "ISA": 0x04,

            # Forward VGA addresses
            "VGA": 0x08,

            # Report master aborts
            "MASTER_ABORT": 0x20,

            # Secondary bus reset (SBR)
            "BUS_RESET": 0x40,

            # Fast Back2Back enabled on secondary interface
            "FAST_BACK": 0x80,
    }

    def __str__(self):
        return "{ Bridge control " + str(self.values()) + " raw " + hex(self.raw) + " }"


class PciBridge(PciDevice):
    def __init__(self, dev_path):
        super(PciBridge, self).__init__(dev_path)
        self.bridge_ctl = DeviceField(PciBridgeControl, self.config, PCI_BRIDGE_CONTROL)
        if self.parent:
            self.parent.children.append(self)
class BrokenGpu(PciDevice):
    def __init__(self, dev_path):
        super(BrokenGpu, self).__init__(dev_path)
        self.name = "BrokenGpu"
        self.cfg_space_working = False
        self.bars_configured = False
        self.cfg_space_working = self.sanity_check_cfg_space()
        error("Config space working %s", str(self.cfg_space_working))
        if self.cfg_space_working:
            self.bars_configured = self.sanity_check_cfg_space_bars()

        if self.parent:
            self.parent.children.append(self)

    def is_gpu(self):
        return True

    def is_broken_gpu(self):
        return True

    def reset_with_sbr(self):
        assert self.parent.is_bridge()
        self.parent.toggle_sbr()
        return self.sanity_check_cfg_space()

    def is_driver_loaded(self):
        return False

    def __str__(self):
        return "GPU %s [broken, cfg space working %d bars configured %d]" % (self.bdf, self.cfg_space_working, self.bars_configured)

class NvidiaDevice(PciDevice):
    def __init__(self, dev_path):
        super(NvidiaDevice, self).__init__(dev_path)

        self.bar0_addr = self.bars[0][0]
        self.fsp_rpc = None
        self._mod_name = None

        if self.parent:
            self.parent.children.append(self)

    def common_init(self):
        self.nvlink = None
        if "nvlink" in self.props:
            self.nvlink = self.props["nvlink"]

    @property
    def is_nvlink_supported(self):
        return self.nvlink is not None

    def is_gpu(self):
        return False

    def is_broken_gpu(self):
        return False

    def is_unknown(self):
        return True

    def reset_with_sbr(self):
        assert False

    def write(self, reg, data):
        self.bar0.write32(reg, data)

    def write_verbose(self, reg, data):
        old = self.read(reg)
        self.bar0.write32(reg, data)
        new = self.read(reg)
        debug("%s writing %s = %s (old %s diff %s) new %s", self, hex(reg), hex(data), hex(old), hex(data ^ old), hex(new))

    def sanity_check(self):
        if not self.sanity_check_cfg_space():
            debug("%s sanity check of config space failed", self)
            return False

        boot = self.read(NV_PMC_BOOT_0)
        if boot == 0xffffffff:
            debug("%s sanity check of mmio failed", self)
            return False

        return True

    def reset_pre(self, reset_with_flr=None):
        if reset_with_flr == None:
            reset_with_flr = self.is_flr_supported()

        debug("%s reset_pre FLR supported %s, FLR being used %s", self, self.is_flr_supported(), reset_with_flr)

        self.expected_sbr_only_scratch = (1 if reset_with_flr else 0)

        flr_scratch = self.flr_resettable_scratch()
        sbr_scratch = self.sbr_resettable_scratch()

        self.write_verbose(flr_scratch, 0x1)
        self.write_verbose(sbr_scratch, 0x1)

        if self.read(sbr_scratch) == 0:
            debug(f"{self} SBR scratch writes not sticking")
            self.expected_sbr_only_scratch = 0

    def reset_post(self):
        flr_scratch = self.flr_resettable_scratch()
        sbr_scratch = self.sbr_resettable_scratch()

        debug(f"{self} reset_post flr-scratch after 0x{self.read_bad_ok(flr_scratch):x}, sbr-only scratch 0x{self.read_bad_ok(sbr_scratch):x}, flr cap {self.is_flr_supported()}")
    def sysfs_reset(self):
        self.reset_pre()

        super(NvidiaDevice, self).sysfs_reset()

        self.reset_post()

    def _init_fsp_rpc(self):
        if self.fsp_rpc != None:
            return

        # Wait for boot to be done such that FSP is available
        self.wait_for_boot()

        self.init_npus()

        self.fsp_rpc = FspRpc(self.fsp, channel_num=2)

    def poll_register(self, name, offset, value, timeout, sleep_interval=0.01, mask=0xffffffff, debug_print=False):
        timestamp = perf_counter()
        while True:
            loop_stamp = perf_counter()
            try:
                if value >> 16 == 0xbadf:
                    reg = self.read_bad_ok(offset)
                else:
                    reg = self.read(offset)
            except:
                error("Failed to read npu register %s (%s)", name, hex(offset))
                raise

            if reg & mask == value:
                if debug_print:
                    debug("Register %s (%s) = %s after %f secs", name, hex(offset), hex(value), perf_counter() - timestamp)
                return
            if loop_stamp - timestamp > timeout:
                raise GpuError("Timed out polling register %s (%s), value %s is not the expected %s. Timeout %f secs" % (name, hex(offset), hex(reg), hex(value), timeout))
            if sleep_interval > 0.0:
                time.sleep(sleep_interval)

class NvSwitch(NvidiaDevice):
    def __init__(self, dev_path):
        self.name = "?"
        self.bar0_addr = 0
        super(NvSwitch, self).__init__(dev_path)
    def is_nvswitch(self):
        return True
    def __str__(self):
        return "NvSwitch %s %s %s BAR0 0x%x" % (self.bdf, self.name, hex(self.device), self.bar0_addr)

class IntelRootPort(PciBridge):
    def __init__(self, dev_path):
        super(IntelRootPort, self).__init__(dev_path)
    def is_intel(self):
        return True
    def __str__(self):
        return "Intel root port %s" % self.bdf

class GpuMemPort(object):
    def __init__(self, name, mem_control_reg, max_size, npu):
        self.name = name
        self.control_reg = mem_control_reg
        self.data_reg = self.control_reg + NV_PPWR_NPU_IMEMD(0) - NV_PPWR_NPU_IMEMC(0)
        self.offset = 0
        self.max_size = max_size
        self.auto_inc_read = False
        self.auto_inc_write = False
        self.secure_imem = False
        self.npu = npu
        self.need_to_write_config_to_hw = True

    def __str__(self):
        return "%s offset %d (0x%x) incr %d incw %d max size %d (0x%x) control reg 0x%x = 0x%x" % (self.name,
                self.offset, self.offset, self.auto_inc_read, self.auto_inc_write,
                self.max_size, self.max_size,
                self.control_reg, self.npu.gpu.read(self.control_reg))

    def configure(self, offset, inc_read=True, inc_write=True, secure_imem=False):
        need_to_write = self.need_to_write_config_to_hw

        if offset != self.offset:
            self.offset = offset
            need_to_write = True

        if self.auto_inc_read != inc_read:
            self.auto_inc_read = inc_read
            need_to_write = True

        if self.auto_inc_write != inc_write:
            self.auto_inc_write = inc_write
            need_to_write = True

        if self.secure_imem != secure_imem:
            self.secure_imem = secure_imem
            need_to_write = True

        if not need_to_write:
            return

        memc_value = offset
        if inc_read:
            memc_value |= NV_PPWR_NPU_IMEMC_AINCR_TRUE
        if inc_write:
            memc_value |= NV_PPWR_NPU_IMEMC_AINCW_TRUE
        if secure_imem:
            memc_value |= NV_PPWR_NPU_IMEMC_SECURE_ENABLED

        self.npu.gpu.write(self.control_reg, memc_value)
        self.need_to_write_config_to_hw = False

    def handle_offset_wraparound(self):
        if self.offset == self.max_size:
            self.configure(0, self.auto_inc_read, self.auto_inc_write, self.secure_imem)

    def read(self, size):
        data = []
        for offset in range(0, size, 4):
            # MEM could match 0xbadf... so use read_bad_ok()
            data.append(self.npu.gpu.read_bad_ok(self.data_reg))

        if self.auto_inc_read:
            self.offset += size

        self.handle_offset_wraparound()

        return data

    def write(self, data, debug_write=False):
        for d in data:
            if debug_write:
                control = self.npu.gpu.read(self.control_reg)
                debug("Writing data %s = %s offset %s, control %s", hex(self.data_reg), hex(d), hex(self.offset), hex(control))
            self.npu.gpu.write(self.data_reg, d)
            if self.auto_inc_write:
                self.offset += 4

        self.handle_offset_wraparound()

class GpuImemPort(GpuMemPort):
    def __init__(self, name, mem_control_reg, max_size, npu):
        super(GpuImemPort, self).__init__(name, mem_control_reg, max_size, npu)
        self.imemt_reg = self.control_reg + NV_PPWR_NPU_IMEMT(0) - NV_PPWR_NPU_IMEMC(0)
class GpuFalcon(object):
    def __init__(self, name, cpuctl, device, pmc_enable_mask=None, pmc_device_enable_mask=None):
        self.name = name
        self.device = device
        self.gpu = device
        self.base_page = cpuctl & ~0xfff
        self.base_page_emem = getattr(self, 'base_page_emem', self.base_page)
        self.cpuctl = cpuctl
        self.pmc_enable_mask = pmc_enable_mask
        self.pmc_device_enable_mask = pmc_device_enable_mask
        self.no_outside_reset = getattr(self, 'no_outside_reset', False)
        self.has_emem = getattr(self, 'has_emem', False)
        self.num_emem_ports = getattr(self, 'num_emem_ports', 1)
        self._max_imem_size = None
        self._max_dmem_size = None
        self._max_emem_size = None
        self._imem_port_count = None
        self._dmem_port_count = None
        self._default_core_npu = None
        self._can_run_ns = None

        self.csb_offset_mailbox0 = getattr(self, 'csb_offset_mailbox0', 0x40)

        self.mem_ports = []
        self.enable()
        self.mem_spaces = ["imem", "dmem"]

        self.imem_ports = []
        for p in range(0, self.imem_port_count):
            name = self.name + "_imem_%d" % p
            mem_control_reg = self.imemc + p * 16
            max_size = self.max_imem_size
            self.imem_ports.append(GpuImemPort(name, mem_control_reg, max_size, self))

        self.dmem_ports = []
        for p in range(0, self.dmem_port_count):
            name = self.name + "_dmem_%d" % p
            mem_control_reg = self.dmemc + p * 8
            max_size = self.max_dmem_size
            self.dmem_ports.append(GpuMemPort(name, mem_control_reg, max_size, self))

        self.emem_ports = []
        if self.has_emem:
            self.mem_spaces.append("emem")
            self._init_emem_ports()

        self.mem_ports = self.imem_ports + self.dmem_ports + self.emem_ports

    def _init_emem_ports(self):
        assert self.has_emem
        for p in range(self.num_emem_ports):
            name = self.name + f"_emem_{p}"
            self.emem_ports.append(GpuMemPort(name, self.base_page_emem + 0xac0 + p * 8, self.max_emem_size, self))

    @property
    def imemc(self):
        return self.cpuctl + NV_PPWR_NPU_IMEMC(0) - NV_PPWR_NPU_CPUCTL

    @property
    def dmemc(self):
        return self.cpuctl + NV_PPWR_NPU_DMEMC(0) - NV_PPWR_NPU_CPUCTL
    @property
    def hwcfg1(self):
        return self.cpuctl + NV_PPWR_NPU_HWCFG1 - NV_PPWR_NPU_CPUCTL

    @property
    def hwcfg_emem(self):
        return self.cpuctl + 0x9bc
    @property
    def max_imem_size(self):
        if self._max_imem_size:
            return self._max_imem_size

        if self.name not in self.gpu.npus_cfg:
            if self.gpu.needs_npus_cfg:
                error("Missing imem/dmem config for npu %s, falling back to hwcfg", self.name)
            self._max_imem_size = self.max_imem_size_from_hwcfg()
        else:
            # Use the imem size provided in the GPU config
            self._max_imem_size = self.gpu.npus_cfg[self.name]["imem_size"]

        # And make sure it matches HW
        if self._max_imem_size != self.max_imem_size_from_hwcfg():
            raise GpuError("HWCFG imem doesn't match %d != %d" % (self._max_imem_size, self.max_imem_size_from_hwcfg()))

        return self._max_imem_size

    @property
    def max_dmem_size(self):
        if self._max_dmem_size:
            return self._max_dmem_size

        if self.name not in self.gpu.npus_cfg:
            if self.gpu.needs_npus_cfg:
                error("Missing imem/dmem config for npu %s, falling back to hwcfg", self.name)
            self._max_dmem_size = self.max_dmem_size_from_hwcfg()
        else:
            # Use the dmem size provided in the GPU config
            self._max_dmem_size = self.gpu.npus_cfg[self.name]["dmem_size"]

        # And make sure it matches HW
        if self._max_dmem_size != self.max_dmem_size_from_hwcfg():
            raise GpuError("HWCFG dmem doesn't match %d != %d" % (self._max_dmem_size, self.max_dmem_size_from_hwcfg()))

        return self._max_dmem_size

    @property
    def max_emem_size(self):
        if self._max_emem_size:
            return self._max_emem_size

        if self.name not in self.gpu.npus_cfg or "emem_size" not in self.gpu.npus_cfg[self.name]:
            if self.gpu.needs_npus_cfg:
                error("Missing emem config for npu %s, falling back to hwcfg", self.name)
            self._max_emem_size = self.max_emem_size_from_hwcfg()
        else:
            # Use the emem size provided in the GPU config
            self._max_emem_size = self.gpu.npus_cfg[self.name]["emem_size"]

        # And make sure it matches HW
        if self._max_emem_size != self.max_emem_size_from_hwcfg():
            raise GpuError("HWCFG emem doesn't match %d != %d" % (self._max_emem_size, self.max_emem_size_from_hwcfg()))

        return self._max_emem_size

    @property
    def dmem_port_count(self):
        if self._dmem_port_count:
            return self._dmem_port_count

        if self.name not in self.gpu.npus_cfg or "dmem_port_count" not in self.gpu.npus_cfg[self.name]:
            if self.gpu.needs_npus_cfg:
                error("%s missing dmem port count for npu %s, falling back to hwcfg", self.gpu, self.name)
            self._dmem_port_count = self.dmem_port_count_from_hwcfg()
        else:
            # Use the dmem port count provided in the GPU config
            self._dmem_port_count = self.gpu.npus_cfg[self.name]["dmem_port_count"]

        # And make sure it matches HW
        if self._dmem_port_count != self.dmem_port_count_from_hwcfg():
            raise GpuError("HWCFG dmem port count doesn't match %d != %d" % (self._dmem_port_count, self.dmem_port_count_from_hwcfg()))

        return self._dmem_port_count

    @property
    def imem_port_count(self):
        if self._imem_port_count:
            return self._imem_port_count

        if self.name not in self.gpu.npus_cfg or "imem_port_count" not in self.gpu.npus_cfg[self.name]:
            if self.gpu.needs_npus_cfg:
                error("%s missing imem port count for npu %s, falling back to hwcfg", self.gpu, self.name)
            self._imem_port_count = self.imem_port_count_from_hwcfg()
        else:
            # Use the imem port count provided in the GPU config
            self._imem_port_count = self.gpu.npus_cfg[self.name]["imem_port_count"]

        # And make sure it matches HW
        if self._imem_port_count != self.imem_port_count_from_hwcfg():
            raise GpuError("HWCFG imem port count doesn't match %d != %d" % (self._imem_port_count, self.imem_port_count_from_hwcfg()))

        return self._imem_port_count
    def max_imem_size_from_hwcfg(self):
        if self.device.is_nvswitch() or self.gpu.is_ampere_plus:
            hwcfg = self.gpu.read(self.base_page + 0x278)
            return (hwcfg & 0xfff) * 256
        else:
            hwcfg = self.gpu.read(self.hwcfg)
            return (hwcfg & 0x1ff) * 256

    def max_dmem_size_from_hwcfg(self):
        if self.device.is_nvswitch() or self.gpu.is_ampere_plus:
            hwcfg = self.gpu.read(self.base_page + 0x278)
            return ((hwcfg >> 16) & 0xfff) * 256
        else:
            hwcfg = self.gpu.read(self.hwcfg)
            return ((hwcfg >> 9) & 0x1ff) * 256

    def max_emem_size_from_hwcfg(self):
        assert self.has_emem
        hwcfg = self.gpu.read(self.hwcfg_emem)
        return (hwcfg & 0x1ff) * 256

    def imem_port_count_from_hwcfg(self):
        hwcfg = self.gpu.read(self.hwcfg1)
        return ((hwcfg >> 8) & 0xf)

    def dmem_port_count_from_hwcfg(self):
        hwcfg = self.gpu.read(self.hwcfg1)
        return ((hwcfg >> 12) & 0xf)

    def get_mem_ports(self, mem):
        if mem == "imem":
            return self.imem_ports
        elif mem == "dmem":
            return self.dmem_ports
        elif mem == "emem":
            assert self.has_emem
            return self.emem_ports
        else:
            assert 0, "Unknown mem %s" % mem

    def get_mem_port(self, mem, port=0):
        return self.get_mem_ports(mem)[port]

    def load_imem(self, data, phys_base, virt_base, secure=False, virtual_tag=True, debug_load=False):
        self.imem_ports[0].configure(offset=phys_base, secure_imem=secure)
        if virtual_tag:
            self.imem_ports[0].write_with_tags(data, virt_base=virt_base, debug_write=debug_load)
        else:
            self.imem_ports[0].write(data, debug_write=debug_load)

    def read_port(self, port, phys_base, size):
        port.configure(offset=phys_base)
        return port.read(size)

    def write_port(self, port, data, phys_base, debug_write=False):
        port.configure(offset=phys_base)
        port.write(data, debug_write)

    def read_imem(self, phys_base, size):
        return self.read_port(self.imem_ports[0], phys_base, size)

    def load_dmem(self, data, phys_base, debug_load=False):
        self.write_port(self.dmem_ports[0], data, phys_base, debug_write=debug_load)

    def read_dmem(self, phys_base, size):
        return self.read_port(self.dmem_ports[0], phys_base, size)

    def write_emem(self, data, phys_base, port=0, debug_write=False):
        self.write_port(self.emem_ports[port], data, phys_base, debug_write=debug_write)

    def read_emem(self, phys_base, size, port=0):
        return self.read_port(self.emem_ports[port], phys_base, size)
    def enable(self):
        if self.no_outside_reset:
            pass
        elif self.pmc_enable_mask:
            pmc_enable = self.gpu.read(NV_PMC_ENABLE)
            self.gpu.write(NV_PMC_ENABLE, pmc_enable | self.pmc_enable_mask)
        elif self.pmc_device_enable_mask:
            enable = self.gpu.read(NV_PMC_DEVICE_ENABLE)
            self.gpu.write(NV_PMC_DEVICE_ENABLE, enable | self.pmc_device_enable_mask)
        else:
            self.gpu.write(self.engine_reset, 0)

        if not self.device.has_fsp:
            if not self.default_core_npu:
                self.select_core_npu()

            self.gpu.poll_register(self.name + " dmactl", self.dmactl, value=0, timeout=1, mask=0x6)
        self.reset_mem_ports()

    def reset_mem_ports(self):
        for m in self.mem_ports:
            m.need_to_write_config_to_hw = True
class FspFalcon(GpuFalcon):
    def __init__(self, device):
        self.no_outside_reset = True
        self.has_emem = True
        self.base_page_emem = 0x8f2000
        self.num_emem_ports = 8
        super(FspFalcon, self).__init__("fsp", 0x8f0100, device, pmc_enable_mask=None)

    def queue_head_off(self, i):
        return self.base_page + 0x2c00 + i * 8

    def queue_tail_off(self, i):
        return self.base_page + 0x2c04 + i * 8

    def msg_queue_head_off(self, i):
        return self.base_page + 0x2c80 + i * 8

    def msg_queue_tail_off(self, i):
        return self.base_page + 0x2c84 + i * 8

class FspRpc(object):
    def __init__(self, fsp_npu, channel_num):
        self.npu = fsp_npu
        self.device = self.npu.device
        self.channel_num = channel_num

        self.nvdm_emem_base = self.channel_num * 1024

        self.reset_rpc_state()

    def __str__(self):
        return f"{self.device} FSP-RPC"

    def reset_rpc_state(self):
        if self.is_queue_empty() and self.is_msg_queue_empty():
            debug(f"{self} both queues empty; queue {self.read_queue_state()} msg queue {self.read_msg_queue_state()}")
            return

        debug(f"{self} one of the queues not empty, waiting for things to settle; queue {self.read_queue_state()} msg queue {self.read_msg_queue_state()}")
        self.poll_for_msg_queue(timeout_fatal=False)
        debug(f"{self} after wait; queue {self.read_queue_state()} msg queue {self.read_msg_queue_state()}")

        # Reset both queues
        self.write_queue_head_tail(self.nvdm_emem_base, self.nvdm_emem_base)
        self.device.write_verbose(self.npu.msg_queue_tail_off(self.channel_num), self.nvdm_emem_base)
        self.device.write_verbose(self.npu.msg_queue_head_off(self.channel_num), self.nvdm_emem_base)

    def read_queue_state(self):
        return (self.device.read(self.npu.queue_head_off(self.channel_num)),
                self.device.read(self.npu.queue_tail_off(self.channel_num)))

    def is_queue_empty(self):
        mhead, mtail = self.read_queue_state()
        return mhead == mtail

    def write_queue_head_tail(self, head, tail):
        self.device.write_verbose(self.npu.queue_tail_off(self.channel_num), tail)
        self.device.write_verbose(self.npu.queue_head_off(self.channel_num), head)

    def read_msg_queue_state(self):
        return (self.device.read(self.npu.msg_queue_head_off(self.channel_num)),
                self.device.read(self.npu.msg_queue_tail_off(self.channel_num)))

    def is_msg_queue_empty(self):
        mhead, mtail = self.read_msg_queue_state()
        return mhead == mtail

    def write_msg_queue_tail(self, tail):
        self.device.write_verbose(self.npu.msg_queue_tail_off(self.channel_num), tail)


    def poll_for_msg_queue(self, timeout=5, sleep_interval=0.01, timeout_fatal=True):
        timestamp = perf_counter()
        while True:
            loop_stamp = perf_counter()
            mhead, mtail = self.read_msg_queue_state()
            if mhead != mtail:
                return
            if loop_stamp - timestamp > timeout:
                if timeout_fatal:
                    raise GpuError(f"Timed out polling for {self.npu.name} message queue on channel {self.channel_num}. head {mhead} == tail {mtail}")
                else:
                    return
            if sleep_interval > 0.0:
                time.sleep(sleep_interval)

    def poll_for_queue_empty(self, timeout=1, sleep_interval=0.01):
        timestamp = perf_counter()
        while True:
            loop_stamp = perf_counter()
            if self.is_queue_empty():
                return
            if loop_stamp - timestamp > timeout:
                raise GpuError(f"Timed out polling for {self.npu.name} cmd queue to be empty on channel {self.channel_num}. head {mhead} != tail {mtail}")
            if sleep_interval > 0.0:
                time.sleep(sleep_interval)

    def prc_cmd(self, data):
        mctp_header = MctpHeader()
        mctp_msg_header = MctpMessageHeader()

        mctp_msg_header.fields.nvdm_type = 0x13

        self.device.wait_for_boot()

        self.poll_for_queue_empty()
        head, tail = self.read_queue_state()
        if head != tail:
            raise GpuError(f"RPC cmd queue not empty head {head} tail {tail}")
        mhead, mtail = self.read_msg_queue_state()
        if mhead != mtail:
            raise GpuError(f"RPC msg queue not empty head {mhead} tail {mtail}")

        cdata = [mctp_header.raw, mctp_msg_header.raw] + data
        debug(f"{self} command {[hex(d) for d in cdata]}")
        self.npu.write_emem(cdata, phys_base=self.nvdm_emem_base, port=self.channel_num)
        self.write_queue_head_tail(self.nvdm_emem_base, self.nvdm_emem_base + (len(cdata) - 1) * 4)
        rpc_time = perf_counter()
        self.poll_for_msg_queue()
        rpc_time = perf_counter() - rpc_time
        debug(f"{self} response took {rpc_time*1000:.1f} ms")

        mhead, mtail = self.read_msg_queue_state()
        debug(f"{self} msg queue after poll {mhead} {mtail}")
        msize = mtail - mhead + 4
        mdata = self.npu.read_emem(self.nvdm_emem_base, msize, port=self.channel_num)
        debug(f"{self} response {[hex(d) for d in mdata]}")

        # Reset the tail before checking for errors
        self.write_msg_queue_tail(mhead)

        if msize < 5 * 4:
            raise GpuError(f"{self} response size {msize} is smaller than expected. Data {[hex(d) for d in mdata]}")
        mctp_msg_header.raw = mdata[1]
        if mctp_msg_header.fields.nvdm_type != 0x15:
            raise GpuError(f"{self} message wrong nvdm_type. Data {[hex(d) for d in mdata]}")
        if mdata[3] != 0x13:
            raise GpuError(f"{self} message request type 0x{mdata[3]:x} not matching the command. Data {[hex(d) for d in mdata]}")
        if mdata[4] != 0x0:
            raise GpuError(f"{self} failed with error 0x{mdata[4]:x}. Data {[hex(d) for d in mdata]}")

        return mdata[5:]
    def prc_knob_read(self, knob_id):
        # Knob read is sub msg 0xc
        prc = 0xc
        prc |= 0x2 << 8
        prc |= knob_id << 16

        debug(f"{self} reading knob 0x{knob_id:x}")

        data = self.prc_cmd([prc])
        if len(data) != 1:
            raise GpuError(f"RPC wrong response size {len(data)}. Data {[hex(d) for d in data]}")

        debug(f"{self} read knob 0x{knob_id:x} = 0x{data[0]:x}")

        return data[0]

    def prc_knob_write(self, knob_id, value):
        # Knob write is sub msg 0xd
        prc = 0xd
        prc |= 0x2 << 8
        prc |= knob_id << 16

        prc_1 = value

        debug(f"{self} writing knob 0x{knob_id:x} = 0x{value:x}")

        data = self.prc_cmd([prc, prc_1])
        if len(data) != 0:
            raise GpuError(f"RPC wrong response size {len(data)}. Data {[hex(d) for d in data]}")

        debug(f"{self} wrote knob 0x{knob_id:x} = 0x{value:x}")

    def prc_knob_check_and_write(self, knob_id, value):
        old_value = self.prc_knob_read(knob_id)
        if old_value != value:
            self.prc_knob_write(knob_id, value)

class UnknownDevice(Exception):
    pass

class UnknownGpuError(Exception):
    pass

class BrokenGpuError(Exception):
    pass

class GpuError(Exception):
    pass
class GpuUcode(object):
    def __init__(self, name, binary):
        self.name = name
        self.binary = binary
        self.pkc = None

    @property
    def imem_ns_size(self):
        return len(self.imem_ns) * 4

    @property
    def imem_sec_size(self):
        return len(self.imem_sec) * 4

    @property
    def dmem_size(self):
        return len(self.dmem) * 4

    def __str__(self):
        return "Ucode %s (imem_ns size %d virt 0x%x phys 0x%x, imem_sec size %d virt 0x%x phys 0x%x, dmem size %d base 0x%x)" % (self.name,
                self.imem_ns_size, self.imem_ns_virt_base, self.imem_ns_phys_base,
                self.imem_sec_size, self.imem_sec_virt_base, self.imem_sec_phys_base,
                self.dmem_size, self.dmem_phys_base)
class NiceStruct(ctypes.LittleEndianStructure):
    def __str__(self) -> str:
        fields = {field[0]: getattr(self, field[0]) for field in self._fields_}
        return str(fields)

class MctpHeader_bits(NiceStruct):
    _fields_ = [
            ("version", c_uint32, 4),
            ("rsvd0", c_uint32, 4),
            ("deid", c_uint32, 8),
            ("seid", c_uint32, 8),
            ("tag", c_uint32, 3),
            ("to", c_uint32, 1),
            ("seq", c_uint32, 2),
            ("eom", c_uint32, 1),
            ("som", c_uint32, 1),
        ]
class MctpHeader(ctypes.Union):
    _fields_ = [("fields", MctpHeader_bits),
                ("raw", c_uint32)]

    def __init__(self):
        self.fields.som = 1
        self.fields.eom = 1

class MctpMessageHeader_bits(NiceStruct):
    _fields_ = [
            ("type", c_uint32, 7),
            ("ic", c_uint32, 1),
            ("vendor_id", c_uint32, 16),
            ("nvdm_type", c_uint32, 8),
    ]

class MctpMessageHeader(ctypes.Union):
    _fields_ = [("fields", MctpMessageHeader_bits),
                ("raw", c_uint32)]

    def __init__(self):
        self.fields.type = 0x7e
        self.fields.vendor_id = 0x10de

class PrcKnob(Enum):
    PRC_KNOB_ID_01                                  = 0x01
    PRC_KNOB_ID_02                                  = 0x02
    PRC_KNOB_ID_03                                  = 0x03
    PRC_KNOB_ID_04                                  = 0x04
    PRC_KNOB_ID_CCD_ALLOW_INB                       = 0x05
    PRC_KNOB_ID_CCD                                 = 0x06
    PRC_KNOB_ID_CCM_ALLOW_INB                       = 0x07
    PRC_KNOB_ID_CCM                                 = 0x08
    PRC_KNOB_ID_BAR0_DECOUPLER_ALLOW_INB            = 0x09
    PRC_KNOB_ID_BAR0_DECOUPLER                      = 0x0a
    PRC_KNOB_ID_21                                  = 0x21
    PRC_KNOB_ID_22                                  = 0x22

class Gpu(NvidiaDevice):
    def __init__(self, dev_path):
        self.name = "?"
        self.bar0_addr = 0

        super(Gpu, self).__init__(dev_path)

        if not self.sanity_check_cfg_space():
            debug("%s sanity check of config space failed", self)
            raise BrokenGpuError()

        # Enable MMIO
        self.set_command_memory(True)
        if self.has_pm():
            if self.pmctrl["STATE"] != 0:
                warning("%s not in D0 (current state %d), forcing it to D0", self, self.pmctrl["STATE"])
                self.pmctrl["STATE"] = 0

        self.bar0_addr = self.bars[0][0]
        self.bar0_size = GPU_BAR0_SIZE
        self.bar1_addr = self.bars[1][0]

        self.bar0 = self._map_bar(0)
        # Map just a small part of BAR1 as we don't need it all
        self.bar1 = self._map_bar(1, 1024 * 1024)

        self.pmcBoot0 = self.read(NV_PMC_BOOT_0)

        if self.pmcBoot0 == 0xffffffff:
            debug("%s sanity check of bar0 failed", self)
            raise BrokenGpuError()

        gpu_map_key = self.pmcBoot0

        if gpu_map_key in GPU_MAP_MULTIPLE:
            match = GPU_MAP_MULTIPLE[self.pmcBoot0]
            # Check for a device id match. Fall back to the default, if not found.
            gpu_map_key = GPU_MAP_MULTIPLE[self.pmcBoot0]["devids"].get(self.device, match["default"])

        if gpu_map_key not in GPU_MAP:
            for off in [0x0, 0x88000, 0x88004]:
                debug("%s offset 0x%x = 0x%x", self.bdf, off, self.read(off))
            raise UnknownGpuError("GPU %s %s bar0 %s" % (self.bdf, hex(self.pmcBoot0), hex(self.bar0_addr)))

        self.gpu_props = GPU_MAP[gpu_map_key]
        gpu_props = self.gpu_props
        self.props = gpu_props
        self.name = gpu_props["name"]
        self.arch = gpu_props["arch"]
        self.is_pmu_reset_in_pmc = gpu_props["pmu_reset_in_pmc"]
        self.is_memory_clear_supported = gpu_props["memory_clear_supported"]
        # Querying ECC state relies on being able to initialize/clear memory
        self.is_ecc_query_supported = self.is_memory_clear_supported
        self.is_cc_query_supported = self.is_hopper_plus
        self.is_forcing_ecc_on_after_reset_supported = gpu_props["forcing_ecc_on_after_reset_supported"]
        self.is_setting_ecc_after_reset_supported = self.is_ampere_plus
        self.is_mig_mode_supported = self.is_ampere_100
        if not self.sanity_check():
            debug("%s sanity check failed", self)
            raise BrokenGpuError()
        self.init_priv_ring()

        self.bar0_window_base = 0
        self.bar0_window_initialized = False
        self.bios = None
        self.npus = None
        self.npu_dma_initialized = False
        self.npus_cfg = gpu_props.get("npus_cfg", {})
        self.needs_npus_cfg = gpu_props.get("needs_npus_cfg", {})

        if self.is_ampere_plus:
            graphics_mask = 0
            graphics_bits = [12]
            if self.is_ampere_100:
                graphics_bits += [1, 9, 10, 11, 13, 14, 18]
            for gb in graphics_bits:
                graphics_mask |= (0x1 << gb)

            self.pmc_device_graphics_mask = graphics_mask
        self.hulk_ucode_data = None

        self.common_init()

    def init_npus(self):
        if self.npus is not None:
            return

        self.npus = []
        gpu_props = self.gpu_props
        if "fsp" in gpu_props["other_npus"]:
            self.fsp = FspFalcon(self)
            self.npus.append(self.fsp)

    @property
    def is_maxwell_plus(self):
        return GPU_ARCHES.index(self.arch) >= GPU_ARCHES.index("maxwell")

    @property
    def is_pascal(self):
        return GPU_ARCHES.index(self.arch) == GPU_ARCHES.index("pascal")

    @property
    def is_pascal_plus(self):
        return GPU_ARCHES.index(self.arch) >= GPU_ARCHES.index("pascal")

    @property
    def is_pascal_10x_plus(self):
        return self.is_pascal_plus and self.name != "P100"

    @property
    def is_pascal_10x(self):
        return self.is_pascal and self.name != "P100"

    @property
    def is_volta(self):
        return GPU_ARCHES.index(self.arch) == GPU_ARCHES.index("volta")

    @property
    def is_volta_plus(self):
        return GPU_ARCHES.index(self.arch) >= GPU_ARCHES.index("volta")

    @property
    def is_turing(self):
        return GPU_ARCHES.index(self.arch) == GPU_ARCHES.index("turing")

    @property
    def is_turing_plus(self):
        return GPU_ARCHES.index(self.arch) >= GPU_ARCHES.index("turing")

    @property
    def is_ampere(self):
        return GPU_ARCHES.index(self.arch) == GPU_ARCHES.index("ampere")

    @property
    def is_ampere_plus(self):
        return GPU_ARCHES.index(self.arch) >= GPU_ARCHES.index("ampere")

    @property
    def is_ampere_100(self):
        return self.name in ["A100", "A30"]

    @property
    def is_ampere_10x(self):
        return self.is_ampere and not self.is_ampere_100

    @property
    def is_ampere_10x_plus(self):
        return self.is_ampere_plus and not self.is_ampere_100

    @property
    def is_hopper(self):
        return GPU_ARCHES.index(self.arch) == GPU_ARCHES.index("hopper")

    @property
    def is_hopper_plus(self):
        return GPU_ARCHES.index(self.arch) >= GPU_ARCHES.index("hopper")

    @property
    def is_hopper_100(self):
        return self.name in ["H100-PCIE", "H100-SXM"]

    @property
    def has_fsp(self):
        return self.is_hopper_plus

    def is_gpu(self):
        return True

    @property
    def is_module_name_supported(self):
        return self.name == "H100-SXM"

    @property
    def module_name(self):
        if self._mod_name != None:
            return self._mod_name
        self._mod_name = f"SXM_{self.read_module_id() + 1}"
        return self._mod_name

    def vbios_scratch_register(self, index):
        if self.is_turing_plus:
            return 0x1400 + index * 4
        else:
            return 0x1580 + index * 4

    def load_vbios(self):
        if self.bios:
            return

        self._load_bios()

    def reload_vbios(self):
        self._load_bios()
    def query_cc_mode(self):
        assert self.is_cc_query_supported
        self.wait_for_boot()
        cc_reg = self.read(0x1182cc)
        cc_state = cc_reg & 0x3
        if cc_state == 0x3:
            return "devtools"
        elif cc_state == 0x1:
            return "on"
        elif cc_state == 0x0:
            return "off"

        raise GpuError(f"Unexpected CC state 0x{cc_reg}")

    def set_cc_mode(self, mode):
        assert self.is_cc_query_supported

        cc_mode = 0x0
        cc_dev_mode = 0x0
        bar0_decoupler_val = 0x0
        if mode == "on":
            cc_mode = 0x1
            bar0_decoupler_val = 0x1
        elif mode == "devtools":
            cc_mode = 0x1
            cc_dev_mode = 0x1
        elif mode == "off":
            pass
        else:
            raise ValueError(f"Invalid mode {mode}")

        self._init_fsp_rpc()

        if cc_mode == 0x1:
            self.fsp_rpc.prc_knob_check_and_write(PrcKnob.PRC_KNOB_ID_02.value, 0x0)
            self.fsp_rpc.prc_knob_check_and_write(PrcKnob.PRC_KNOB_ID_04.value, 0x0)
            self.fsp_rpc.prc_knob_check_and_write(PrcKnob.PRC_KNOB_ID_22.value, 0x0)

        self.fsp_rpc.prc_knob_check_and_write(PrcKnob.PRC_KNOB_ID_BAR0_DECOUPLER.value, bar0_decoupler_val)
        self.fsp_rpc.prc_knob_check_and_write(PrcKnob.PRC_KNOB_ID_CCD.value, cc_dev_mode)
        self.fsp_rpc.prc_knob_check_and_write(PrcKnob.PRC_KNOB_ID_CCM.value, cc_mode)

    def query_cc_settings(self):
        assert self.is_cc_query_supported

        self._init_fsp_rpc()

        knobs = [
            ("enable", PrcKnob.PRC_KNOB_ID_CCM.value),
            ("enable-devtools", PrcKnob.PRC_KNOB_ID_CCD.value),

            ("enable-allow-inband-control", PrcKnob.PRC_KNOB_ID_CCM_ALLOW_INB.value),
            ("enable-devtools-allow-inband-control", PrcKnob.PRC_KNOB_ID_CCD_ALLOW_INB.value),
        ]

        knob_state = []

        for name, knob_id in knobs:
            knob_value = self.fsp_rpc.prc_knob_read(knob_id)
            knob_state.append((name, knob_value))

        return knob_state

    def query_prc_knobs(self):
        assert self.has_fsp

        self._init_fsp_rpc()

        knob_state = []

        for knob in PrcKnob:
            knob_value = self.fsp_rpc.prc_knob_read(knob.value)
            knob_state.append((knob.name, knob_value))

        return knob_state
    def wait_for_boot(self):
        assert self.is_turing_plus
        if self.is_hopper_plus:
            try:
                self.poll_register("boot_complete", 0x200bc, 0xff, 5)
            except GpuError as err:
                _, _, tb = sys.exc_info()
                debug("{} boot not done 0x{:x} = 0x{:x}".format(self, 0x200bc, self.read(0x200bc)))
                for offset in range(0, 4*4, 4):
                    debug_offset = 0x8f0320 + offset
                    debug(" 0x{:x} = 0x{:x}".format(debug_offset, self.read(debug_offset)))
                traceback.print_tb(tb)
                raise
        else:
            self.poll_register("boot_complete", 0x118234, 0x3ff, 5)
    def _is_read_good(self, reg, data):
        return data >> 16 != 0xbadf

    def read_bad_ok(self, reg):
        data = self.bar0.read32(reg)
        return data

    def check_read(self, reg):
        data = self.bar0.read32(reg)
        return self._is_read_good(reg, data)

    def read(self, reg):
        data = self.bar0.read32(reg)
        if not self._is_read_good(reg, data):
            raise GpuError("gpu %s reg %s = %s, bad?" % (self, hex(reg), hex(data)))
        return data

    def read_bar1(self, offset):
        return self.bar1.read32(offset)

    def write_bar1(self, offset, data):
        return self.bar1.write32(offset, data)
    # Init priv ring (internal bus)
    def init_priv_ring(self):
        self.write(0x12004c, 0x4)
        self.write(0x122204, 0x2)
    def flr_resettable_scratch(self):
        if self.is_volta_plus:
            return self.vbios_scratch_register(22)
        else:
            return self.vbios_scratch_register(15)

    def sbr_resettable_scratch(self):
        if self.is_hopper_plus:
            return 0x91288
        if self.is_ampere_plus:
            return 0x88e10
        return self.flr_resettable_scratch()
    def __str__(self):
        return "GPU %s %s %s BAR0 0x%x" % (self.bdf, self.name, hex(self.device), self.bar0_addr)

    def __eq__(self, other):
        return self.bar0_addr == other.bar0_addr
def print_topo_indent(root, indent):
    if root.is_hidden():
        indent = indent - 1
    else:
        print(" " * indent, root)
    for c in root.children:
        print_topo_indent(c, indent + 1)

def print_topo():
    print("Topo:")
    for c in DEVICES:
        dev = DEVICES[c]
        if dev.is_root():
            print_topo_indent(dev, 1)
    sys.stdout.flush()
def create_args():
    argp = optparse.OptionParser(usage="usage: %prog [options]")
    argp.add_option("--gpu", type="int", default=-1)
    argp.add_option("--gpu-bdf", help="Select a single GPU by providing a substring of the BDF, e.g. '01:00'.")
    argp.add_option("--gpu-name", help="Select a single GPU by providing a substring of the GPU name, e.g. 'T4'. If multiple GPUs match, the first one will be used.")
    argp.add_option("--no-gpu", action='store_true', help="Do not use any of the GPUs; commands requiring one will not work.")
    argp.add_option("--log", type="choice", choices=['debug', 'info', 'warning', 'error', 'critical'], default='info')
    argp.add_option("--reset-with-os", action='store_true', default=False,
                      help="Reset with OS through /sys/.../reset")
    argp.add_option("--query-cc-mode", action='store_true', default=False,
                      help="Query the current Confidential Computing (CC) mode of the GPU.")
    argp.add_option("--query-cc-settings", action='store_true', default=False,
                      help="Query the Confidential Computing (CC) settings of the GPU."
                      "This prints the lower level setting knobs that will take effect upon GPU reset.")
    argp.add_option("--set-cc-mode", type='choice', choices=["off", "on", "devtools"],
                      help="Configure Confidentail Computing (CC) mode. The choices are off (disabled), on (enabled) or devtools (enabled in DevTools mode)."
                      "The GPU needs to be reset to make the selected mode active. See --reset-after-cc-mode-switch for one way of doing it.")
    argp.add_option("--reset-after-cc-mode-switch", action='store_true', default=False,
                    help="Reset the GPU after switching CC mode such that it is activated immediately.")
    return argp


# Called instead of main() when imported as a library rather than run as a
# command.
def init():
    global opts

    argp = create_args()
    (opts, _) = argp.parse_args([])

def main():
    # Replace 5678 with the desired port number
	 #debugpy.listen(('localhost', 5678))
    #print("Waiting for debugger to attach...")
    #debugpy.wait_for_client()

    print("NVIDIA GPU Tools version {0}".format(VERSION))
    sys.stdout.flush()

    global opts

    argp = create_args()
    (opts, args) = argp.parse_args()

    if len(args) != 0:
        print("ERROR: Exactly zero positional argument expected.")
        argp.print_usage()
        sys.exit(1)
    logging.basicConfig(level=getattr(logging, opts.log.upper()),
                        format='%(asctime)s.%(msecs)03d %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d,%H:%M:%S')   
    if opts.gpu_bdf is not None:
        gpus, other = find_gpus(opts.gpu_bdf)
        if len(gpus) == 0:
            error("Matching for {0} found nothing".format(opts.gpu_bdf))
            sys.exit(1)
        elif len(gpus) > 1:
            error("Matching for {0} found more than one GPU {1}".format(opts.gpu_bdf, ", ".join([str(g) for g in gpus])))
            sys.exit(1)
        else:
            gpu = gpus[0]
    elif opts.gpu_name is not None:
        gpus, other = find_gpus()
        gpus = [g for g in gpus if opts.gpu_name in g.name]
        if len(gpus) == 0:
            error("Matching for {0} found nothing".format(opts.gpu_name))
            sys.exit(1)
        gpu = gpus[0]
    else:
        gpus, other = find_gpus()
        print("GPUs:")
        for i, g in enumerate(gpus):
            print(" ", i, g)
        print("Other:")
        for i, o in enumerate(other):
            print(" ", i, o)
        sys.stdout.flush()
        if opts.gpu == -1:
            info("No GPU specified, select GPU with --gpu, --gpu-bdf, or --gpu-name")
            return 0

        if opts.gpu >= len(gpus):
            raise ValueError("GPU index out of bounds")
        gpu = gpus[opts.gpu]

    if gpu:
        print_topo()
        info("Selected %s", gpu)
        if gpu.is_gpu() and gpu.is_hopper_plus:
            cc_mode = gpu.query_cc_mode()
            if cc_mode != "off":
                warning(f"{gpu} has CC mode {cc_mode}, some functionality may not work")
    if opts.reset_with_os:
        gpu.sysfs_reset()
    if opts.query_cc_settings:
        if not gpu.is_gpu() or not gpu.is_cc_query_supported:
            error(f"Querying CC settings is not supported on {gpu}")
            sys.exit(1)

        cc_settings = gpu.query_cc_settings()
        info(f"{gpu} CC settings:")
        for name, value in cc_settings:
            info(f"  {name} = {value}")
    if opts.set_cc_mode:
        if not gpu.is_gpu() or not gpu.is_cc_query_supported:
            error(f"Configuring CC not supported on {gpu}")
            sys.exit(1)

        gpu.set_cc_mode(opts.set_cc_mode)
        info(f"{gpu} CC mode set to {opts.set_cc_mode}. It will be active after GPU reset.")
        if opts.reset_after_cc_mode_switch:
            gpu.reset_with_os()
            new_mode = gpu.query_cc_mode()
            if new_mode != opts.set_cc_mode:
                raise GpuError(f"{gpu} failed to switch to CC mode {opts.set_cc_mode}, current mode is {new_mode}.")
            info(f"{gpu} was reset to apply the new CC mode.")

    if opts.query_cc_mode:
        if not gpu.is_gpu() or not gpu.is_cc_query_supported:
            error(f"Querying CC mode is not supported on {gpu}")
            sys.exit(1)

        cc_mode = gpu.query_cc_mode()
        info(f"{gpu} CC mode is {cc_mode}")
if __name__ == "__main__":
    main()
else:
    init()
