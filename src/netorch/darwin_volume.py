"""Identifier of the volume that holds an open file or directory (Darwin only).

One bounded read in the caller's own process: ``fgetattrlist(2)`` with
``ATTR_VOL_UUID`` on a descriptor the caller already holds. No subprocess, no
second path lookup and no write. Request and reply are those of xnu at tag
``xnu-12377.121.6``: ``bsd/sys/attr.h`` (lines 48-50, 87-105, 465, 512, 521)
and ``getvolattrlist`` in ``bsd/vfs/vfs_attrlist.c`` (lines 991-1739).
"""

from __future__ import annotations

import ctypes
import errno
import os
import struct
import sys

ATTR_BIT_MAP_COUNT = 5
ATTR_CMN_RETURNED_ATTRS = 0x80000000
ATTR_VOL_UUID = 0x00040000
# getattrlist(2) asks for this bit with every other volume attribute.
ATTR_VOL_INFO = 0x80000000
# The length word reports what the kernel needed, so a short reply is visible.
FSOPT_REPORT_FULLSIZE = 0x00000004
# Every requested attribute is packed, valid or not, so the request alone fixes
# the reply layout. A volume without an identifier lacks the bit in the returned set.
FSOPT_PACK_INVAL_ATTRS = 0x00000008
OPTIONS = FSOPT_REPORT_FULLSIZE | FSOPT_PACK_INVAL_ATTRS
# struct attrlist: u_short bitmapcount, u_int16_t reserved, five 32-bit groups.
REQUEST = struct.pack(
    "=HHIIIII",
    ATTR_BIT_MAP_COUNT,
    0,
    ATTR_CMN_RETURNED_ATTRS,
    ATTR_VOL_INFO | ATTR_VOL_UUID,
    0,
    0,
    0,
)
# A 32-bit length, one attribute_set_t (five 32-bit groups) and one uuid_t.
REPLY_BYTES = 40


def decode_volume_uuid(reply: bytes) -> str:
    """Decode the one complete reply to ``REQUEST``; refuse everything else.

    The returned set has to carry the two requested bits and nothing of the
    directory, file or fork groups, which were not requested. Other bits of the
    common and volume groups are not inspected: the identifier is at one offset
    whatever the set names.
    """
    if len(reply) != REPLY_BYTES:
        raise ValueError("volume identity reply has the wrong size")
    length, common, volume, directory, file, fork = struct.unpack_from("=6I", reply)
    if (
        length != REPLY_BYTES
        or not common & ATTR_CMN_RETURNED_ATTRS
        or not volume & ATTR_VOL_UUID
        or directory
        or file
        or fork
    ):
        raise ValueError("volume identifier is truncated or not provided by this volume")
    raw = reply[24:40]
    if raw == bytes(16):
        raise ValueError("volume identifier is empty")
    text = raw.hex()
    return "-".join((text[0:8], text[8:12], text[12:16], text[16:20], text[20:32]))


def volume_uuid(fd: int) -> str:
    """Lower-case UUID of the volume that holds the object behind ``fd``.

    Raises ``OSError`` where the interface does not exist and when the call
    fails, and ``ValueError`` for a reply that ``decode_volume_uuid`` refuses.
    A caller treats either as "not verified", never as an identity.
    """
    if sys.platform != "darwin":
        raise OSError(errno.ENOTSUP, "volume identity needs the Darwin attribute interface")
    reply = ctypes.create_string_buffer(REPLY_BYTES)
    # int fgetattrlist(int, void *, void *, size_t, unsigned int) for LP64.
    function = ctypes.CDLL(None, use_errno=True).fgetattrlist
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    if function(fd, REQUEST, reply, REPLY_BYTES, OPTIONS) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return decode_volume_uuid(reply.raw)
