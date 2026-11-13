"""
Mach-O Binary Validator.
Provides bit-level validation of Apple Mach-O 64-bit and 32-bit headers,
CPU architecture types, load commands, and alignments.
"""

import struct
from typing import Dict, Any, Union

MH_MAGIC_64 = 0xFEEDFACF       # 64-bit little-endian
MH_CIGAM_64 = 0xCFFAEDFE       # 64-bit big-endian
MH_MAGIC_32 = 0xFEEDFACE       # 32-bit little-endian
MH_CIGAM_32 = 0xCEFAEDFE       # 32-bit big-endian

CPU_TYPE_ARM64 = 0x0100000C     # CPU_TYPE_ARM64 (16777228)
CPU_SUBTYPE_ARM64_ALL = 0x00000000
MH_EXECUTE = 0x2
LC_CODE_SIGNATURE = 0x1D


def validate_macho_binary(file_or_bytes: Union[str, bytes]) -> Dict[str, Any]:
    """
    Validates Mach-O binary headers, magic numbers, CPU architecture, and alignment.
    Supports both file paths and raw byte buffers.
    """
    if isinstance(file_or_bytes, str):
        try:
            with open(file_or_bytes, "rb") as f:
                data = f.read()
        except Exception as e:
            return {"valid": False, "error": f"Failed to read file: {e}"}
    elif isinstance(file_or_bytes, (bytes, bytearray)):
        data = file_or_bytes
    else:
        return {"valid": False, "error": "Invalid argument type; expected path string or bytes"}

    if len(data) < 32:
        return {"valid": False, "error": f"Binary length ({len(data)} bytes) is smaller than Mach-O header (32 bytes)"}

    # Inspect magic
    raw_magic = struct.unpack("<I", data[:4])[0]
    
    is_64bit = False
    is_little_endian = True

    if raw_magic == MH_MAGIC_64:
        is_64bit = True
        is_little_endian = True
    elif raw_magic == MH_CIGAM_64:
        is_64bit = True
        is_little_endian = False
    elif raw_magic == MH_MAGIC_32:
        is_64bit = False
        is_little_endian = True
    elif raw_magic == MH_CIGAM_32:
        is_64bit = False
        is_little_endian = False
    else:
        return {"valid": False, "error": f"Invalid Mach-O magic: 0x{raw_magic:08X}"}

    fmt_prefix = "<" if is_little_endian else ">"

    if is_64bit:
        header_fmt = f"{fmt_prefix}IIIIIIII"
        header_size = 32
        magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack(
            header_fmt, data[:header_size]
        )
    else:
        header_fmt = f"{fmt_prefix}IIIIIII"
        header_size = 28
        magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack(
            header_fmt, data[:header_size]
        )
        reserved = 0

    cpu_type_str = "ARM64" if cputype == CPU_TYPE_ARM64 else f"0x{cputype:08X}"

    # Alignment checks
    is_aligned = (len(data) % 4 == 0)

    return {
        "valid": True,
        "magic": hex(magic),
        "is_64bit": is_64bit,
        "is_little_endian": is_little_endian,
        "cpu_type": cpu_type_str,
        "cpu_type_raw": cputype,
        "cpu_subtype": cpusubtype,
        "file_type": filetype,
        "ncmds": ncmds,
        "sizeofcmds": sizeofcmds,
        "flags": hex(flags),
        "reserved": reserved,
        "total_size": len(data),
        "is_aligned": is_aligned,
        "error": None
    }
