"""
QNetra Binary Scanner — Binary Format Detector

Identifies the format of a binary file using magic bytes and basic header inspection.
This is the first step in the binary scanning pipeline — format determines which
inspection strategies are available.

Supported formats:
  - ELF (Linux/Unix): symbol table, import/export analysis via lief
  - PE (Windows): import table, export table analysis via lief
  - Mach-O (macOS): basic detection only (not fully analyzed in Phase 1)
  - Archives (.a, .lib): detected but not analyzed
  - Unknown: falls back to string extraction only
"""

from __future__ import annotations

import logging
import struct
from pathlib import Path

from scanners.framework.models import BinaryFormat

logger = logging.getLogger(__name__)

# Magic byte constants
_ELF_MAGIC = b"\x7fELF"
_PE_MAGIC = b"MZ"
_MACHO_MAGIC_LE = b"\xcf\xfa\xed\xfe"
_MACHO_MAGIC_BE = b"\xce\xfa\xed\xfe"
_MACHO_FAT_LE = b"\xca\xfe\xba\xbe"
_AR_MAGIC = b"!<arch>"
_JAVA_CLASS_MAGIC = b"\xca\xfe\xba\xbe"

# Number of header bytes to read
_HEADER_SIZE = 16


def detect_format(path: Path) -> BinaryFormat:
    """
    Identify the binary format of a file using magic byte inspection.

    Args:
        path: Path to the binary file.

    Returns:
        BinaryFormat enum value.
    """
    try:
        with open(path, "rb") as fh:
            header = fh.read(_HEADER_SIZE)
    except (OSError, PermissionError) as e:
        logger.warning("Cannot read binary header for %s: %s", path, e)
        return BinaryFormat.UNKNOWN

    if not header:
        return BinaryFormat.UNKNOWN

    # ELF
    if header[:4] == _ELF_MAGIC:
        return BinaryFormat.ELF

    # PE (MZ header — also covers DOS executables that are PE-wrapped)
    if header[:2] == _PE_MAGIC:
        return BinaryFormat.PE

    # Mach-O (both LE and BE, and fat binary — note CAFEBABE is also Java class)
    if header[:4] in (_MACHO_MAGIC_LE, _MACHO_MAGIC_BE):
        return BinaryFormat.MACHO
    if header[:4] == _MACHO_FAT_LE:
        # Distinguish fat Mach-O from Java .class by architecture count field
        # Java class files have magic 0xCAFEBABE followed by minor_version (2 bytes) + major_version (2 bytes)
        # Fat Mach-O has nfat_arch as count — if it looks like a version number it's Java
        try:
            nfat_arch = struct.unpack(">I", header[4:8])[0]
            if nfat_arch < 20:  # Fat Mach-O typically has 2-4 archs
                return BinaryFormat.MACHO
        except struct.error:
            pass

    # Static library archive
    if header[:7] == _AR_MAGIC:
        return BinaryFormat.ARCHIVE

    return BinaryFormat.UNKNOWN


def is_parseable_with_lief(fmt: BinaryFormat) -> bool:
    """Return True if lief can parse this binary format for symbol table inspection."""
    return fmt in (BinaryFormat.ELF, BinaryFormat.PE)


def get_format_description(fmt: BinaryFormat) -> str:
    descriptions = {
        BinaryFormat.ELF: "ELF (Linux/Unix executable or shared library)",
        BinaryFormat.PE: "PE (Windows Portable Executable or DLL)",
        BinaryFormat.MACHO: "Mach-O (macOS/iOS executable)",
        BinaryFormat.ARCHIVE: "Static library archive (.a or .lib)",
        BinaryFormat.UNKNOWN: "Unknown binary format",
    }
    return descriptions.get(fmt, "Unknown")
