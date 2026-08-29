"""
QNetra Shared Utilities — Binary String Extraction

Extracts readable strings from binary files (similar to the Unix `strings` command).
Used by the BinaryScanner's string_analyzer for broad-spectrum indicator detection.

This is a pure Python implementation requiring no external tools — it reads bytes
directly and extracts sequences of printable ASCII characters above a minimum length.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Generator

logger = logging.getLogger(__name__)

# Minimum string length to be considered meaningful (avoids noise from short sequences)
_DEFAULT_MIN_LENGTH = 6

# Printable ASCII byte range: 0x20 (space) to 0x7E (~)
_PRINTABLE_LOW = 0x20
_PRINTABLE_HIGH = 0x7E

# Read chunk size for streaming large files
_CHUNK_SIZE = 64 * 1024  # 64 KB


def extract_strings(
    path: Path,
    min_length: int = _DEFAULT_MIN_LENGTH,
    max_strings: int = 50_000,
    max_bytes: int = 50 * 1024 * 1024,
) -> Generator[tuple[str, int], None, None]:
    """
    Extract printable ASCII strings from a binary file.

    Yields (string, byte_offset) tuples. Byte offset is approximate (chunk-relative).
    Stops after max_strings extractions or max_bytes read (safety limit for large files).

    Args:
        path: Binary file to read.
        min_length: Minimum consecutive printable characters to qualify as a string.
        max_strings: Maximum number of strings to extract.
        max_bytes: Maximum bytes to read from the file.

    Yields:
        (extracted_string, approximate_byte_offset) tuples.
    """
    total_bytes_read = 0
    strings_yielded = 0
    current_string: list[int] = []
    current_start_offset = 0
    absolute_offset = 0

    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(_CHUNK_SIZE)
                if not chunk:
                    break

                total_bytes_read += len(chunk)
                if total_bytes_read > max_bytes:
                    logger.debug("Reached max_bytes limit (%d) for %s", max_bytes, path)
                    break

                for i, byte in enumerate(chunk):
                    if _PRINTABLE_LOW <= byte <= _PRINTABLE_HIGH:
                        if not current_string:
                            current_start_offset = absolute_offset + i
                        current_string.append(byte)
                    else:
                        if len(current_string) >= min_length:
                            yield bytes(current_string).decode("ascii"), current_start_offset
                            strings_yielded += 1
                            if strings_yielded >= max_strings:
                                return
                        current_string = []

                absolute_offset += len(chunk)

        # Flush remaining string at EOF
        if len(current_string) >= min_length:
            yield bytes(current_string).decode("ascii"), current_start_offset

    except PermissionError:
        logger.warning("Permission denied reading binary: %s", path)
    except OSError as e:
        logger.warning("OS error reading binary %s: %s", path, e)


def extract_strings_list(
    path: Path,
    min_length: int = _DEFAULT_MIN_LENGTH,
    max_strings: int = 50_000,
    max_bytes: int = 50 * 1024 * 1024,
) -> list[tuple[str, int]]:
    """Convenience wrapper that collects all strings into a list."""
    return list(extract_strings(path, min_length, max_strings, max_bytes))
