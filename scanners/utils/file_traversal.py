"""
QNetra Shared Utilities — File System Traversal

Provides a reusable, robust file traversal utility used by both the
RepositoryScanner and ContainerScanner. Handles:
  - Recursive directory walking
  - Exclusion pattern matching (glob-style)
  - File size limits
  - Permission error recovery
  - Scan statistics tracking
"""

from __future__ import annotations

import fnmatch
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger(__name__)


@dataclass
class TraversalStats:
    directories_visited: int = 0
    files_discovered: int = 0
    files_skipped_excluded: int = 0
    files_skipped_too_large: int = 0
    files_skipped_unreadable: int = 0
    errors: list[str] = field(default_factory=list)


def _matches_any_pattern(name: str, patterns: list[str]) -> bool:
    """Check if a file or directory name matches any exclusion glob pattern."""
    for pattern in patterns:
        if fnmatch.fnmatch(name, pattern):
            return True
        # Also check the pattern without wildcards as a simple substring
        if pattern == name:
            return True
    return False


def traverse_directory(
    root: Path,
    exclude_patterns: list[str],
    max_file_size_bytes: int = 10 * 1024 * 1024,
    follow_symlinks: bool = False,
    stats: Optional[TraversalStats] = None,
) -> Generator[Path, None, None]:
    """
    Recursively traverse a directory, yielding file paths that pass all filters.

    Args:
        root: Root directory to traverse.
        exclude_patterns: Glob-style patterns for directory/file names to skip.
        max_file_size_bytes: Skip files larger than this size.
        follow_symlinks: Whether to follow symbolic links.
        stats: Optional TraversalStats object to update during traversal.

    Yields:
        Absolute Path objects for each eligible file.
    """
    if stats is None:
        stats = TraversalStats()

    if not root.exists():
        stats.errors.append(f"Root path does not exist: {root}")
        return

    if not root.is_dir():
        stats.errors.append(f"Root path is not a directory: {root}")
        return

    try:
        entries = list(os.scandir(root))
    except PermissionError as e:
        stats.errors.append(f"Permission denied reading directory {root}: {e}")
        return
    except OSError as e:
        stats.errors.append(f"OS error reading directory {root}: {e}")
        return

    stats.directories_visited += 1

    for entry in entries:
        entry_path = Path(entry.path)
        entry_name = entry.name

        # Skip if name matches exclusion patterns
        if _matches_any_pattern(entry_name, exclude_patterns):
            logger.debug("Excluded: %s", entry_path)
            continue

        try:
            is_dir = entry.is_dir(follow_symlinks=follow_symlinks)
            is_file = entry.is_file(follow_symlinks=follow_symlinks)
        except OSError:
            stats.files_skipped_unreadable += 1
            continue

        if is_dir:
            # Recurse
            yield from traverse_directory(
                entry_path,
                exclude_patterns,
                max_file_size_bytes,
                follow_symlinks,
                stats,
            )

        elif is_file:
            stats.files_discovered += 1

            # Check file size
            try:
                file_size = entry.stat(follow_symlinks=follow_symlinks).st_size
                if file_size > max_file_size_bytes:
                    stats.files_skipped_too_large += 1
                    logger.debug(
                        "Skipping oversized file (%d bytes > %d limit): %s",
                        file_size, max_file_size_bytes, entry_path
                    )
                    continue
            except OSError:
                stats.files_skipped_unreadable += 1
                continue

            yield entry_path


def safe_read_text(path: Path, max_bytes: int = 5 * 1024 * 1024) -> tuple[str | None, str | None]:
    """
    Safely read a text file with encoding fallbacks.

    Args:
        path: File path to read.
        max_bytes: Maximum bytes to read (prevents runaway memory for large files).

    Returns:
        (content, None) on success, (None, error_message) on failure.
    """
    try:
        # Try UTF-8 first (most source code)
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read(max_bytes)
        return content, None
    except PermissionError as e:
        return None, f"Permission denied: {e}"
    except OSError as e:
        return None, f"OS error reading {path}: {e}"
    except Exception as e:
        return None, f"Unexpected error reading {path}: {type(e).__name__}: {e}"
