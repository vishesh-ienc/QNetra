"""
QNetra Repository Scanner — Repository Traversal

Handles repository-specific file traversal with:
  - Language-aware file routing
  - Manifest file identification
  - Binary file exclusion
  - Statistics collection
"""

from __future__ import annotations

import logging
from pathlib import Path

from scanners.framework.models import ScanOptions, ScanStatistics
from scanners.utils.file_traversal import TraversalStats, traverse_directory
from scanners.utils.language_detector import Language, detect_language, is_source_language

logger = logging.getLogger(__name__)


class RepositoryTraversal:
    """
    Traverses a repository directory and classifies discovered files by language.
    Respects exclusion patterns and file size limits from ScanOptions.
    """

    def __init__(self, options: ScanOptions) -> None:
        self._options = options

    def collect_files(
        self,
        root: Path,
        stats: ScanStatistics,
    ) -> dict[Language, list[Path]]:
        """
        Walk the repository tree and return files grouped by detected language.

        Args:
            root: Repository root directory.
            stats: ScanStatistics to update during traversal.

        Returns:
            Dict mapping Language -> list of file paths.
        """
        files_by_language: dict[Language, list[Path]] = {}
        traversal_stats = TraversalStats()

        for file_path in traverse_directory(
            root=root,
            exclude_patterns=self._options.exclude_patterns,
            max_file_size_bytes=self._options.max_file_size_bytes,
            follow_symlinks=self._options.follow_symlinks,
            stats=traversal_stats,
        ):
            lang = detect_language(file_path)

            if lang == Language.BINARY:
                # Skip binary files in repository scanner — handled by BinaryScanner
                traversal_stats.files_skipped_excluded += 1
                continue

            if lang == Language.UNKNOWN:
                traversal_stats.files_skipped_excluded += 1
                continue

            if lang not in files_by_language:
                files_by_language[lang] = []
            files_by_language[lang].append(file_path)

        # Update ScanStatistics
        stats.directories_visited = traversal_stats.directories_visited
        stats.files_discovered = traversal_stats.files_discovered
        stats.files_skipped = (
            traversal_stats.files_skipped_excluded +
            traversal_stats.files_skipped_too_large
        )
        stats.files_errored = traversal_stats.files_skipped_unreadable

        total_classified = sum(len(v) for v in files_by_language.values())
        logger.info(
            "Repository traversal complete | dirs=%d | files_discovered=%d | classified=%d",
            traversal_stats.directories_visited,
            traversal_stats.files_discovered,
            total_classified,
        )

        return files_by_language
