"""
QNetra Repository Scanner — Language Analyzer Base

Defines the LanguageAnalyzer abstract base class that all language-specific
analyzers extend. Provides the common interface and shared utilities.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from scanners.framework.models import RawFinding


class LanguageAnalyzer(ABC):
    """
    Abstract base for language-specific cryptographic code analyzers.

    Each language analyzer receives source file content and returns
    a list of RawFinding objects representing discovered cryptographic indicators.

    Subclasses implement:
      - analyze(): Primary analysis entry point
      - _extract_imports(): Find library imports
      - _analyze_calls(): Identify cryptographic API calls
      - _apply_patterns(): Regex fallback pass
    """

    LANGUAGE_NAME: str = "unknown"

    @abstractmethod
    def analyze(self, file_path: Path, content: str) -> list[RawFinding]:
        """
        Analyze source file content for cryptographic indicators.

        MUST NOT raise exceptions for malformed input — return empty list instead.

        Args:
            file_path: Absolute path to the source file.
            content: Full text content of the source file.

        Returns:
            List of RawFinding objects (may be empty).
        """

    def _snippet(self, lines: list[str], line_idx: int, context: int = 2) -> str:
        """Extract a code snippet around a given line index with context lines."""
        start = max(0, line_idx - context)
        end = min(len(lines), line_idx + context + 1)
        return "\n".join(lines[start:end])

    def _truncate_snippet(self, snippet: str, max_length: int = 200) -> str:
        """Truncate a snippet to a maximum character length for storage."""
        if len(snippet) <= max_length:
            return snippet
        return snippet[:max_length] + "..."
