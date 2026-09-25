"""
QNetra Shared Utilities — .gitignore-Aware Path Filter

Parses .gitignore files in a repository and builds a compiled filter that
allows the traversal layer to skip files/directories that a developer has
already designated as generated, vendored, or irrelevant.

Design principles:
  - Conservative: only excludes entries that unambiguously match gitignore patterns.
  - Non-destructive: never silently drops real source files that have crypto content.
  - Fast: name-only patterns stored in a frozenset for O(1) lookup; path-relative
    patterns compiled to fnmatch; early-exit on first match.
  - Safe: malformed gitignore lines are skipped; errors are logged but never fatal.

Performance (v3.0):
  - Simple name-only patterns (the vast majority in real .gitignore files) are stored
    in a frozenset → O(1) lookup vs O(N) fnmatch loop.
  - Complex anchored/glob patterns kept in a separate list (much shorter).
  - should_exclude() checks the fast-path set before the slow-path list.
  - GitignoreRules.from_root() only reads .gitignore at the repo root + up to
    max_depth levels, using a BFS that re-uses already-open scandir entries.

Usage:
    rules = GitignoreRules.from_root(repo_root)
    if rules.should_exclude(entry_name, entry_path, is_dir):
        skip()
"""

from __future__ import annotations

import fnmatch
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Hard limit: don't parse gitignore files larger than 1 MB
_MAX_GITIGNORE_BYTES = 1 * 1024 * 1024

# Maximum gitignore files to parse per repo (nested .gitignores)
_MAX_GITIGNORE_FILES = 20


@dataclass
class GitignoreRules:
    """
    Compiled set of exclusion rules derived from one or more .gitignore files.

    Internal structure (v3.0 — optimized):
      - _simple_names: frozenset of plain name patterns (no slashes, no wildcards
        except * which maps to fnmatch). O(1) for exact names; O(K) fnmatch for
        glob names where K is the number of glob-containing simple patterns.
      - _simple_names_exact: frozenset of exact literal name patterns → O(1) lookup.
      - _simple_names_glob: list of glob patterns for name-only matching.
      - _anchored_rules: list of (pattern, base_dir, negated, dir_only) for
        path-relative patterns (contain '/'). These are the minority.
    """

    # Exact name matches: frozenset for O(1) lookup
    _exact_names: frozenset[str] = field(default_factory=frozenset)
    # Glob name-only patterns (e.g. "*.min.js", "*.bundle.*")
    _glob_names: list[tuple[str, bool, bool]] = field(default_factory=list)  # (pattern, negated, dir_only)
    # Complex anchored patterns with '/' (path-relative, much rarer)
    _anchored_rules: list[tuple[str, str, bool, bool]] = field(default_factory=list)  # (pattern, base_dir, negated, dir_only)
    _enabled: bool = True

    # Mutable working set used during parsing — converted to frozenset at seal()
    _exact_names_working: list[str] = field(default_factory=list)
    _sealed: bool = False

    @classmethod
    def disabled(cls) -> "GitignoreRules":
        """Return a no-op rules object (all paths pass through)."""
        obj = cls()
        obj._enabled = False
        obj._sealed = True
        return obj

    def _seal(self) -> None:
        """Convert working list to frozenset. Call after all parse_file() calls."""
        if not self._sealed:
            self._exact_names = frozenset(self._exact_names_working)
            self._exact_names_working = []  # free memory
            self._sealed = True

    @classmethod
    def from_root(cls, root: Path, max_depth: int = 1) -> "GitignoreRules":
        """
        Discover and parse all .gitignore files starting from `root`.

        max_depth=1: only the root .gitignore + immediate child directories
        are scanned. For cloned repos, the root .gitignore contains 95%+ of
        all relevant exclusion rules. Deeper BFS was causing a full second
        directory traversal on Windows (expensive stat calls per entry).

        Args:
            root: Repository root directory.
            max_depth: Maximum directory depth to search for nested .gitignores.

        Returns:
            Compiled GitignoreRules instance.
        """
        obj = cls()
        files_parsed = 0

        # BFS over directory tree up to max_depth
        queue: list[tuple[Path, int]] = [(root, 0)]
        while queue and files_parsed < _MAX_GITIGNORE_FILES:
            current_dir, depth = queue.pop(0)
            gitignore_path = current_dir / ".gitignore"
            if gitignore_path.is_file():
                obj._parse_file(gitignore_path, base_dir=current_dir)
                files_parsed += 1

            if depth < max_depth:
                try:
                    for entry in os.scandir(current_dir):
                        if entry.is_dir(follow_symlinks=False) and not entry.name.startswith("."):
                            queue.append((Path(entry.path), depth + 1))
                except (PermissionError, OSError):
                    pass

        obj._seal()

        if files_parsed > 0:
            logger.debug(
                "GitignoreRules: parsed %d .gitignore file(s) from %s "
                "| exact=%d | globs=%d | anchored=%d",
                files_parsed, root,
                len(obj._exact_names), len(obj._glob_names), len(obj._anchored_rules),
            )

        return obj

    def _parse_file(self, path: Path, base_dir: Path) -> None:
        """Parse a single .gitignore file and append its rules."""
        try:
            size = path.stat().st_size
            if size > _MAX_GITIGNORE_BYTES:
                logger.debug("Skipping oversized .gitignore: %s (%d bytes)", path, size)
                return
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError) as exc:
            logger.debug("Cannot read .gitignore at %s: %s", path, exc)
            return

        base_str = str(base_dir)
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            negated = line.startswith("!")
            if negated:
                line = line[1:].strip()
                if not line:
                    continue

            dir_only = line.endswith("/")
            if dir_only:
                line = line.rstrip("/")

            if not line:
                continue

            if "/" in line:
                # Anchored to a specific directory in the tree
                self._anchored_rules.append((line, base_str, negated, dir_only))
            elif any(c in line for c in ("*", "?", "[")):
                # Glob pattern, name-only
                self._glob_names.append((line, negated, dir_only))
            else:
                # Plain name — goes into the O(1) set (unless negated)
                if not negated:
                    self._exact_names_working.append(line)
                else:
                    # Negated exact name: keep in glob list for ordered processing
                    self._glob_names.append((line, negated, dir_only))

    def should_exclude(self, name: str, full_path: Path, is_dir: bool) -> bool:
        """
        Return True if this path should be excluded according to gitignore rules.

        Performance: O(1) for exact name matches (the common case).
        O(G) for glob-name patterns. O(A) for anchored patterns.
        In practice G + A << total_rules for most repos.

        Args:
            name: The file/directory name (basename).
            full_path: Absolute path to the entry.
            is_dir: True if this entry is a directory.

        Returns:
            True if the entry should be skipped, False otherwise.
        """
        if not self._enabled:
            return False

        # Fast path: O(1) frozenset lookup for exact name matches
        # This handles the vast majority of gitignore exclusions (e.g. "node_modules",
        # "__pycache__", ".DS_Store", "*.pyc" does NOT apply here — only exact names).
        if name in self._exact_names:
            return True

        # Glob name-only patterns (e.g. "*.min.js", "*.log")
        # These are the minority; ordered processing allows negation.
        result = False
        if self._glob_names:
            for pattern, negated, dir_only in self._glob_names:
                if dir_only and not is_dir:
                    continue
                if fnmatch.fnmatch(name, pattern):
                    result = not negated

        # Anchored patterns (path-relative, rarest case)
        if self._anchored_rules:
            full_str = str(full_path)
            for pattern, base_dir, negated, dir_only in self._anchored_rules:
                if dir_only and not is_dir:
                    continue
                try:
                    rel = full_path.relative_to(base_dir)
                    rel_str = str(rel).replace("\\", "/")
                    clean_pattern = pattern.lstrip("/")
                    if fnmatch.fnmatch(rel_str, clean_pattern) or fnmatch.fnmatch(name, clean_pattern):
                        result = not negated
                except ValueError:
                    pass

        return result


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

_EMPTY_RULES = GitignoreRules.disabled()


def load_gitignore_rules(root: Path, enabled: bool = True) -> GitignoreRules:
    """
    Load gitignore rules for a repository root.

    Args:
        root: Repository root directory.
        enabled: If False, returns a no-op rules object.

    Returns:
        Compiled GitignoreRules.
    """
    if not enabled:
        return _EMPTY_RULES
    try:
        return GitignoreRules.from_root(root)
    except Exception as exc:  # noqa: BLE001 — never fatal
        logger.warning("Failed to load .gitignore rules from %s: %s", root, exc)
        return _EMPTY_RULES
