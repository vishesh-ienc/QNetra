"""
Acquisition and validation layer for public GitHub repositories.

Supports cloning public GitHub repositories via shallow git clones into a safe
temporary workspace. Validates URL structures, rejects private/inaccessible
repositories pre-flight, and prevents path traversal or shell injection attacks.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger("qnetra.backend.github")

# Strict regex matching: github.com/<owner>/<repo>
# Allowed characters in owner/repo: alphanumeric, hyphen, underscore, period.
# Owner/repo cannot start or end with hyphen or period, and cannot contain consecutive dots.
_GITHUB_PATH_RE = re.compile(
    r"^/(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38})/(?P<repo>[A-Za-z0-9_.-]+)$"
)


def normalize_github_url(raw_url: str) -> tuple[str, str, str]:
    """
    Validate and normalize a public GitHub repository URL.

    Accepts:
        - https://github.com/owner/repo
        - http://github.com/owner/repo (coerced to https)
        - github.com/owner/repo (coerced to https)
        - URLs with trailing .git or trailing slashes

    Rejects:
        - Non-github hostnames
        - URLs with authentication embedded (user:pass@)
        - Shell metacharacters or dangerous characters
        - Traversal or dot-dot path segments

    Returns:
        tuple[normalized_url, owner, repo]

    Raises:
        ValueError if the URL is invalid or malformed.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise ValueError("GitHub repository URL is required.")

    trimmed = raw_url.strip()

    # Reject dangerous characters
    if any(c in trimmed for c in ";&|`$<>\\\"'\n\r\t \x00"):
        raise ValueError("Repository URL contains invalid or disallowed characters.")

    # Prepend https scheme if missing
    if not re.match(r"^https?://", trimmed, re.IGNORECASE):
        trimmed = f"https://{trimmed}"

    try:
        parsed = urlparse(trimmed)
    except Exception as exc:
        raise ValueError(f"Failed to parse repository URL: {exc}") from exc

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Repository URL must use HTTP or HTTPS protocol.")

    hostname = (parsed.hostname or "").lower()
    if hostname not in ("github.com", "www.github.com"):
        raise ValueError(
            f"Only public repositories on github.com are supported (received '{hostname}')."
        )

    if parsed.username or parsed.password:
        raise ValueError("Embedded credentials in repository URLs are not permitted.")

    # Normalize path
    path = parsed.path.rstrip("/")
    if path.endswith(".git"):
        path = path[:-4]

    match = _GITHUB_PATH_RE.match(path)
    if not match:
        raise ValueError(
            "Invalid GitHub repository path. Expected format: https://github.com/<owner>/<repo>"
        )

    owner = match.group("owner")
    repo = match.group("repo")

    # Reject illegal repo names like "." or ".."
    if repo in (".", "..") or repo.startswith("-"):
        raise ValueError(f"Invalid repository name '{repo}'.")

    normalized_url = f"https://github.com/{owner}/{repo}"
    return normalized_url, owner, repo


def verify_public_repo(normalized_url: str, timeout: int = 15) -> tuple[bool, str]:
    """
    Perform a fast pre-flight verification using `git ls-remote` without downloading.

    Ensures the repository exists and is publicly accessible without prompting for credentials.
    Returns:
        (True, "") if the repository is accessible.
        (False, error_message) if the repository is private, non-existent, or git failed.
    """
    env = {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "echo",
    }

    cmd = ["git", "ls-remote", "--exit-code", "-h", normalized_url]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            env=env,
            check=False,
        )
        if proc.returncode == 0:
            return True, ""

        err = proc.stderr.strip()
        if "Authentication failed" in err or "could not read Username" in err:
            return (
                False,
                "This GitHub repository could not be found or is not publicly accessible (repository is private or requires authentication).",
            )
        if "Repository not found" in err or "not found" in err.lower():
            return (
                False,
                "This GitHub repository could not be found or is not publicly accessible (Repository not found).",
            )
        if "could not resolve host" in err.lower() or "unable to access" in err.lower():
            return (
                False,
                "QNetra could not reach GitHub. Check the repository URL and try again.",
            )

        return (
            False,
            f"This GitHub repository could not be found or is not publicly accessible: {err or f'git exited with code {proc.returncode}'}",
        )

    except subprocess.TimeoutExpired:
        return (
            False,
            f"This repository could not be scanned within the supported acquisition limits (Connection to GitHub timed out after {timeout} seconds).",
        )
    except FileNotFoundError:
        return False, "The 'git' command-line executable was not found on the server."
    except Exception as exc:
        return False, f"Unexpected error checking repository: {exc}"


def _remove_readonly(func, path, exc_info):
    """Clear the readonly bit and retry file removal (necessary for .git objects on Windows)."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


def safe_rmtree(path: Path) -> None:
    """Recursively remove a directory tree, handling Windows read-only files."""
    if not path.exists():
        return
    shutil.rmtree(path, onerror=_remove_readonly)


def acquire_github_repository(
    normalized_url: str,
    scan_id: str,
    timeout: int = 180,
) -> Path:
    """
    Clone a public GitHub repository into a temporary workspace directory.

    Performs a shallow clone (`--depth 1 --single-branch --no-tags`) to maximize speed
    and minimize network and disk overhead.
    Removes the `.git` directory after cloning to prevent arbitrary hook execution,
    save space, and keep the scanner focused on source code.

    Returns:
        Path to the root directory containing the cloned repository files.

    Raises:
        RuntimeError if cloning fails or times out.
    """
    temp_base = Path(tempfile.gettempdir()) / "qnetra_repos"
    temp_base.mkdir(parents=True, exist_ok=True)

    dest_dir = temp_base / scan_id
    if dest_dir.exists():
        safe_rmtree(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    env = {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "echo",
    }

    cmd = [
        "git",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
        normalized_url,
        str(dest_dir),
    ]

    logger.info("Acquiring public GitHub repository %s into %s", normalized_url, dest_dir)

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            env=env,
            check=False,
        )

        if proc.returncode != 0:
            err = proc.stderr.strip()
            safe_rmtree(dest_dir)
            raise RuntimeError(
                f"QNetra could not acquire this repository: Failed to clone repository: {err or f'git clone exited with code {proc.returncode}'}"
            )

        # Remove .git metadata directory
        git_dir = dest_dir / ".git"
        if git_dir.exists():
            safe_rmtree(git_dir)

        return dest_dir

    except subprocess.TimeoutExpired as exc:
        safe_rmtree(dest_dir)
        raise RuntimeError(
            f"This repository could not be scanned within the supported acquisition limits: Cloning repository timed out after {timeout} seconds."
        ) from exc
    except Exception:
        safe_rmtree(dest_dir)
        raise
