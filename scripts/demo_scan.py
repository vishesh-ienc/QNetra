"""
QNetra — Phase 1 Scanner Demonstration Script
==============================================
scripts/demo_scan.py

PURPOSE
-------
Orchestrates the existing Phase 1 Discovery Layer scanners against
controlled cryptographic test fixtures and serialises all RawFinding
objects to JSON so that raw_findings.md can be populated with REAL output.

CONSTRAINTS (per AGENTS.md and PROJECT_RULES.md)
------------------------------------------------
- Uses ONLY the existing scanner implementations from scanners/
- Does NOT implement normalization, CryptoAsset, CBOM, risk scoring,
  Mosca, or any Phase 2+ logic
- Passive / read-only scanning — no binaries are executed (RULE-008)
- No new scanner logic is implemented here; this is orchestration only

USAGE
-----
    python scripts/demo_scan.py

OUTPUT
------
- Console summary of findings per scanner/language
- raw_findings.md (root of repo) populated with actual scan results
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure repo root is on PYTHONPATH so scanners can be imported
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from scanners.framework.models import ScanTarget, TargetType, ScanOptions
from scanners.framework.router import ScannerRouter
from scanners.repository.scanner import RepositoryScanner
from scanners.container.scanner import ContainerScanner
from scanners.binary.scanner import BinaryScanner

logging.basicConfig(
    level=logging.WARNING,   # Suppress verbose scanner INFO during demo
    format="%(name)s | %(levelname)s | %(message)s",
)

# ---------------------------------------------------------------------------
# Fixture paths
# ---------------------------------------------------------------------------

SAMPLES = REPO_ROOT / "samples"

FIXTURES = {
    "repo_python":     SAMPLES / "repository_samples" / "python_crypto",
    "repo_javascript": SAMPLES / "repository_samples" / "javascript_crypto",
    "repo_java":       SAMPLES / "repository_samples" / "java_crypto",
    "repo_cpp":        SAMPLES / "repository_samples" / "cpp_crypto",
    "container":       SAMPLES / "container_sample",
    "binary":          SAMPLES / "binary_samples" / "sample_crypto_binary.elf",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding_to_dict(f) -> dict:
    """Convert a RawFinding to a plain dict for JSON serialisation."""
    return {
        "finding_id": f.finding_id,
        "scanner_name": f.scanner_name,
        "discovery_method": f.discovery_method.value,
        "raw_symbol": f.raw_symbol,
        "suspected_algorithm": f.suspected_algorithm,
        "artifact_category": f.artifact_category.value,
        "library_hint": f.library_hint,
        "key_size_hint": f.key_size_hint,
        "mode_hint": f.mode_hint,
        "curve_hint": f.curve_hint,
        "location": {
            "file_path": f.location.file_path,
            "start_line": f.location.start_line,
            "end_line": f.location.end_line,
            "snippet": f.location.snippet,
        },
        "confidence_score": round(f.confidence_score, 4),
        "confidence_level": f.confidence_level.value,
        "confidence_rationale": f.confidence_rationale,
        "binary_format": f.binary_format.value if f.binary_format else None,
        "symbol_name": f.symbol_name,
    }


def _run_repo_scan(label: str, path: Path) -> dict:
    """Run RepositoryScanner against a single-language directory."""
    print(f"  Scanning {label}: {path}")
    target = ScanTarget(
        path=str(path),
        target_type=TargetType.REPOSITORY,
        name=label,
        options=ScanOptions(),
    )
    scanner = RepositoryScanner()
    result = scanner.scan(target)
    findings = [_finding_to_dict(f) for f in result.findings]
    print(f"    -> {len(findings)} finding(s)  |  status={result.status.value}")
    return {
        "label": label,
        "path": str(path),
        "status": result.status.value,
        "warnings": result.warnings,
        "errors": result.errors,
        "findings_count": len(findings),
        "findings": findings,
    }


def _run_container_scan(path: Path) -> dict:
    """Run ContainerScanner against the synthetic container fixture."""
    print(f"  Scanning container filesystem: {path}")
    target = ScanTarget(
        path=str(path),
        target_type=TargetType.CONTAINER_FS,
        name="sample-container",
        options=ScanOptions(),
        metadata={"image_reference": "qnetra-demo/sample-container:latest"},
    )
    scanner = ContainerScanner()
    result = scanner.scan(target)
    findings = [_finding_to_dict(f) for f in result.findings]
    print(f"    -> {len(findings)} finding(s)  |  status={result.status.value}")
    return {
        "label": "container",
        "path": str(path),
        "status": result.status.value,
        "warnings": result.warnings,
        "errors": result.errors,
        "findings_count": len(findings),
        "findings": findings,
    }


def _run_binary_scan(path: Path) -> dict:
    """Run BinaryScanner against the synthetic ELF fixture."""
    print(f"  Scanning binary: {path}")
    target = ScanTarget(
        path=str(path),
        target_type=TargetType.BINARY,
        name="sample_crypto_binary.elf",
        options=ScanOptions(),
    )
    scanner = BinaryScanner()
    result = scanner.scan(target)
    findings = [_finding_to_dict(f) for f in result.findings]
    print(f"    -> {len(findings)} finding(s)  |  status={result.status.value}")
    return {
        "label": "binary",
        "path": str(path),
        "status": result.status.value,
        "warnings": result.warnings,
        "errors": result.errors,
        "findings_count": len(findings),
        "findings": findings,
    }


def _run_router_demo(path: Path, target_type: TargetType, label: str) -> dict:
    """Demonstrate ScannerRouter dispatch."""
    router = ScannerRouter.create_default()
    target = ScanTarget(
        path=str(path),
        target_type=target_type,
        name=label,
    )
    result = router.route(target)
    return {
        "routed_to": result.scanner_name,
        "resolved_type": target_type.value,
        "findings_count": len(result.findings),
        "status": result.status.value,
    }


# ---------------------------------------------------------------------------
# Markdown Generation
# ---------------------------------------------------------------------------

def _format_finding_block(idx: int, f: dict) -> str:
    loc = f["location"]
    lines = [
        f"#### Finding #{idx}",
        "",
        f"| Field | Value |",
        f"| :--- | :--- |",
        f"| **Algorithm** | `{f['suspected_algorithm'] or 'N/A'}` |",
        f"| **Category** | `{f['artifact_category']}` |",
        f"| **Method** | `{f['discovery_method']}` |",
        f"| **Raw Symbol** | `{f['raw_symbol'][:120]}` |",
        f"| **Library Hint** | `{f['library_hint'] or 'N/A'}` |",
        f"| **Key Size** | `{f['key_size_hint'] or 'N/A'}` bits |",
        f"| **Mode** | `{f['mode_hint'] or 'N/A'}` |",
        f"| **Curve** | `{f['curve_hint'] or 'N/A'}` |",
        f"| **File** | `{loc['file_path']}` |",
        f"| **Lines** | `{loc['start_line']} – {loc['end_line']}` |",
        f"| **Binary Format** | `{f['binary_format'] or 'N/A'}` |",
        f"| **Symbol Name** | `{f['symbol_name'] or 'N/A'}` |",
        f"| **Confidence Score** | `{f['confidence_score']}` |",
        f"| **Confidence Level** | `{f['confidence_level']}` |",
        f"| **Confidence Rationale** | {f['confidence_rationale']} |",
    ]
    if loc["snippet"]:
        lines += ["", "```", loc["snippet"][:300], "```"]
    lines.append("")
    return "\n".join(lines)


def generate_markdown(
    repo_results: list[dict],
    container_result: dict,
    binary_result: dict,
    router_demo: dict,
    scan_timestamp: str,
) -> str:
    """Generate the complete raw_findings.md content from actual scan results."""

    py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    platform = sys.platform

    # Summary table data
    all_results = repo_results + [container_result, binary_result]
    summary_rows = []
    for r in all_results:
        label = r["label"]
        if label.startswith("repo_"):
            scanner = "Repository"
            target_label = label.replace("repo_", "").capitalize()
        elif label == "container":
            scanner = "Container"
            target_label = "Sample Container FS"
        else:
            scanner = "Binary"
            target_label = "sample_crypto_binary.elf (ELF)"
        methods = ", ".join(sorted(set(
            f["discovery_method"] for f in r["findings"]
        ))) if r["findings"] else "N/A"
        summary_rows.append(
            f"| {scanner} | {target_label} | {r['findings_count']} | {methods} |"
        )

    total_findings = sum(r["findings_count"] for r in all_results)

    # Build markdown sections
    sections = []

    sections.append(f"""# QNetra — Raw Findings Demonstration

> **Generated:** {scan_timestamp}  
> **Purpose:** Demonstrates the Phase 1 Cryptographic Discovery Layer by scanning controlled cryptographic test fixtures and recording the actual `RawFinding` objects returned by QNetra's real scanners.

> [!IMPORTANT]
> **This is discovery output only.** No normalization, CBOM generation, quantum risk scoring, Mosca analysis, or PQC recommendation has been applied. This is strictly Phase 1 output — raw cryptographic evidence as discovered.

---

## 1. Purpose

This document records the actual `RawFinding` objects produced by the QNetra Phase 1 Discovery Layer when run against controlled, synthetic cryptographic test fixtures. Every value shown was generated by the real scanner code — no results have been manually invented or edited.

The scanners answer a single question per finding:

> **"What cryptographic evidence did we discover, where, and how confident are we?"**

They do **NOT** yet answer:

> **"What is the normalized cryptographic asset, its quantum risk score, or its PQC replacement?"**

That is Phase 2 (Normalization → CryptoAsset → CBOM → Risk → Mosca).

---

## 2. Test Environment

| Property | Value |
| :--- | :--- |
| **Scan Date** | {scan_timestamp} |
| **Operating System** | {platform} |
| **Python Version** | {py_version} |
| **QNetra Scanner Version** | v1.0.0 (Phase 1 Discovery Layer) |
| **RawFinding Contract Version** | v1.1.0 |
| **Python Sample Fixture** | `samples/repository_samples/python_crypto/` |
| **JavaScript Sample Fixture** | `samples/repository_samples/javascript_crypto/` |
| **Java Sample Fixture** | `samples/repository_samples/java_crypto/` |
| **C/C++ Sample Fixture** | `samples/repository_samples/cpp_crypto/` |
| **Container FS Fixture** | `samples/container_sample/` |
| **Binary Fixture** | `samples/binary_samples/sample_crypto_binary.elf` |

---

## 3. Repository Scanner Results
""")

    for r in repo_results:
        lang = r["label"].replace("repo_", "").upper()
        sections.append(f"""### 3.{repo_results.index(r)+1}. {lang}

**Fixture:** `{r['path']}`  
**Scanner:** `RepositoryScanner`  
**Status:** `{r['status']}`  
**Findings:** {r['findings_count']}
""")
        if r["warnings"]:
            sections.append("**Warnings:**\n" + "\n".join(f"- {w}" for w in r["warnings"]) + "\n")
        if r["errors"]:
            sections.append("**Errors:**\n" + "\n".join(f"- {e}" for e in r["errors"]) + "\n")
        if r["findings"]:
            for idx, f in enumerate(r["findings"], 1):
                sections.append(_format_finding_block(idx, f))
        else:
            sections.append("> No findings produced from this fixture.\n")
        sections.append("---\n")

    sections.append("""## 4. Container Scanner Results

""")
    r = container_result
    sections.append(f"""**Fixture:** `{r['path']}`  
**Scanner:** `ContainerScanner`  
**Status:** `{r['status']}`  
**Findings:** {r['findings_count']}
""")
    if r["warnings"]:
        sections.append("**Warnings:**\n" + "\n".join(f"- {w}" for w in r["warnings"]) + "\n")
    if r["errors"]:
        sections.append("**Errors:**\n" + "\n".join(f"- {e}" for e in r["errors"]) + "\n")
    if r["findings"]:
        for idx, f in enumerate(r["findings"], 1):
            sections.append(_format_finding_block(idx, f))
    else:
        sections.append("> No findings produced from the container fixture.\n")
    sections.append("---\n")

    sections.append("""## 5. Binary Scanner Results

""")
    r = binary_result
    sections.append(f"""**Fixture:** `{r['path']}`  
**Scanner:** `BinaryScanner`  
**Status:** `{r['status']}`  
**Findings:** {r['findings_count']}
""")
    if r["warnings"]:
        sections.append("**Warnings:**\n" + "\n".join(f"- {w}" for w in r["warnings"]) + "\n")
    if r["errors"]:
        sections.append("**Errors:**\n" + "\n".join(f"- {e}" for e in r["errors"]) + "\n")
    if r["findings"]:
        for idx, f in enumerate(r["findings"], 1):
            sections.append(_format_finding_block(idx, f))
    else:
        sections.append("> No findings produced from the binary fixture.\n")
    sections.append("---\n")

    sections.append(f"""## 6. ScannerRouter Dispatch Demonstration

The `ScannerRouter` automatically routes a `ScanTarget` to the correct scanner.

| Property | Value |
| :--- | :--- |
| **Target Path** | `{FIXTURES["repo_python"]}` |
| **Resolved Type** | `{router_demo["resolved_type"]}` |
| **Routed To** | `{router_demo["routed_to"]}` |
| **Status** | `{router_demo["status"]}` |
| **Findings** | {router_demo["findings_count"]} |

---

## 7. Scanner Summary

| Scanner | Target | Findings | Detection Methods |
| :--- | :--- | ---: | :--- |
""")
    sections.append("\n".join(summary_rows))
    sections.append(f"\n| **TOTAL** | **All fixtures** | **{total_findings}** | Multiple |\n")

    sections.append("""
---

## 8. Representative Finding Explanations

This section selects one finding per scanner type and explains what evidence triggered it.
""")

    # Pick one representative finding from each scanner
    for r in repo_results:
        if r["findings"]:
            f = r["findings"][0]
            lang = r["label"].replace("repo_", "").upper()
            sections.append(f"""### {lang} — `{f['suspected_algorithm'] or f['artifact_category']}`

**Evidence:** Scanner detected `{f['raw_symbol'][:100]}` in file `{f['location']['file_path']}` at line {f['location']['start_line']}.  
**Detection mechanism:** {f['discovery_method']} — {f['confidence_rationale']}

""")

    if container_result["findings"]:
        f = container_result["findings"][0]
        sections.append(f"""### Container — `{f['suspected_algorithm'] or f['artifact_category']}`

**Evidence:** `{f['raw_symbol'][:100]}` detected via {f['discovery_method']} inside the container filesystem.  
**Detection mechanism:** {f['confidence_rationale']}

""")

    if binary_result["findings"]:
        f = binary_result["findings"][0]
        sections.append(f"""### Binary — `{f['suspected_algorithm'] or f['artifact_category']}`

**Evidence:** `{f['raw_symbol'][:100]}` extracted from binary file via {f['discovery_method']}.  
**Detection mechanism:** {f['confidence_rationale']}

""")

    sections.append("""---

## 9. What This Demonstrates

```
Input Target (source file / container FS / compiled binary)
        ↓
ScanTarget envelope (path, target_type, ScanOptions)
        ↓
ScannerRouter → dispatches to appropriate BaseScanner subclass
        ↓
Scanner Pipeline (AST / regex / API match / string extract / symbol inspect)
        ↓
RawFinding[] — each finding records:
  WHAT:  suspected_algorithm, artifact_category, raw_symbol
  WHERE: location (file_path, start_line, snippet)
  HOW:   discovery_method, scanner_name
  WHY:   confidence_score, confidence_level, confidence_rationale
```

### The Discovery Layer currently answers:

> **"What cryptographic evidence did we discover, where, how, and how confident are we?"**

### The Discovery Layer does NOT yet answer:

> **"What is the canonical normalized cryptographic asset?"**  
> **"What is its quantum risk score?"**  
> **"What is the Mosca migration urgency?"**  
> **"What PQC algorithm should replace it?"**

Those questions are answered by Phase 2 (`core/normalization` → `CryptoAsset`) and Phase 3 (risk engine, Mosca engine, recommendation engine).

---

*Generated by `scripts/demo_scan.py` using real QNetra Phase 1 scanner output.*  
*All values are actual scanner output — no manual editing.*
""")

    return "\n".join(sections)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    scan_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print("=" * 65)
    print("QNetra Phase 1 — Scanner Demonstration")
    print(f"Timestamp: {scan_timestamp}")
    print("=" * 65)

    # --- Repository scans ---
    print("\n[1/3] Repository Scanner")
    repo_results = []
    for key in ["repo_python", "repo_javascript", "repo_java", "repo_cpp"]:
        path = FIXTURES[key]
        if path.exists():
            repo_results.append(_run_repo_scan(key, path))
        else:
            print(f"  SKIP {key}: fixture not found at {path}")

    # --- Container scan ---
    print("\n[2/3] Container Scanner")
    container_result = {}
    if FIXTURES["container"].exists():
        container_result = _run_container_scan(FIXTURES["container"])
    else:
        print(f"  SKIP container: fixture not found")
        container_result = {"label": "container", "path": str(FIXTURES["container"]),
                            "status": "SKIPPED", "warnings": [], "errors": [],
                            "findings_count": 0, "findings": []}

    # --- Binary scan ---
    print("\n[3/3] Binary Scanner")
    binary_result = {}
    if FIXTURES["binary"].exists():
        binary_result = _run_binary_scan(FIXTURES["binary"])
    else:
        print(f"  SKIP binary: fixture not found")
        binary_result = {"label": "binary", "path": str(FIXTURES["binary"]),
                         "status": "SKIPPED", "warnings": [], "errors": [],
                         "findings_count": 0, "findings": []}

    # --- Router demo ---
    print("\n[+] ScannerRouter dispatch demo")
    router_demo = _run_router_demo(
        FIXTURES["repo_python"], TargetType.REPOSITORY, "router-demo-python"
    )
    print(f"    -> Routed to: {router_demo['routed_to']}")

    # --- Total summary ---
    total = sum(r.get("findings_count", 0) for r in repo_results + [container_result, binary_result])
    print(f"\n{'='*65}")
    print(f"  Total findings across all scanners: {total}")
    print(f"{'='*65}")

    # --- Generate raw_findings.md ---
    print("\n[+] Generating raw_findings.md ...")
    md_content = generate_markdown(
        repo_results=repo_results,
        container_result=container_result,
        binary_result=binary_result,
        router_demo=router_demo,
        scan_timestamp=scan_timestamp,
    )
    output_path = REPO_ROOT / "raw_findings.md"
    output_path.write_text(md_content, encoding="utf-8")
    print(f"    Written: {output_path}  ({len(md_content):,} chars)")
    print("\nDone. Open raw_findings.md to review actual scanner output.")


if __name__ == "__main__":
    main()
