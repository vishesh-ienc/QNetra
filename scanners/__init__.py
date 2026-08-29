"""
QNetra — Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)
Scanners Package

This package implements the QNetra Discovery Layer, consisting of:
  - Discovery Framework (models, base scanner contract, scanner router)
  - Shared Cryptographic Knowledge Registries
  - Shared Utilities (traversal, language detection, string extraction)
  - Repository / Source Code Scanner (Python AST, JS/Java/C++ pattern analysis)
  - Container Scanner (filesystem + package metadata inspection)
  - Binary Scanner (ELF/PE format, symbol table, string analysis)

Output: List[RawFinding] — evidence-rich discovery records for downstream normalization.

Phase: 1 — Cryptographic Discovery Layer
"""

__version__ = "1.0.0"
__author__ = "QNetra Team"
