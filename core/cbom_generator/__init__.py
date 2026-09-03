"""
QNetra CBOM Generator — CycloneDX 1.6 Cryptographic Bill of Materials Serializer
==================================================================================

Milestone 2.3: CycloneDX 1.6 CBOM Generation Layer

This package transforms canonical CryptoAsset objects into a fully conformant
CycloneDX 1.6 Cryptographic Bill of Materials (CBOM).

Architecture:
  CryptoAsset[] → mapper.py → models.py → serializer.py → CycloneDX 1.6 JSON
                                                    └→ validator.py (schema check)

Pipeline position:
  Discovery → Normalization → CryptoAsset → Classification → CBOM Generator

Design Constraints (per AGENTS.md and PROJECT_RULES.md):
  - CBOM generation is READ-ONLY with respect to CryptoAsset.
  - No scanning, normalization, classification, or risk scoring is performed here.
  - No fabrication of cryptographic parameters (no invented key sizes/curves).
  - Output is deterministic: same input → identical JSON output.
  - Evidence traceability is preserved through custom qnetra: namespaced properties.
  - CycloneDX schema version: 1.6 (ECMA-424, 1st Edition, April 2024).

Public API:
  from core.cbom_generator import CBOMSerializer, CBOMValidator

References:
  - CycloneDX 1.6 Specification: https://cyclonedx.org/docs/1.6/json/
  - CycloneDX CBOM Capability: https://cyclonedx.org/capabilities/cbom/
  - docs/06_API_AND_DATA_CONTRACTS.md Section 3
  - docs/04_MODULES.md (core.cbom_generator)
  - PROJECT_RULES.md RULE-005
"""

from core.cbom_generator.serializer import CBOMSerializer
from core.cbom_generator.validator import CBOMValidator

__all__ = [
    "CBOMSerializer",
    "CBOMValidator",
]
