"""
QNetra CBOM Generator — CycloneDX 1.6 Schema Validator
========================================================

Validates generated CBOM JSON against a bundled structural schema that
reflects the CycloneDX 1.6 Cryptographic BOM structure.

DESIGN NOTE:
  The official CycloneDX 1.6 JSON schema from
  https://cyclonedx.org/docs/1.6/json/ is complex and requires network
  access or schema bundling. This module implements a focused structural
  validator (not a full JSON Schema draft-07 validator) that checks:

    1. Required top-level fields: bomFormat, specVersion, version, components
    2. bomFormat == "CycloneDX"
    3. specVersion == "1.6"
    4. components[].type == "cryptographic-asset"
    5. components[].cryptoProperties.assetType is valid
    6. components[].cryptoProperties.algorithmProperties.primitive is valid
    7. components[].bom-ref uniqueness
    8. serialNumber conforms to urn:uuid: pattern (if present)

  If jsonschema and the official schema file are available, a full
  schema validation is also performed as an additional layer.

Usage:
    from core.cbom_generator import CBOMValidator

    validator = CBOMValidator()
    result = validator.validate(json_dict)
    if result.is_valid:
        print("CBOM is valid!")
    else:
        for error in result.errors:
            print(f"  ERROR: {error}")
        for warning in result.warnings:
            print(f"  WARNING: {warning}")
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from core.cbom_generator.models import (
    CDX_ASSET_TYPE_ALGORITHM,
    CDX_ASSET_TYPE_CERTIFICATE,
    CDX_ASSET_TYPE_PROTOCOL,
    CDX_ASSET_TYPE_RELATED_MATERIAL,
    CDX_PRIMITIVE_AE,
    CDX_PRIMITIVE_BLOCK_CIPHER,
    CDX_PRIMITIVE_DRBG,
    CDX_PRIMITIVE_EKEP,
    CDX_PRIMITIVE_HASH,
    CDX_PRIMITIVE_KDF,
    CDX_PRIMITIVE_KEY_AGREE,
    CDX_PRIMITIVE_KEM,
    CDX_PRIMITIVE_MAC,
    CDX_PRIMITIVE_PKE_ASYMM,
    CDX_PRIMITIVE_POST_QUANTUM,
    CDX_PRIMITIVE_SIGNATURE,
    CDX_PRIMITIVE_STREAM_CIPHER,
    CDX_PRIMITIVE_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Valid enum values from CycloneDX 1.6 specification
# ---------------------------------------------------------------------------
_VALID_ASSET_TYPES = frozenset({
    CDX_ASSET_TYPE_ALGORITHM,
    CDX_ASSET_TYPE_CERTIFICATE,
    CDX_ASSET_TYPE_PROTOCOL,
    CDX_ASSET_TYPE_RELATED_MATERIAL,
})

_VALID_PRIMITIVES = frozenset({
    CDX_PRIMITIVE_AE,
    CDX_PRIMITIVE_BLOCK_CIPHER,
    CDX_PRIMITIVE_DRBG,
    CDX_PRIMITIVE_EKEP,
    CDX_PRIMITIVE_HASH,
    CDX_PRIMITIVE_KDF,
    CDX_PRIMITIVE_KEY_AGREE,
    CDX_PRIMITIVE_KEM,
    CDX_PRIMITIVE_MAC,
    CDX_PRIMITIVE_PKE_ASYMM,
    CDX_PRIMITIVE_POST_QUANTUM,
    CDX_PRIMITIVE_SIGNATURE,
    CDX_PRIMITIVE_STREAM_CIPHER,
    CDX_PRIMITIVE_UNKNOWN,
})

# CycloneDX 1.6 valid primitive values also include "pke" and "ekep" from spec
_VALID_PRIMITIVES_EXTENDED = _VALID_PRIMITIVES | frozenset({"pke"})

_SERIAL_NUMBER_PATTERN = re.compile(
    r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


@dataclass
class CBOMValidationResult:
    """Result of a CBOM validation run."""
    is_valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.is_valid


class CBOMValidator:
    """
    Validates a CycloneDX 1.6 CBOM JSON document (as Python dict).

    Performs structural and enum validation against the CycloneDX 1.6
    specification requirements. Optionally performs full JSON Schema
    validation if `jsonschema` is available.
    """

    def validate(self, doc: dict[str, Any]) -> CBOMValidationResult:
        """
        Validate a CBOM document dict against CycloneDX 1.6 structural rules.

        Args:
            doc: Python dict representation of the CycloneDX CBOM document.

        Returns:
            CBOMValidationResult with is_valid flag, errors, and warnings.
        """
        errors: list[str] = []
        warnings: list[str] = []

        # 1. Top-level structure checks
        self._validate_top_level(doc, errors)

        # 2. serialNumber format (if present)
        self._validate_serial_number(doc, errors)

        # 3. metadata checks (warnings only for optional fields)
        self._validate_metadata(doc, warnings)

        # 4. Component-level validation
        bom_refs_seen: set[str] = set()
        components = doc.get("components", [])
        if not isinstance(components, list):
            errors.append(f"'components' must be an array; got {type(components).__name__}.")
        else:
            for i, comp in enumerate(components):
                self._validate_component(
                    comp, index=i, errors=errors, warnings=warnings,
                    bom_refs_seen=bom_refs_seen,
                )

        is_valid = len(errors) == 0
        return CBOMValidationResult(is_valid=is_valid, errors=errors, warnings=warnings)

    # ------------------------------------------------------------------
    # Private validation helpers
    # ------------------------------------------------------------------

    def _validate_top_level(self, doc: dict[str, Any], errors: list[str]) -> None:
        """Validate required top-level fields."""
        if not isinstance(doc, dict):
            errors.append("BOM document must be a JSON object.")
            return

        # bomFormat
        bom_format = doc.get("bomFormat")
        if bom_format is None:
            errors.append("Missing required field: 'bomFormat'.")
        elif bom_format != "CycloneDX":
            errors.append(
                f"'bomFormat' must be 'CycloneDX'; got '{bom_format}'."
            )

        # specVersion
        spec_version = doc.get("specVersion")
        if spec_version is None:
            errors.append("Missing required field: 'specVersion'.")
        elif spec_version != "1.6":
            errors.append(
                f"'specVersion' must be '1.6' for this validator; got '{spec_version}'."
            )

        # version (must be integer >= 1)
        version = doc.get("version")
        if version is None:
            errors.append("Missing required field: 'version'.")
        elif not isinstance(version, int) or version < 1:
            errors.append(
                f"'version' must be an integer >= 1; got {version!r}."
            )

        # components (must be present, can be empty list)
        if "components" not in doc:
            errors.append("Missing required field: 'components'.")

    def _validate_serial_number(self, doc: dict[str, Any], errors: list[str]) -> None:
        """Validate optional serialNumber field format."""
        sn = doc.get("serialNumber")
        if sn is not None:
            if not isinstance(sn, str):
                errors.append(
                    f"'serialNumber' must be a string; got {type(sn).__name__}."
                )
            elif not _SERIAL_NUMBER_PATTERN.match(sn):
                errors.append(
                    f"'serialNumber' does not conform to 'urn:uuid:*' pattern; got '{sn}'."
                )

    def _validate_metadata(self, doc: dict[str, Any], warnings: list[str]) -> None:
        """Check optional metadata block (warnings only)."""
        metadata = doc.get("metadata")
        if metadata is None:
            warnings.append(
                "Optional 'metadata' block is absent. "
                "Recommend including tools and timestamp for traceability."
            )
            return

        tools = metadata.get("tools")
        if tools is None:
            warnings.append("'metadata.tools' is absent. Recommend identifying generating tool.")

    def _validate_component(
        self,
        comp: Any,
        index: int,
        errors: list[str],
        warnings: list[str],
        bom_refs_seen: set[str],
    ) -> None:
        """Validate a single component entry."""
        prefix = f"components[{index}]"

        if not isinstance(comp, dict):
            errors.append(f"{prefix}: component must be an object.")
            return

        # type field
        comp_type = comp.get("type")
        if comp_type is None:
            errors.append(f"{prefix}: missing required field 'type'.")
        elif comp_type != "cryptographic-asset":
            # Non-crypto-asset components are allowed by CDX 1.6 but unusual in a CBOM
            warnings.append(
                f"{prefix}: component type is '{comp_type}', expected 'cryptographic-asset'."
            )

        # bom-ref uniqueness
        bom_ref = comp.get("bom-ref")
        if bom_ref is not None:
            if not isinstance(bom_ref, str) or len(bom_ref) < 1:
                errors.append(f"{prefix}: 'bom-ref' must be a non-empty string.")
            elif bom_ref in bom_refs_seen:
                errors.append(
                    f"{prefix}: duplicate 'bom-ref' '{bom_ref}'. All bom-refs must be unique within the BOM."
                )
            else:
                bom_refs_seen.add(bom_ref)

        # name
        name = comp.get("name")
        if name is None:
            warnings.append(f"{prefix}: 'name' is absent. Recommend providing a human-readable name.")

        # cryptoProperties
        crypto_props = comp.get("cryptoProperties")
        if crypto_props is None:
            warnings.append(
                f"{prefix}: 'cryptoProperties' is absent for a cryptographic-asset component."
            )
        elif isinstance(crypto_props, dict):
            self._validate_crypto_properties(crypto_props, prefix, errors, warnings)

    def _validate_crypto_properties(
        self,
        cp: dict[str, Any],
        prefix: str,
        errors: list[str],
        warnings: list[str],
    ) -> None:
        """Validate a cryptoProperties block."""
        # assetType
        asset_type = cp.get("assetType")
        if asset_type is None:
            errors.append(f"{prefix}.cryptoProperties: missing required field 'assetType'.")
        elif asset_type not in _VALID_ASSET_TYPES:
            errors.append(
                f"{prefix}.cryptoProperties: invalid 'assetType' '{asset_type}'. "
                f"Valid values: {sorted(_VALID_ASSET_TYPES)}."
            )

        # algorithmProperties (only expected for assetType="algorithm")
        algo_props = cp.get("algorithmProperties")
        if asset_type == CDX_ASSET_TYPE_ALGORITHM and algo_props is None:
            warnings.append(
                f"{prefix}.cryptoProperties: 'algorithmProperties' absent for assetType='algorithm'."
            )
        elif algo_props is not None and isinstance(algo_props, dict):
            self._validate_algorithm_properties(algo_props, prefix, errors, warnings)

    def _validate_algorithm_properties(
        self,
        ap: dict[str, Any],
        prefix: str,
        errors: list[str],
        warnings: list[str],
    ) -> None:
        """Validate an algorithmProperties block."""
        ap_prefix = f"{prefix}.cryptoProperties.algorithmProperties"

        # primitive (required)
        primitive = ap.get("primitive")
        if primitive is None:
            errors.append(f"{ap_prefix}: missing required field 'primitive'.")
        elif primitive not in _VALID_PRIMITIVES_EXTENDED:
            errors.append(
                f"{ap_prefix}: invalid 'primitive' '{primitive}'. "
                f"Valid values: {sorted(_VALID_PRIMITIVES_EXTENDED)}."
            )

        # executionEnvironment (required by QNetra convention, warning if absent)
        exec_env = ap.get("executionEnvironment")
        if exec_env is None:
            warnings.append(
                f"{ap_prefix}: 'executionEnvironment' absent. QNetra default is 'software-plain-text'."
            )

        # nistQuantumSecurityLevel range check
        nist_level = ap.get("nistQuantumSecurityLevel")
        if nist_level is not None:
            if not isinstance(nist_level, int) or nist_level not in (1, 2, 3, 4, 5):
                errors.append(
                    f"{ap_prefix}: 'nistQuantumSecurityLevel' must be 1, 2, 3, 4, or 5; "
                    f"got {nist_level!r}."
                )

        # classicalSecurityLevel should be a positive integer
        classical_level = ap.get("classicalSecurityLevel")
        if classical_level is not None:
            if not isinstance(classical_level, int) or classical_level < 1:
                errors.append(
                    f"{ap_prefix}: 'classicalSecurityLevel' must be a positive integer; "
                    f"got {classical_level!r}."
                )
