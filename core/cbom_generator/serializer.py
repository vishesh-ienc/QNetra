"""
QNetra CBOM Generator — CycloneDX 1.6 JSON/XML Serializer
==========================================================

The public entry point for Milestone 2.3 CBOM generation.

CBOMSerializer transforms a list of CryptoAsset objects into a
complete CycloneDX 1.6 CBOM in either JSON or XML format.

Design Constraints:
  - CBOM generation is stateless and produces deterministic output.
  - The same list of CryptoAssets, sorted by asset_id, always produces
    the same JSON byte-for-byte (except for optional live timestamps).
  - No scanning, normalization, classification, or risk scoring.
  - Evidence traceability is preserved through qnetra: properties.
  - JSON is the primary format; XML is generated from the JSON model.

Usage:
    from core.cbom_generator import CBOMSerializer

    serializer = CBOMSerializer()

    # Generate JSON CBOM (deterministic, no timestamp)
    json_str = serializer.to_json(assets, deterministic=True)

    # Generate JSON CBOM with live timestamp
    json_str = serializer.to_json(assets, deterministic=False)

    # Generate XML CBOM
    xml_str = serializer.to_xml(assets, deterministic=True)

    # Retrieve the intermediate CDXBom model
    bom = serializer.build_bom(assets)

CycloneDX 1.6 Reference:
  https://cyclonedx.org/docs/1.6/json/
  ECMA-424, 1st Edition, April 2024

Internal pipeline:
  CryptoAsset[] → mapper.map_asset_to_component() → CDXBom → JSON/XML
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional
from xml.etree import ElementTree as ET

from core.models import CryptoAsset
from core.cbom_generator.mapper import map_asset_to_component
from core.cbom_generator.models import (
    CDXBom,
    CDXComponent,
    CDXCryptoProperties,
    CDXAlgorithmProperties,
    CDXEvidence,
    CDXMetadata,
    CDXMetadataTools,
    CDXProperty,
    CDXToolComponent,
    CDX_ASSET_TYPE_ALGORITHM,
)


# ---------------------------------------------------------------------------
# Deterministic BOM serial number (constant UUID for reproducible output)
# Used ONLY when deterministic=True to allow byte-for-byte identical output.
# ---------------------------------------------------------------------------
_DETERMINISTIC_SERIAL = "urn:uuid:00000000-0000-5000-8000-000000000000"

# CycloneDX 1.6 XML namespace
_CDX_NAMESPACE = "http://cyclonedx.org/schema/bom/1.6"


class CBOMSerializer:
    """
    Serializes a list of CryptoAsset objects to CycloneDX 1.6 JSON or XML.

    Attributes:
        tool_version: Version string embedded in CBOM metadata.tools.
    """

    def __init__(self, tool_version: str = "1.0.0") -> None:
        self._tool_version = tool_version

    def build_bom(
        self,
        assets: list[CryptoAsset],
        *,
        deterministic: bool = True,
        scan_timestamp: Optional[datetime] = None,
    ) -> CDXBom:
        """
        Build a CDXBom (intermediate model) from a list of CryptoAssets.

        Args:
            assets: Canonical classified CryptoAsset list (input contract).
            deterministic: If True, use a fixed serial number and omit timestamp.
                          If False, generate a fresh UUID4 serial number and
                          embed a live ISO 8601 timestamp.
            scan_timestamp: Optional fixed timestamp to use when deterministic=False.
                           If None and deterministic=False, uses UTC now.

        Returns:
            CDXBom populated with components mapped from all assets.
        """
        # Sort assets by asset_id for stable, deterministic component ordering
        sorted_assets = sorted(assets, key=lambda a: a.asset_id)

        # Map each asset to a CDXComponent
        components = [map_asset_to_component(asset) for asset in sorted_assets]

        # Build metadata
        metadata = self._build_metadata(deterministic=deterministic, scan_timestamp=scan_timestamp)

        # Serial number
        if deterministic:
            serial = _DETERMINISTIC_SERIAL
        else:
            serial = f"urn:uuid:{uuid.uuid4()}"

        return CDXBom(
            bom_format="CycloneDX",
            spec_version="1.6",
            serial_number=serial,
            version=1,
            metadata=metadata,
            components=components,
        )

    def _build_metadata(
        self,
        *,
        deterministic: bool,
        scan_timestamp: Optional[datetime],
    ) -> CDXMetadata:
        """Build the BOM metadata block including tool identification."""
        tool = CDXToolComponent(
            type="application",
            name="QNetra ECDAT Engine",
            version=self._tool_version,
            description="Enterprise Cryptographic Discovery & Analysis Tool",
        )
        tools = CDXMetadataTools(components=[tool])

        timestamp: Optional[str] = None
        if not deterministic:
            ts = scan_timestamp or datetime.now(tz=timezone.utc)
            timestamp = ts.strftime("%Y-%m-%dT%H:%M:%SZ")

        return CDXMetadata(tools=tools, timestamp=timestamp)

    # ------------------------------------------------------------------
    # JSON Serialization
    # ------------------------------------------------------------------

    def to_json(
        self,
        assets: list[CryptoAsset],
        *,
        deterministic: bool = True,
        scan_timestamp: Optional[datetime] = None,
        indent: int = 2,
    ) -> str:
        """
        Serialize CryptoAssets to CycloneDX 1.6 JSON string.

        Args:
            assets: Input CryptoAsset list.
            deterministic: If True, suppress timestamp and use fixed serial.
            scan_timestamp: Optional override timestamp (used when not deterministic).
            indent: JSON indentation spaces (default 2).

        Returns:
            Formatted CycloneDX 1.6 JSON string.
        """
        bom = self.build_bom(
            assets,
            deterministic=deterministic,
            scan_timestamp=scan_timestamp,
        )
        doc = self._bom_to_dict(bom)
        return json.dumps(doc, indent=indent, ensure_ascii=False)

    def to_json_dict(
        self,
        assets: list[CryptoAsset],
        *,
        deterministic: bool = True,
        scan_timestamp: Optional[datetime] = None,
    ) -> dict[str, Any]:
        """
        Serialize CryptoAssets to CycloneDX 1.6 document as a Python dict.

        Returns the raw dict before JSON serialization — useful for
        programmatic access and schema validation.
        """
        bom = self.build_bom(
            assets,
            deterministic=deterministic,
            scan_timestamp=scan_timestamp,
        )
        return self._bom_to_dict(bom)

    def _bom_to_dict(self, bom: CDXBom) -> dict[str, Any]:
        """Convert a CDXBom to a plain Python dict matching CycloneDX 1.6 structure."""
        doc: dict[str, Any] = {
            "bomFormat": bom.bom_format,
            "specVersion": bom.spec_version,
            "version": bom.version,
        }

        if bom.serial_number is not None:
            doc["serialNumber"] = bom.serial_number

        if bom.metadata is not None:
            meta = self._metadata_to_dict(bom.metadata)
            if meta:
                doc["metadata"] = meta

        doc["components"] = [
            self._component_to_dict(c) for c in bom.components
        ]

        return doc

    def _metadata_to_dict(self, metadata: CDXMetadata) -> dict[str, Any]:
        """Serialize CDXMetadata to dict."""
        meta: dict[str, Any] = {}

        if metadata.timestamp is not None:
            meta["timestamp"] = metadata.timestamp

        if metadata.tools is not None and metadata.tools.components:
            tool_components = []
            for tc in metadata.tools.components:
                tool_entry: dict[str, Any] = {
                    "type": tc.type,
                    "name": tc.name,
                    "version": tc.version,
                }
                if tc.description:
                    tool_entry["description"] = tc.description
                tool_components.append(tool_entry)
            meta["tools"] = {"components": tool_components}

        return meta

    def _component_to_dict(self, component: CDXComponent) -> dict[str, Any]:
        """Serialize CDXComponent to dict conforming to CycloneDX 1.6."""
        comp: dict[str, Any] = {
            "type": component.type,
        }

        if component.bom_ref:
            comp["bom-ref"] = component.bom_ref

        if component.name:
            comp["name"] = component.name

        if component.crypto_properties is not None:
            comp["cryptoProperties"] = self._crypto_props_to_dict(
                component.crypto_properties
            )

        if component.evidence:
            occurrences = self._evidence_to_dict_list(component.evidence)
            if occurrences:
                comp["evidence"] = {"occurrences": occurrences}

        if component.properties:
            comp["properties"] = [
                {"name": p.name, "value": p.value}
                for p in component.properties
            ]

        return comp

    def _crypto_props_to_dict(self, cp: CDXCryptoProperties) -> dict[str, Any]:
        """Serialize CDXCryptoProperties to dict."""
        result: dict[str, Any] = {"assetType": cp.asset_type}

        if cp.algorithm_properties is not None:
            result["algorithmProperties"] = self._algo_props_to_dict(
                cp.algorithm_properties
            )

        if cp.oid is not None:
            result["oid"] = cp.oid

        # implementationLibrary is a QNetra extension (not a standard CDX field)
        # We use a custom property for this; omit from cryptoProperties
        # However, if it fits "related-crypto-material", retain here for context
        # Per design: skip here; it's captured in qnetra:implementation-library property
        # (see mapper._build_properties)

        return result

    def _algo_props_to_dict(self, ap: CDXAlgorithmProperties) -> dict[str, Any]:
        """
        Serialize CDXAlgorithmProperties to dict.

        Only includes fields with non-None values — enforces NO FABRICATION.
        """
        result: dict[str, Any] = {
            "primitive": ap.primitive,
            "executionEnvironment": ap.execution_environment,
        }

        if ap.parameter_set_identifier is not None:
            result["parameterSetIdentifier"] = ap.parameter_set_identifier

        if ap.curve is not None:
            result["curve"] = ap.curve

        if ap.mode is not None:
            result["mode"] = ap.mode

        if ap.padding is not None:
            result["padding"] = ap.padding

        if ap.crypto_functions:
            result["cryptoFunctions"] = ap.crypto_functions

        if ap.classical_security_level is not None:
            result["classicalSecurityLevel"] = ap.classical_security_level

        if ap.nist_quantum_security_level is not None:
            result["nistQuantumSecurityLevel"] = ap.nist_quantum_security_level

        return result

    def _evidence_to_dict_list(
        self, evidence: list[CDXEvidence]
    ) -> list[dict[str, Any]]:
        """Serialize evidence occurrences list."""
        result = []
        for ev in evidence:
            entry: dict[str, Any] = {}
            if ev.location is not None:
                entry["location"] = ev.location
            if ev.line is not None:
                entry["line"] = ev.line
            if ev.symbol is not None:
                entry["symbol"] = ev.symbol
            if entry:
                result.append(entry)
        return result

    # ------------------------------------------------------------------
    # XML Serialization
    # ------------------------------------------------------------------

    def to_xml(
        self,
        assets: list[CryptoAsset],
        *,
        deterministic: bool = True,
        scan_timestamp: Optional[datetime] = None,
        xml_declaration: bool = True,
    ) -> str:
        """
        Serialize CryptoAssets to CycloneDX 1.6 XML string.

        Generates XML from the same internal CDXBom model used by to_json().
        Ensures structural consistency between JSON and XML outputs.

        Args:
            assets: Input CryptoAsset list.
            deterministic: If True, suppress timestamp and use fixed serial.
            scan_timestamp: Optional override timestamp.
            xml_declaration: If True, prepend <?xml version="1.0" encoding="UTF-8"?>.

        Returns:
            CycloneDX 1.6 XML string.
        """
        bom = self.build_bom(
            assets,
            deterministic=deterministic,
            scan_timestamp=scan_timestamp,
        )
        root = self._bom_to_xml_element(bom)

        # Indent the XML for readability (Python 3.9+)
        ET.indent(root, space="  ")

        xml_bytes = ET.tostring(root, encoding="unicode", xml_declaration=False)

        if xml_declaration:
            return '<?xml version="1.0" encoding="UTF-8"?>\n' + xml_bytes
        return xml_bytes

    def _bom_to_xml_element(self, bom: CDXBom) -> ET.Element:
        """Build the root <bom> XML element for a CDXBom."""
        attribs: dict[str, str] = {
            "xmlns": _CDX_NAMESPACE,
            "version": str(bom.version),
        }
        if bom.serial_number is not None:
            attribs["serialNumber"] = bom.serial_number

        root = ET.Element("bom", attrib=attribs)

        # <metadata>
        if bom.metadata is not None:
            meta_el = ET.SubElement(root, "metadata")
            if bom.metadata.timestamp is not None:
                ET.SubElement(meta_el, "timestamp").text = bom.metadata.timestamp
            if bom.metadata.tools is not None and bom.metadata.tools.components:
                tools_el = ET.SubElement(meta_el, "tools")
                for tc in bom.metadata.tools.components:
                    comp_el = ET.SubElement(tools_el, "component", attrib={"type": tc.type})
                    ET.SubElement(comp_el, "name").text = tc.name
                    ET.SubElement(comp_el, "version").text = tc.version
                    if tc.description:
                        ET.SubElement(comp_el, "description").text = tc.description

        # <components>
        if bom.components:
            components_el = ET.SubElement(root, "components")
            for component in bom.components:
                self._component_to_xml_element(components_el, component)

        return root

    def _component_to_xml_element(
        self, parent: ET.Element, component: CDXComponent
    ) -> ET.Element:
        """Add a CDXComponent as a child element to parent."""
        attribs: dict[str, str] = {"type": component.type}
        if component.bom_ref:
            attribs["bom-ref"] = component.bom_ref

        comp_el = ET.SubElement(parent, "component", attrib=attribs)

        if component.name:
            ET.SubElement(comp_el, "name").text = component.name

        if component.crypto_properties is not None:
            cp_el = ET.SubElement(comp_el, "cryptoProperties")
            self._crypto_props_to_xml(cp_el, component.crypto_properties)

        if component.evidence:
            ev_el = ET.SubElement(comp_el, "evidence")
            occ_el = ET.SubElement(ev_el, "occurrences")
            for ev in component.evidence:
                occur_el = ET.SubElement(occ_el, "occurrence")
                if ev.location is not None:
                    ET.SubElement(occur_el, "location").text = ev.location
                if ev.line is not None:
                    ET.SubElement(occur_el, "line").text = str(ev.line)
                if ev.symbol is not None:
                    ET.SubElement(occur_el, "symbol").text = ev.symbol

        if component.properties:
            props_el = ET.SubElement(comp_el, "properties")
            for p in component.properties:
                prop_el = ET.SubElement(props_el, "property", attrib={"name": p.name})
                prop_el.text = p.value

        return comp_el

    def _crypto_props_to_xml(
        self, parent: ET.Element, cp: CDXCryptoProperties
    ) -> None:
        """Serialize CDXCryptoProperties into XML children of parent."""
        ET.SubElement(parent, "assetType").text = cp.asset_type

        if cp.algorithm_properties is not None:
            ap = cp.algorithm_properties
            ap_el = ET.SubElement(parent, "algorithmProperties")
            ET.SubElement(ap_el, "primitive").text = ap.primitive
            ET.SubElement(ap_el, "executionEnvironment").text = ap.execution_environment

            if ap.parameter_set_identifier is not None:
                ET.SubElement(ap_el, "parameterSetIdentifier").text = ap.parameter_set_identifier

            if ap.curve is not None:
                ET.SubElement(ap_el, "curve").text = ap.curve

            if ap.mode is not None:
                ET.SubElement(ap_el, "mode").text = ap.mode

            if ap.padding is not None:
                ET.SubElement(ap_el, "padding").text = ap.padding

            if ap.classical_security_level is not None:
                ET.SubElement(ap_el, "classicalSecurityLevel").text = str(
                    ap.classical_security_level
                )

            if ap.nist_quantum_security_level is not None:
                ET.SubElement(ap_el, "nistQuantumSecurityLevel").text = str(
                    ap.nist_quantum_security_level
                )

        if cp.oid is not None:
            ET.SubElement(parent, "oid").text = cp.oid
