"""
QNetra Normalization Subsystem — Finding Deduplicator & Aggregator
==================================================================

Implements deterministic grouping, deduplication, and aggregation of raw scanner findings
into canonical CryptoAsset models.

Aggregation Rules:
  1. Source Code (Repository): Findings in the same file that refer to compatible algorithms
     and non-conflicting parameters on proximate/identical lines (within +/- 2 lines) merge into
     a single CryptoAsset. Distinct call sites at different line locations remain separate.
  2. Binary Targets: Findings within the same compiled binary file sharing the same algorithm
     and compatible parameters merge into that binary's asset.
  3. Container Filesystem: Findings in the same container filesystem path sharing the same
     algorithm/package merge into a single asset.
  4. Disjoint / Ambiguous: Findings with conflicting algorithms (e.g. RSA vs AES), conflicting
     key sizes (e.g. 1024 vs 2048), or conflicting cipher modes (e.g. GCM vs CBC) NEVER merge.

Deterministic Identity Strategy:
  Canonical CryptoAsset UUIDs are generated deterministically using RFC 4122 UUIDv5
  under the QNetra DNS namespace 'asset.qnetra.io'.

Contracts:
  - docs/06_API_AND_DATA_CONTRACTS.md Section 2.2
  - docs/10_API_CONTRACT.md Section 8
"""

from __future__ import annotations

import os
import uuid
from collections import defaultdict
from typing import Any, Optional, Sequence

from core.models import CryptoAsset, PrimitiveType, SupportingFindingEvidence
from core.normalization.algorithm_normalizer import AlgorithmNormalizer, NormalizedAttributes
from core.normalization.confidence_aggregator import ConfidenceAggregator
from scanners.framework.models import FileLocation, RawFinding

# Deterministic namespace for all QNetra CryptoAsset UUIDs
QNETRA_ASSET_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "asset.qnetra.io")


def _normalize_path(path: str) -> str:
    """Normalize file path for consistent cross-platform clustering."""
    if not path:
        return ""
    # Standardize forward slashes and strip leading current directory indicators
    norm = path.replace("\\", "/").strip()
    if norm.startswith("./"):
        norm = norm[2:]
    return norm.lower()


class Deduplicator:
    """
    Groups and aggregates RawFinding records into canonical CryptoAsset records.
    """

    @staticmethod
    def deduplicate(findings: Sequence[RawFinding]) -> list[CryptoAsset]:
        """
        Group raw findings by deterministic clustering keys and synthesize CryptoAsset records.

        Args:
            findings: Sequence of RawFinding objects.

        Returns:
            List of deduplicated, canonical CryptoAsset instances.
        """
        if not findings:
            return []

        # 1. First pass: Normalize individual findings
        normalized_records: list[tuple[RawFinding, NormalizedAttributes]] = []
        for f in findings:
            attrs = AlgorithmNormalizer.normalize_finding(f)
            normalized_records.append((f, attrs))

        # 2. Cluster findings into candidate buckets
        # Group by file path and target classification
        file_buckets: dict[str, list[tuple[RawFinding, NormalizedAttributes]]] = defaultdict(list)
        for f, attrs in normalized_records:
            file_key = _normalize_path(f.location.file_path)
            file_buckets[file_key].append((f, attrs))

        # 3. Within each file bucket, perform fine-grained aggregation
        assets: list[CryptoAsset] = []
        for file_key, bucket in sorted(file_buckets.items()):
            clusters = Deduplicator._cluster_bucket(file_key, bucket)
            for cluster in clusters:
                asset = Deduplicator._merge_cluster(file_key, cluster)
                assets.append(asset)

        # 4. Return assets in deterministic order (by file_path, line, algorithm)
        assets.sort(
            key=lambda a: (
                a.location.file_path,
                a.location.start_line or 0,
                a.algorithm,
                a.asset_id,
            )
        )
        return assets

    @staticmethod
    def _cluster_bucket(
        file_key: str,
        items: list[tuple[RawFinding, NormalizedAttributes]],
    ) -> list[list[tuple[RawFinding, NormalizedAttributes]]]:
        """
        Cluster findings in the same file into distinct asset candidate groups.
        """
        clusters: list[list[tuple[RawFinding, NormalizedAttributes]]] = []

        for item in items:
            f, attrs = item
            placed = False

            # Check existing clusters in this bucket
            for cluster in clusters:
                if Deduplicator._is_compatible(cluster, item):
                    cluster.append(item)
                    placed = True
                    break

            if not placed:
                clusters.append([item])

        return clusters

    @staticmethod
    def _is_compatible(
        cluster: list[tuple[RawFinding, NormalizedAttributes]],
        candidate: tuple[RawFinding, NormalizedAttributes],
    ) -> bool:
        """
        Determine if candidate finding can be merged into an existing cluster.
        """
        cand_f, cand_attrs = candidate

        # Compare candidate against all members of the cluster
        for existing_f, existing_attrs in cluster:
            # 1. Check target type / format compatibility
            is_binary = cand_f.binary_format is not None or existing_f.binary_format is not None
            is_container = cand_f.container_context is not None or existing_f.container_context is not None

            # 2. Check algorithm family compatibility
            fam1 = (existing_attrs.algorithm_family or "").upper()
            fam2 = (cand_attrs.algorithm_family or "").upper()
            if fam1 and fam2 and fam1 != fam2:
                return False

            # 3. Check algorithm name compatibility (allow specific vs generic, e.g. AES vs AES-256-GCM)
            alg1 = existing_attrs.algorithm.upper()
            alg2 = cand_attrs.algorithm.upper()
            if not Deduplicator._algorithms_match(alg1, alg2, fam1):
                return False

            # 4. Check explicit parameter conflicts
            # Key sizes: if both have key sizes, they must be equal
            k1 = existing_attrs.key_length_bits
            k2 = cand_attrs.key_length_bits
            if k1 is not None and k2 is not None and k1 != k2:
                return False

            # Modes: if both have modes, they must be equal
            m1 = (existing_attrs.mode or "").upper()
            m2 = (cand_attrs.mode or "").upper()
            if m1 and m2 and m1 != m2:
                return False

            # Curves: if both have curves, they must be equal
            c1 = (existing_attrs.curve or "").lower()
            c2 = (cand_attrs.curve or "").lower()
            if c1 and c2 and c1 != c2:
                return False

            # 5. Check location proximity
            if is_binary or is_container:
                # For compiled binaries and container packages, findings in the same file
                # with matching algorithm belong to the same binary asset
                continue

            # For source code: check line numbers
            line1 = existing_f.location.start_line
            line2 = cand_f.location.start_line

            if line1 is not None and line2 is not None:
                # Merge if on same line or within +/- 2 lines (proximate statement)
                if abs(line1 - line2) > 2:
                    return False
            elif line1 is None and line2 is None:
                # Both are file-level (e.g. imports)
                continue
            else:
                # One has line, one does not (e.g. file-level regex match vs AST line call)
                # Keep separate unless they share library or raw symbol
                if existing_attrs.primitive_type == PrimitiveType.LIBRARY:
                    return False

        return True

    @staticmethod
    def _algorithms_match(alg1: str, alg2: str, family: str) -> bool:
        """Check if two algorithm strings represent compatible representations."""
        if alg1 == alg2:
            return True
        if alg1 in ("UNKNOWN ALGORITHM", "N/A") or alg2 in ("UNKNOWN ALGORITHM", "N/A"):
            return True

        # If one is generic family and other is specific variant (e.g. AES and AES-256-GCM)
        if alg1 == family or alg2 == family:
            return True
        if alg1.startswith(alg2) or alg2.startswith(alg1):
            return True

        # Both start with family (e.g. AES-256 and AES-256-GCM)
        if family and alg1.startswith(family) and alg2.startswith(family):
            return True

        return False

    @staticmethod
    def _merge_cluster(
        file_key: str,
        cluster: list[tuple[RawFinding, NormalizedAttributes]],
    ) -> CryptoAsset:
        """
        Merge a cluster of compatible findings into a single canonical CryptoAsset.
        """
        # Collect raw findings
        findings = [item[0] for item in cluster]
        attrs_list = [item[1] for item in cluster]

        # 1. Select the most specific algorithm string
        best_alg = Deduplicator._select_most_specific_algorithm(attrs_list)

        # 2. Select family
        family = next((a.algorithm_family for a in attrs_list if a.algorithm_family), None)

        # 3. Select primitive category
        primitive_type = Deduplicator._select_most_specific_category(attrs_list)

        # 4. Resolve technical parameters
        key_size = next((a.key_length_bits for a in attrs_list if a.key_length_bits is not None), None)
        mode = next((a.mode for a in attrs_list if a.mode), None)
        curve = next((a.curve for a in attrs_list if a.curve), None)
        padding = next((a.padding for a in attrs_list if a.padding), None)
        library = next((a.implementation_library for a in attrs_list if a.implementation_library), None)

        # 5. Resolve primary location & supporting locations
        primary_loc = Deduplicator._select_primary_location(findings)
        all_locations = [f.location for f in findings]

        # 6. Build supporting findings evidence
        supporting_evidence: list[SupportingFindingEvidence] = []
        for f in findings:
            supporting_evidence.append(
                SupportingFindingEvidence(
                    finding_id=f.finding_id,
                    scanner_name=f.scanner_name,
                    discovery_method=f.discovery_method.value,
                    raw_symbol=f.raw_symbol,
                    location=f.location,
                    confidence_score=round(f.confidence_score, 4),
                    confidence_rationale=f.confidence_rationale,
                )
            )

        # Supporting finding IDs
        supporting_ids = sorted(f.finding_id for f in findings)

        # 7. Aggregate confidence
        conf_score, conf_level, conf_rationale = ConfidenceAggregator.aggregate(findings)

        # 8. Build extra metadata
        metadata: dict[str, Any] = {
            "finding_count": len(findings),
            "discovery_methods": sorted(set(f.discovery_method.value for f in findings)),
            "scanners": sorted(set(f.scanner_name for f in findings)),
            "raw_symbols": sorted(set(f.raw_symbol for f in findings if f.raw_symbol)),
        }
        symbols = [f.symbol_name for f in findings if f.symbol_name]
        if symbols:
            metadata["symbols"] = sorted(set(symbols))
        offsets = [f.location.byte_offset for f in findings if f.location.byte_offset is not None]
        if offsets:
            metadata["byte_offsets"] = sorted(set(offsets))
        container_ctx = next((f.container_context for f in findings if f.container_context), None)
        if container_ctx:
            metadata["container_context"] = container_ctx.model_dump()
        bin_format = next((f.binary_format for f in findings if f.binary_format), None)
        if bin_format:
            metadata["binary_format"] = bin_format.value

        # 9. Generate Deterministic Asset ID (UUIDv5)
        line_anchor = str(primary_loc.start_line) if primary_loc.start_line is not None else "file"
        asset_id = Deduplicator.generate_deterministic_id(
            file_path=file_key,
            line_anchor=line_anchor,
            algorithm=best_alg,
            key_size=key_size,
            mode=mode,
            curve=curve,
            library=library,
        )

        return CryptoAsset(
            asset_id=asset_id,
            algorithm=best_alg,
            algorithm_family=family,
            primitive_type=primitive_type,
            key_length_bits=key_size,
            curve=curve,
            mode=mode,
            padding=padding,
            implementation_library=library,
            location=primary_loc,
            locations=all_locations,
            supporting_finding_ids=supporting_ids,
            supporting_findings=supporting_evidence,
            confidence_score=conf_score,
            confidence_level=conf_level,
            confidence_rationale=conf_rationale,
            metadata=metadata,
        )

    @staticmethod
    def generate_deterministic_id(
        file_path: str,
        line_anchor: str,
        algorithm: str,
        key_size: Optional[int] = None,
        mode: Optional[str] = None,
        curve: Optional[str] = None,
        library: Optional[str] = None,
    ) -> str:
        """
        Generate a strictly deterministic RFC 4122 UUIDv5 for a canonical CryptoAsset.
        Ensures identical findings produce the exact same ID across runs and platforms.
        """
        seed = (
            f"path:{file_path}|"
            f"line:{line_anchor}|"
            f"alg:{algorithm.upper()}|"
            f"key:{key_size or 'none'}|"
            f"mode:{(mode or 'none').upper()}|"
            f"curve:{(curve or 'none').lower()}|"
            f"lib:{(library or 'none').lower()}"
        )
        return str(uuid.uuid5(QNETRA_ASSET_NAMESPACE, seed))

    @staticmethod
    def _select_most_specific_algorithm(attrs_list: list[NormalizedAttributes]) -> str:
        """Select algorithm name with highest specificity (e.g. AES-256-GCM > AES-256 > AES)."""
        valid_algs = [a.algorithm for a in attrs_list if a.algorithm and a.algorithm != "Unknown Algorithm"]
        if not valid_algs:
            return "Unknown Algorithm"
        # Return the longest algorithm string as heuristic for specificity
        return max(valid_algs, key=len)

    @staticmethod
    def _select_most_specific_category(attrs_list: list[NormalizedAttributes]) -> PrimitiveType:
        """Select most descriptive primitive type."""
        for a in attrs_list:
            if a.primitive_type != PrimitiveType.UNKNOWN:
                return a.primitive_type
        return PrimitiveType.UNKNOWN

    @staticmethod
    def _select_primary_location(findings: list[RawFinding]) -> FileLocation:
        """
        Select highest-fidelity location for primary display.
        Prefers AST findings with line numbers and snippets over generic matches.
        """
        # First preference: AST with start_line and snippet
        for f in findings:
            if f.discovery_method.value == "AST" and f.location.start_line is not None and f.location.snippet:
                return f.location

        # Second preference: Highest confidence finding with line number
        with_line = [f for f in findings if f.location.start_line is not None]
        if with_line:
            best = max(with_line, key=lambda f: f.confidence_score)
            return best.location

        # Third preference: Finding with highest confidence score
        best_overall = max(findings, key=lambda f: f.confidence_score)
        return best_overall.location
