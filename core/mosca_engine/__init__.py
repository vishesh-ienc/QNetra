"""
QNetra Mosca Engine — Public API
==================================

Milestone 3.2: Michele Mosca Migration & HNDL Engine.

This module exports the complete public interface for the Mosca engine subsystem.

Public API:
  MoscaEngine          : Primary engine class (assess, assess_all, generate_report).
  MoscaInput           : Per-asset context inputs (X, Y, Z, HNDL sensitivity, date).
  MoscaConfig          : Engine configuration (default quantum horizon, migration policy).
  MoscaAssessment      : Per-asset result with X, Y, Z, inequality, HNDL, urgency, deadline.
  MoscaAssessmentReport: Repository-level aggregate report.
  AssetMoscaDetail     : Lightweight summary record for report lists.
  MoscaUrgency         : Migration urgency enum (IMMEDIATE, URGENT, PLANNED, MONITOR, ...).
  HNDLExposure         : HNDL exposure tier enum (CRITICAL, HIGH, MEDIUM, LOW, NONE, UNKNOWN).

Contract References:
  - docs/05_ALGORITHMS.md (Alg-07: Michele Mosca Migration Inequality)
  - docs/06_API_AND_DATA_CONTRACTS.md (Section 2.4: MoscaAssessmentReport)
  - docs/10_API_CONTRACT.md (Section 12: Mosca API)
  - docs/09_KNOWLEDGE_BASE.md (Section 2.1: Mosca's Theorem)
"""

from core.mosca_engine.engine import MoscaEngine
from core.mosca_engine.knowledge import MoscaConfig
from core.mosca_engine.models import (
    AssetMoscaDetail,
    HNDLExposure,
    MoscaAssessment,
    MoscaAssessmentReport,
    MoscaInput,
    MoscaUrgency,
)

__all__ = [
    "MoscaEngine",
    "MoscaInput",
    "MoscaConfig",
    "MoscaAssessment",
    "MoscaAssessmentReport",
    "AssetMoscaDetail",
    "MoscaUrgency",
    "HNDLExposure",
]
