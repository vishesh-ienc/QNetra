"""
QNetra Backend — API Gateway (Phase 4)
=======================================

Thin FastAPI layer over the existing, unmodified pipeline:

    scanners.*  ->  core.normalization  ->  core.classification
                ->  core.risk_engine    ->  core.mosca_engine
                ->  core.recommendation_engine  ->  core.cbom_generator

Per PROJECT_RULES.md RULE-004 (layered separation), this package contains
NO cryptographic analysis logic. It validates requests, calls the engines,
and shapes their output into the JSON contract the frontend consumes.
Every number in every response is produced by an engine in core/ or
scanners/ — nothing here computes, scores, or classifies anything.
"""
