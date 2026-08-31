"""Materialized R5 route entrypoint; extraction remains non-authoritative."""
from r5_wrapper import extract_scoring

EXTRACTOR_SPEC_ID = "R4_SCORING_ID_JSONL_WRAPPER_EXTRACTOR_V1"
RULE_ID = "R4_WRAPPER_SCORING_231"
EXTRACTOR = extract_scoring
