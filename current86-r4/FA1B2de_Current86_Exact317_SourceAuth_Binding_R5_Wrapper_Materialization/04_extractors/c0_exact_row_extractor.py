"""Materialized R5 route entrypoint; extraction remains non-authoritative."""
from r5_wrapper import extract_c0

EXTRACTOR_SPEC_ID = "R4_C0_IMMUTABLE_JSONL_WRAPPER_EXTRACTOR_V1"
RULE_ID = "R4_WRAPPER_C0_60"
EXTRACTOR = extract_c0
