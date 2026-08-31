"""Materialized R5 route entrypoint; extraction remains non-authoritative."""
from r5_wrapper import extract_raw

EXTRACTOR_SPEC_ID = "R4_RAW_PLAYBOOK_POSITIONAL_EXTRACTOR_V1"
RULE_ID = "R4_WRAPPER_RAW_LEGACY_26"
EXTRACTOR = extract_raw
