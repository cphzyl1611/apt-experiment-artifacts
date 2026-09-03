# Fail-closed rules

`FAIL_CLOSED_RULES.json` is the machine-readable rule set. The future
transaction evaluates schema validity first and then every semantic rule; one
failure returns `FAIL_CLOSED_NO_ACTIVATION` and produces no receipt or handoff.

The rule set intentionally includes the old V1 circularity check: the
materialized governance record must not require a source authority that is
created by this later transaction.

