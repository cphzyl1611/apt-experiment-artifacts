# Exact317 Provenance Recovery R3

This packet performs provenance recovery only. Authenticated bytes were indexed for 86 RAW targets, 60 C0 evidence rows, and 231 scoring rows. The 7,911 scalar leaves are carried forward unchanged as non-authoritative evidence.

No canonical-intrinsic source manifest entry or frozen candidate-object extraction authority was found. C0 archive/source/producer/manifest/checksum anchors are complete, but C0 remains explicitly noncanonical evidence-only. Consequently no candidate_object_id is materialized and all 317 targets remain Stage-A blocked.

Blockers: `BLOCKED_MISSING_PRODUCER_IDENTITY` = 26; `BLOCKED_MISSING_SOURCE_MANIFEST` = 291.

Terminal: `EXACT317_PROVENANCE_RECOVERY_R3 = BLOCKED`
