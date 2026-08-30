from pathlib import Path
import unittest

from build_exp_e0_c_readiness import audit_raw_authority
from build_exp_e0c_r1_enrichment import (
    build_r1_enrichment,
    build_r1_outputs,
    load_current_readiness,
)


CORPUS = Path("/home/cph/experiment/APT数据集/playbooks")
REGISTRY = Path(
    "/home/cph/experiment-worktrees/full-action-protocol-binding/"
    "data/full_action/raw_action_registry.jsonl"
)
CURRENT = Path("EXP_E0_C_1796_PROVX_REPLAY_READINESS.jsonl")


class R1EnrichmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit = audit_raw_authority(CORPUS, REGISTRY)
        cls.current = load_current_readiness(CURRENT)
        cls.result = build_r1_enrichment(cls.audit, cls.current)

    def test_enrichment_conserves_exact_raw_keys(self):
        rows = self.result["rows"]
        self.assertEqual(len(rows), 1796)
        self.assertEqual(len({row["raw_key"] for row in rows}), 1796)
        self.assertEqual(self.result["conservation"]["missing_raw_count"], 0)
        self.assertEqual(self.result["conservation"]["extra_raw_count"], 0)
        self.assertEqual(self.result["conservation"]["duplicate_raw_key_count"], 0)
        self.assertTrue(all(row["formal_execution_authorized"] is False for row in rows))
        self.assertTrue(all("primary_execution_archetype" in row for row in rows))
        self.assertTrue(all("planning_field_provenance" in row for row in rows))

    def test_source_evidenced_fields_have_provenance_and_result_dimensions_stay_unexecuted(self):
        rows = self.result["rows"]
        for row in rows:
            enrichment = row["r1_enrichment"]
            provenance = enrichment["planning_field_provenance"]
            for field, value in enrichment.items():
                is_unknown = value == "UNKNOWN" or (
                    isinstance(value, list) and value == ["UNKNOWN"]
                )
                if field == "planning_field_provenance" or is_unknown:
                    continue
                self.assertIn(field, provenance, row["raw_key"])
                self.assertTrue(provenance[field], row["raw_key"])
            self.assertEqual(row["provx_phase1_observable"], "UNKNOWN")
            self.assertEqual(row["provx_phase2_core_edge_localizable"], "UNKNOWN")
            self.assertEqual(row["attack_action_success"], "UNEXECUTED_NOT_OBSERVED")
            self.assertEqual(row["real_enforcement_prevention"], "UNEXECUTED_NOT_OBSERVED")

    def test_lexical_flag_provenance_points_to_name_or_description(self):
        rows = {row["raw_key"]: row for row in self.result["rows"]}
        row = rows["6000002::S02::A001"]
        enrichment = row["r1_enrichment"]
        self.assertTrue(enrichment["requires_network_fabric"])
        evidence = enrichment["planning_field_provenance"]["requires_network_fabric"]
        self.assertTrue(any(item["source_field_path"].endswith(".name") for item in evidence))
        self.assertFalse(
            all(item["source_field_path"].endswith(".action_type") for item in evidence)
        )

    def test_structured_protocol_evidence_is_retained(self):
        rows = {row["raw_key"]: row for row in self.result["rows"]}
        row = rows["6000002::S04::A001"]["r1_enrichment"]
        self.assertIn("HTTP", row["named_protocols_or_services"])
        evidence = row["planning_field_provenance"]["named_protocols_or_services"]
        self.assertTrue(any("args.transfer.protocol" in item["source_field_path"] for item in evidence))

    def test_narrative_words_do_not_create_tool_names_or_wrong_archetypes(self):
        rows = {row["raw_key"]: row for row in self.result["rows"]}
        self.assertNotIn("API", rows["6000002::S05::A007"]["r1_enrichment"]["explicit_tool_or_malware_names"])
        self.assertNotIn("EXE", rows["6000003::S02::A003"]["r1_enrichment"]["explicit_tool_or_malware_names"])
        self.assertEqual(
            rows["6000002::S02::A001"]["r1_enrichment"]["primary_execution_archetype"],
            "NETWORK_C2_BEACON",
        )
        self.assertEqual(
            rows["6000047::S01::A002"]["r1_enrichment"]["primary_execution_archetype"],
            "NETWORK_SERVICE_INTERACTION",
        )

    def test_backlog_reports_network_and_service_requirements_and_terminal_metadata(self):
        outputs = build_r1_outputs(self.result)
        family = next(
            item for item in outputs["adapter_backlog"]["adapter_families"]
            if item["primary_execution_archetype"] == "NETWORK_SERVICE_INTERACTION"
        )
        self.assertIn("requires_network_fabric", family["telemetry_requirements"])
        self.assertIn("requires_external_service_emulation", family["telemetry_requirements"])
        self.assertIn("WEB_APPLICATION_SERVICE", family["service_or_protocol_prerequisites"])
        self.assertIn("NEXT_ACTION = FRESH_REVIEW_OF_EXP_E0C_R1_EXECUTION_ARCHETYPE_ENRICHMENT", outputs["planning_report"])
        self.assertEqual(outputs["conservation_audit"]["next_action"], "FRESH_REVIEW_OF_EXP_E0C_R1_EXECUTION_ARCHETYPE_ENRICHMENT")
        self.assertTrue(outputs["conservation_audit"]["stop"])

    def test_representative_archetypes_and_candidate_modes_are_source_conservative(self):
        rows = {row["raw_key"]: row for row in self.result["rows"]}
        pcap = rows["6000002::S01::A001"]["r1_enrichment"]
        self.assertEqual(pcap["primary_execution_archetype"], "NETWORK_SERVICE_INTERACTION")
        self.assertEqual(pcap["candidate_execution_mode_for_design"], "EMULATED_CANDIDATE")
        self.assertTrue(pcap["requires_network_fabric"])
        self.assertIn("RDP", pcap["named_protocols_or_services"])

        host = rows["6000002::S02::A002"]["r1_enrichment"]
        self.assertEqual(host["primary_execution_archetype"], "DISCOVERY_ENUMERATION")
        self.assertEqual(host["candidate_execution_mode_for_design"], "NATIVE_CANDIDATE")
        self.assertTrue(host["requires_host_process_telemetry"])

        email = rows["6000002::S01::A003"]["r1_enrichment"]
        self.assertEqual(email["primary_execution_archetype"], "EMAIL_DELIVERY")
        self.assertEqual(email["candidate_execution_mode_for_design"], "SYNTHETIC_CANDIDATE")
        self.assertFalse(email["formal_execution_authorized"] if "formal_execution_authorized" in email else False)

    def test_catalog_and_backlog_conserve_rows(self):
        outputs = build_r1_outputs(self.result)
        catalog = outputs["catalog"]
        backlog = outputs["adapter_backlog"]
        self.assertEqual(catalog["raw_record_count"], 1796)
        self.assertEqual(sum(item["raw_count"] for item in catalog["archetypes"].values()), 1796)
        self.assertEqual(backlog["raw_record_count"], 1796)
        self.assertEqual(sum(item["raw_count"] for item in backlog["adapter_families"]), 1796)
        self.assertEqual(len(backlog["adapter_families"]), catalog["execution_archetype_count"])


if __name__ == "__main__":
    unittest.main()
