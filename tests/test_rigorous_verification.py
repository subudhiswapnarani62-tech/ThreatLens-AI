import json
import sys
import hashlib
import unittest
from datetime import datetime
from unittest.mock import patch
from pathlib import Path
from urllib import request as urllib_request
from urllib.error import HTTPError

# Add project root and backend to sys.path
root_dir = Path(__file__).resolve().parent.parent
backend_dir = root_dir / "backend"
sys.path.insert(0, str(root_dir))
sys.path.insert(0, str(backend_dir))

from backend.main import validate_architecture_payload
from backend.comparison_engine import (
    SECURITY_TEST_REGISTRY,
    compare_architectures,
    execute_test_suite,
    stable_threat_key,
)
from backend.analyzer import analyze_architecture

API_BASE = "http://127.0.0.1:8001"
BASELINE_PATH = root_dir / "test_data" / "vehicle_v1.json"


def get_baseline_hash():
    with open(BASELINE_PATH, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def load_baseline():
    with open(BASELINE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def api_request(method: str, path: str, data: dict = None):
    url = f"{API_BASE}{path}"
    headers = {"Content-Type": "application/json"} if data is not None else {}
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib_request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib_request.urlopen(req) as resp:
            status = resp.status
            content = resp.read().decode("utf-8")
            return status, json.loads(content) if content else {}
    except HTTPError as e:
        err_content = e.read().decode("utf-8")
        try:
            parsed = json.loads(err_content)
        except Exception:
            parsed = {"raw": err_content}
        return e.code, parsed


class TestThreatLensRigorousVerification(unittest.TestCase):
    # =================================================================
    # 1. BASELINE ARCHITECTURE INTEGRITY & IMMUTABILITY (REQ 1, 9)
    # =================================================================
    def test_01_baseline_file_and_pipeline(self):
        """Baseline produces exactly 4 components, 4 interfaces, 4 surfaces, 13 threats."""
        v1 = load_baseline()
        self.assertEqual(v1["system"], "Connected Vehicle")
        self.assertEqual(len(v1["components"]), 4)
        self.assertEqual(len(v1["interfaces"]), 4)

        analysis = analyze_architecture(v1)
        self.assertEqual(len(analysis["attack_surfaces"]), 4)
        self.assertEqual(len(analysis["threats"]), 13)
        self.assertEqual(len(analysis["security_findings"]), 13)

        for f in analysis["security_findings"]:
            self.assertTrue(f["cwe"].startswith("CWE-"))
            self.assertIn(f["risk_level"], ("Critical", "High", "Medium", "Low"))

    def test_02_baseline_endpoint_and_immutability(self):
        """GET /api/baseline is read-only; attempts to modify fail with 405; file hash stays identical."""
        initial_hash = get_baseline_hash()

        status, body = api_request("GET", "/api/baseline")
        self.assertEqual(status, 200)
        self.assertEqual(body["system"], "Connected Vehicle")

        # POST /api/baseline -> 405 Method Not Allowed
        status_post, _ = api_request("POST", "/api/baseline", {"system": "Mutated Vehicle"})
        self.assertEqual(status_post, 405)

        # PUT /api/baseline -> 405 Method Not Allowed
        status_put, _ = api_request("PUT", "/api/baseline", {"system": "Mutated Vehicle"})
        self.assertEqual(status_put, 405)

        # DELETE /api/baseline -> 405 Method Not Allowed
        status_del, _ = api_request("DELETE", "/api/baseline")
        self.assertEqual(status_del, 405)

        # File hash on disk is untouched
        self.assertEqual(get_baseline_hash(), initial_hash)

    # =================================================================
    # 2. WI-FI ADDITION SCENARIO (REQ 2)
    # =================================================================
    def test_03_wifi_addition_in_v2(self):
        """
        Adding Wi-Fi interface in V2:
        - Exactly 1 interface added (infotainment -> external [Wi-Fi])
        - Exactly 1 Wi-Fi attack surface added
        - Exactly 4 Wi-Fi threats generated (Spoofing, Tampering, Info Disclosure, DoS)
        - Exactly 13 retained threats without duplicates
        - ONLY relevant test (TC-WIFI-04) marked NEEDS_REVALIDATION
        - All other tests (TC-CAN-01, TC-ETH-02, TC-BLE-03, TC-UDS-05, TC-AUT-06) remain NOT_RUN
        """
        v1 = load_baseline()
        v2 = json.loads(json.dumps(v1))
        v2["system"] = "Connected Vehicle V2 (Wi-Fi Enabled)"
        v2["interfaces"].append({
            "source": "infotainment",
            "target": "external",
            "protocol": "Wi-Fi"
        })

        status, diff = api_request("POST", "/api/compare", {"baseline": v1, "target": v2})
        self.assertEqual(status, 200)

        # 1. Interface delta
        added_ifaces = diff["changes"]["interfaces"]["added"]
        self.assertEqual(len(added_ifaces), 1)
        self.assertEqual(added_ifaces[0]["source"], "infotainment")
        self.assertEqual(added_ifaces[0]["target"], "external")
        self.assertEqual(added_ifaces[0]["protocol"], "Wi-Fi")
        self.assertEqual(len(diff["changes"]["interfaces"]["removed"]), 0)
        self.assertEqual(len(diff["changes"]["interfaces"]["modified"]), 0)
        self.assertEqual(diff["changes"]["interfaces"]["unchanged_count"], 4)

        # 2. Attack surface delta
        added_surfaces = diff["attack_surface_delta"]["added"]
        self.assertEqual(len(added_surfaces), 1)
        self.assertEqual(added_surfaces[0]["protocol"], "Wi-Fi")
        self.assertEqual(added_surfaces[0]["type"], "External")
        self.assertEqual(diff["attack_surface_delta"]["retained_count"], 4)

        # 3. Threats delta
        new_threats = diff["threat_delta"]["new_threats"]
        self.assertEqual(len(new_threats), 4)
        new_categories = {t["stride_category"] for t in new_threats}
        self.assertEqual(new_categories, {"Spoofing", "Tampering", "Information Disclosure", "Denial of Service"})
        for t in new_threats:
            self.assertEqual(t["protocol"], "Wi-Fi")
            self.assertEqual(t["source"], "infotainment")
            self.assertEqual(t["target"], "external")

        # Retained threats count
        self.assertEqual(diff["threat_delta"]["retained_count"], 13)
        self.assertEqual(len(diff["threat_delta"]["removed_threats"]), 0)
        self.assertEqual(len(diff["threat_delta"]["modified_threats"]), 0)

        # 4. Security test impact: ONLY TC-WIFI-04 needs revalidation
        tests = {t["id"]: t for t in diff["security_tests"]}
        self.assertEqual(tests["TC-WIFI-04"]["status"], "NEEDS_REVALIDATION")
        self.assertTrue(tests["TC-WIFI-04"]["needs_revalidation"])
        self.assertEqual(tests["TC-WIFI-04"]["new_threat_count"], 4)

        # Every other test MUST be NOT_RUN
        for other_id in ("TC-CAN-01", "TC-ETH-02", "TC-BLE-03", "TC-UDS-05", "TC-AUT-06"):
            self.assertEqual(tests[other_id]["status"], "NOT_RUN", f"{other_id} must be NOT_RUN")
            self.assertFalse(tests[other_id]["needs_revalidation"])

    # =================================================================
    # 3. ADDITIONAL TEST CASES (REQ 3)
    # =================================================================
    def test_04_no_architecture_changes(self):
        """Comparing identical architectures produces 0 diffs and 0 revalidations."""
        v1 = load_baseline()
        status, diff = api_request("POST", "/api/compare", {"baseline": v1, "target": v1})
        self.assertEqual(status, 200)

        self.assertEqual(len(diff["changes"]["components"]["added"]), 0)
        self.assertEqual(len(diff["changes"]["components"]["removed"]), 0)
        self.assertEqual(diff["changes"]["components"]["unchanged_count"], 4)

        self.assertEqual(len(diff["changes"]["interfaces"]["added"]), 0)
        self.assertEqual(len(diff["changes"]["interfaces"]["removed"]), 0)
        self.assertEqual(diff["changes"]["interfaces"]["unchanged_count"], 4)

        self.assertEqual(len(diff["attack_surface_delta"]["added"]), 0)
        self.assertEqual(len(diff["attack_surface_delta"]["removed"]), 0)
        self.assertEqual(diff["attack_surface_delta"]["retained_count"], 4)

        self.assertEqual(len(diff["threat_delta"]["new_threats"]), 0)
        self.assertEqual(len(diff["threat_delta"]["removed_threats"]), 0)
        self.assertEqual(diff["threat_delta"]["retained_count"], 13)

        for t in diff["security_tests"]:
            self.assertEqual(t["status"], "NOT_RUN")
            self.assertFalse(t["needs_revalidation"])

    def test_05_removing_an_interface(self):
        """Removing Bluetooth interface removes 3 threats and flags TC-BLE-03."""
        v1 = load_baseline()
        v2 = json.loads(json.dumps(v1))
        v2["interfaces"] = [i for i in v2["interfaces"] if i["protocol"] != "Bluetooth"]

        status, diff = api_request("POST", "/api/compare", {"baseline": v1, "target": v2})
        self.assertEqual(status, 200)

        self.assertEqual(len(diff["changes"]["interfaces"]["removed"]), 1)
        self.assertEqual(diff["changes"]["interfaces"]["removed"][0]["protocol"], "Bluetooth")
        self.assertEqual(len(diff["attack_surface_delta"]["removed"]), 1)
        self.assertEqual(len(diff["threat_delta"]["removed_threats"]), 3)
        self.assertEqual(diff["threat_delta"]["retained_count"], 10)

        tests = {t["id"]: t for t in diff["security_tests"]}
        self.assertEqual(tests["TC-BLE-03"]["status"], "NEEDS_REVALIDATION")
        self.assertEqual(tests["TC-CAN-01"]["status"], "NOT_RUN")

    def test_06_modifying_interface_protocol(self):
        """Modifying Ethernet to CAN triggers both TC-ETH-02 and TC-CAN-01."""
        v1 = load_baseline()
        v2 = json.loads(json.dumps(v1))
        for iface in v2["interfaces"]:
            if iface["protocol"] == "Ethernet":
                iface["protocol"] = "CAN"

        status, diff = api_request("POST", "/api/compare", {"baseline": v1, "target": v2})
        self.assertEqual(status, 200)

        mod_ifaces = diff["changes"]["interfaces"]["modified"]
        self.assertEqual(len(mod_ifaces), 1)
        self.assertEqual(mod_ifaces[0]["old_protocol"], "Ethernet")
        self.assertEqual(mod_ifaces[0]["new_protocol"], "CAN")
        self.assertEqual(len(diff["threat_delta"]["new_threats"]), 3)
        self.assertEqual(
            {finding["protocol"] for finding in diff["threat_delta"]["new_threats"]},
            {"CAN"},
        )
        self.assertEqual(len(diff["threat_delta"]["removed_threats"]), 4)
        self.assertEqual(
            {finding["protocol"] for finding in diff["threat_delta"]["removed_threats"]},
            {"Ethernet"},
        )
        self.assertEqual(diff["threat_delta"]["modified_threats"], [])

        tests = {t["id"]: t for t in diff["security_tests"]}
        self.assertEqual(tests["TC-ETH-02"]["status"], "NEEDS_REVALIDATION")
        self.assertEqual(tests["TC-CAN-01"]["status"], "NEEDS_REVALIDATION")

    def test_07_adding_a_component(self):
        """Adding a component is detected in component additions."""
        v1 = load_baseline()
        v2 = json.loads(json.dumps(v1))
        v2["components"].append({
            "id": "telematics",
            "name": "Telematics ECU",
            "type": "ECU"
        })

        status, diff = api_request("POST", "/api/compare", {"baseline": v1, "target": v2})
        self.assertEqual(status, 200)
        self.assertEqual(len(diff["changes"]["components"]["added"]), 1)
        self.assertEqual(diff["changes"]["components"]["added"][0]["id"], "telematics")
        self.assertEqual(diff["changes"]["components"]["unchanged_count"], 4)

    # =================================================================
    # 4. INPUT VALIDATION & ERROR HANDLING (REQ 3)
    # =================================================================
    def test_08_empty_architecture_rejection(self):
        """Empty architecture is rejected with 400 Bad Request."""
        status, body = api_request("POST", "/api/analyze", {"system": "Empty", "components": [], "interfaces": []})
        self.assertEqual(status, 400)
        self.assertIn("cannot be empty", body.get("detail", ""))

    def test_09_missing_system_name_rejection(self):
        """Missing or blank system name is rejected with 400."""
        status, body = api_request("POST", "/api/analyze", {"system": "   ", "components": [{"id": "c1", "name": "C1"}]})
        self.assertEqual(status, 400)
        self.assertIn("'system' name is required", body.get("detail", ""))

    def test_10_missing_component_fields_rejection(self):
        """Component missing id or name is rejected with 400."""
        bad_arch = {
            "system": "Vehicle",
            "components": [{"name": "Missing ID"}],
            "interfaces": [{"source": "c1", "target": "c2", "protocol": "CAN"}]
        }
        status, body = api_request("POST", "/api/analyze", bad_arch)
        self.assertEqual(status, 400)
        self.assertIn("missing required field 'id'", body.get("detail", ""))

    def test_11_missing_interface_fields_rejection(self):
        """Interface missing protocol is rejected with 400 or 422."""
        bad_arch = {
            "system": "Vehicle",
            "components": [{"id": "c1", "name": "C1"}],
            "interfaces": [{"source": "c1", "target": "c2"}]
        }
        status, body = api_request("POST", "/api/analyze", bad_arch)
        self.assertIn(status, (400, 422))

    def test_12_duplicate_component_identifiers_rejection(self):
        """Duplicate component IDs are rejected with 400."""
        bad_arch = {
            "system": "Vehicle",
            "components": [
                {"id": "gateway", "name": "Gateway ECU"},
                {"id": "gateway", "name": "Duplicate Gateway ECU"},
            ],
            "interfaces": [{"source": "gateway", "target": "external", "protocol": "Bluetooth"}]
        }
        status, body = api_request("POST", "/api/analyze", bad_arch)
        self.assertEqual(status, 400)
        self.assertIn("duplicate component identifier", body.get("detail", "").lower())

    def test_13_duplicate_interfaces_rejection(self):
        """Duplicate interface definitions are rejected with 400."""
        bad_arch = {
            "system": "Vehicle",
            "components": [
                {"id": "gateway", "name": "Gateway ECU"},
                {"id": "engine", "name": "Engine ECU"},
            ],
            "interfaces": [
                {"source": "gateway", "target": "engine", "protocol": "CAN"},
                {"source": "gateway", "target": "engine", "protocol": "CAN"},
            ]
        }
        status, body = api_request("POST", "/api/analyze", bad_arch)
        self.assertEqual(status, 400)
        self.assertIn("duplicate interface definition", body.get("detail", "").lower())

    def test_14_interface_self_loop_rejection(self):
        """Interface where source == target is rejected with 400."""
        bad_arch = {
            "system": "Vehicle",
            "components": [{"id": "gateway", "name": "Gateway ECU"}],
            "interfaces": [{"source": "gateway", "target": "gateway", "protocol": "CAN"}]
        }
        status, body = api_request("POST", "/api/analyze", bad_arch)
        self.assertEqual(status, 400)
        self.assertIn("identical source and target", body.get("detail", ""))

    def test_15_repeated_comparison_requests_deterministic(self):
        """Multiple comparison requests with same input return deterministic identical results."""
        v1 = load_baseline()
        v2 = json.loads(json.dumps(v1))
        v2["interfaces"].append({"source": "infotainment", "target": "external", "protocol": "Wi-Fi"})

        status1, res1 = api_request("POST", "/api/compare", {"baseline": v1, "target": v2})
        self.assertEqual(status1, 200)

        for _ in range(5):
            status_n, res_n = api_request("POST", "/api/compare", {"baseline": v1, "target": v2})
            self.assertEqual(status_n, 200)
            self.assertEqual(res_n["threat_delta"]["new_threats"], res1["threat_delta"]["new_threats"])
            self.assertEqual(res_n["attack_surface_delta"]["added"], res1["attack_surface_delta"]["added"])
            self.assertEqual(len(res_n["security_tests"]), len(res1["security_tests"]))

    # =================================================================
    # 5. AUDIT THREAT COMPARISON KEYS (REQ 4)
    # =================================================================
    def test_16_threat_identity_order_invariance(self):
        """Threat identity does not depend on auto-generated ID or list order."""
        v1 = load_baseline()
        v2 = json.loads(json.dumps(v1))
        # Reverse interface order in V2
        v2["interfaces"] = list(reversed(v2["interfaces"]))

        diff = compare_architectures(v1, v2)
        self.assertEqual(len(diff["threat_delta"]["new_threats"]), 0)
        self.assertEqual(len(diff["threat_delta"]["removed_threats"]), 0)
        self.assertEqual(diff["threat_delta"]["retained_count"], 13)

    def test_17_threat_property_modification_detection(self):
        """Threat property modification is tracked in modified_threats."""
        v1 = load_baseline()
        old_analysis = analyze_architecture(v1)
        new_analysis = json.loads(json.dumps(old_analysis))
        new_analysis["security_findings"][0]["risk_score"] = 72
        new_analysis["security_findings"][0]["description"] = "Updated finding description"

        with patch(
            "backend.comparison_engine.analyze_architecture",
            side_effect=(old_analysis, new_analysis),
        ):
            diff = compare_architectures(v1, v1)

        modified = diff["threat_delta"]["modified_threats"]
        self.assertEqual(len(modified), 1)
        self.assertEqual(
            modified[0]["changes"]["risk_score"],
            {"old": 78, "new": 72},
        )
        self.assertEqual(
            modified[0]["changes"]["description"],
            {"old": old_analysis["security_findings"][0]["description"], "new": "Updated finding description"},
        )

    # =================================================================
    # 6. AUDIT TEST EXECUTION & SIMULATION TRANSPARENCY (REQ 5, 6, 7)
    # =================================================================
    def test_18_simulated_execution_audit(self):
        """
        Test execution harness:
        - Labels execution mode as SIMULATED
        - Discloses simulated outcome vs physical hardware bench requirement
        - Stores execution_mode, test_result, target_architecture_version, timestamp, evidence
        - Marks unconfigured protocols as NOT_APPLICABLE rather than claiming false pass
        """
        v1 = load_baseline()
        results = execute_test_suite(["TC-CAN-01", "TC-WIFI-04"], v1)
        res_map = {r["id"]: r for r in results}

        # TC-CAN-01 (CAN interfaces present in V1)
        tc_can = res_map["TC-CAN-01"]
        self.assertEqual(tc_can["execution_mode"], "SIMULATED")
        self.assertEqual(tc_can["status"], "PASSED")
        self.assertEqual(tc_can["test_result"], "PASS")
        self.assertEqual(tc_can["target_architecture_version"], "Connected Vehicle")
        self.assertIsNotNone(tc_can["last_run_timestamp"])
        self.assertIn("SIMULATED", tc_can["evidence"])
        self.assertIn("Vector CANoe", tc_can["evidence"])
        self.assertIn("[SIMULATION MODE]", tc_can["execution_log"])

        # TC-WIFI-04 (Wi-Fi NOT present in V1)
        tc_wifi = res_map["TC-WIFI-04"]
        self.assertEqual(tc_wifi["execution_mode"], "SIMULATED")
        self.assertEqual(tc_wifi["status"], "NOT_APPLICABLE")
        self.assertEqual(tc_wifi["test_result"], "NOT_APPLICABLE")
        self.assertIn("NOT APPLICABLE", tc_wifi["evidence"])

    def test_19_api_execute_tests_endpoint(self):
        """POST /api/execute-tests endpoint returns simulated execution logs and evidence."""
        v1 = load_baseline()
        status, data = api_request("POST", "/api/execute-tests", {
            "test_ids": ["TC-CAN-01"],
            "architecture": v1
        })
        self.assertEqual(status, 200)
        self.assertEqual(len(data["executed_tests"]), 1)
        t = data["executed_tests"][0]
        self.assertEqual(t["id"], "TC-CAN-01")
        self.assertEqual(t["execution_mode"], "SIMULATED")
        self.assertEqual(t["status"], "PASSED")
        self.assertIn("SIMULATED", t["evidence"])

    def test_20_affected_test_cannot_remain_pass_without_revalidation(self):
        """
        Verify Requirement 7:
        When a test is affected by an architecture change, its status MUST BE NEEDS_REVALIDATION.
        A prior execution PASS cannot persist as valid without revalidation against the new architecture version.
        """
        v1 = load_baseline()
        # Suppose TC-CAN-01 was executed and passed on V1
        initial_run = execute_test_suite(["TC-CAN-01"], v1)[0]
        self.assertEqual(initial_run["status"], "PASSED")

        # Now V2 modifies the CAN interface or adds a CAN interface to gateway
        v2 = json.loads(json.dumps(v1))
        v2["system"] = "Connected Vehicle V2 (Modified CAN)"
        v2["interfaces"].append({
            "source": "gateway",
            "target": "external",
            "protocol": "CAN"
        })

        diff = compare_architectures(v1, v2)
        tests = {t["id"]: t for t in diff["security_tests"]}

        # TC-CAN-01 MUST transition to NEEDS_REVALIDATION
        self.assertEqual(tests["TC-CAN-01"]["status"], "NEEDS_REVALIDATION")
        self.assertTrue(tests["TC-CAN-01"]["needs_revalidation"])

        # Emulate frontend combinedSecurityTests logic:
        # A test whose needs_revalidation is True CANNOT retain the stale PASS
        executed_cache = {"TC-CAN-01": initial_run}
        test_obj = tests["TC-CAN-01"]

        # If needs_revalidation is True, status remains NEEDS_REVALIDATION
        combined_status = (
            initial_run["status"]
            if (not test_obj["needs_revalidation"] and initial_run["target_architecture_version"] == v2["system"])
            else test_obj["status"]
        )
        self.assertEqual(combined_status, "NEEDS_REVALIDATION")
        self.assertNotEqual(combined_status, "PASSED")

    def test_21_multiple_protocol_changes_pair_removed_interfaces_once(self):
        """Protocol changes on one endpoint pair each removed interface at most once."""
        v1 = load_baseline()
        v1["interfaces"].append({
            "source": "gateway",
            "target": "engine",
            "protocol": "Ethernet",
        })
        v2 = json.loads(json.dumps(v1))
        v2["interfaces"] = [
            iface for iface in v2["interfaces"]
            if not (
                iface["source"] == "gateway"
                and iface["target"] == "engine"
                and iface["protocol"] in ("CAN", "Ethernet")
            )
        ]
        v2["interfaces"].extend([
            {"source": "gateway", "target": "engine", "protocol": "Wi-Fi"},
            {"source": "gateway", "target": "engine", "protocol": "Diagnostic"},
        ])

        diff = compare_architectures(v1, v2)
        interface_changes = diff["changes"]["interfaces"]
        self.assertEqual(len(interface_changes["modified"]), 2)
        self.assertEqual(len(interface_changes["added"]), 0)
        self.assertEqual(len(interface_changes["removed"]), 0)
        self.assertEqual(
            {change["old_protocol"] for change in interface_changes["modified"]},
            {"CAN", "Ethernet"},
        )
        self.assertEqual(
            {change["new_protocol"] for change in interface_changes["modified"]},
            {"Wi-Fi", "Diagnostic"},
        )

    def test_22_execution_timestamp_is_timezone_aware_utc(self):
        result = execute_test_suite(["TC-CAN-01"], load_baseline())[0]
        timestamp = datetime.fromisoformat(result["last_run_timestamp"])
        self.assertIsNotNone(timestamp.tzinfo)
        self.assertEqual(timestamp.utcoffset().total_seconds(), 0)


if __name__ == "__main__":
    unittest.main()

