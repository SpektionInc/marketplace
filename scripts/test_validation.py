#!/usr/bin/env python3
"""Regression tests for marketplace validation and acceptance gates."""

import importlib.util
import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


parity = load_module("parity_check", REPO_ROOT / "scripts" / "parity_check.py")
smoke = load_module(
    "contract_smoke", REPO_ROOT / "plugins" / "spektion" / "scripts" / "contract_smoke.py")


class ValidationRegressionTests(unittest.TestCase):
    def test_tool_regex_returns_complete_tool_name(self):
        self.assertEqual(parity.TOOL_RE.findall("Call search_assets now"), ["search_assets"])
        self.assertEqual(parity.TOOL_RE.findall("Call count_ai_session_detections"),
                         ["count_ai_session_detections"])

    def fixture(self, name):
        return json.loads((smoke.DEFAULT_FIXTURES / f"{name}.json").read_text())

    def test_census_and_chat_only_tools_are_checked_in_skill_references(self):
        errors = []
        parity.scan_tool_references("count_ai_session_detection search_ai_inventory", "skill",
                                    parity.tools_by_name(parity.load_contract()), errors)
        self.assertEqual(len(errors), 2)

    def test_array_elements_and_scalar_detection_ids_are_rejected(self):
        contract = smoke.load_contract()
        for value in ("DET-AI-1020", [123], [True]):
            with self.subTest(value=value):
                fx = self.fixture("call_search_ai_sessions")
                fx["request"]["params"]["arguments"]["detection_id"] = value
                with self.assertRaises(AssertionError):
                    smoke.assert_tool_call_request(contract, fx)
        fx = self.fixture("call_count_ai_session_detections")
        fx["request"]["params"]["arguments"]["asset_importance"] = [True]
        with self.assertRaisesRegex(AssertionError, "array item type"):
            smoke.assert_tool_call_request(contract, fx)

    def test_discovery_rejects_missing_array_item_schema(self):
        result = self.fixture("tools_list")["response"]["result"]
        tool = next(t for t in result["tools"] if t["name"] == "search_ai_sessions")
        del tool["inputSchema"]["properties"]["detection_id"]["items"]
        with self.assertRaisesRegex(AssertionError, "array item type"):
            smoke.assert_tools_list(smoke.load_contract(), result)

    def test_census_counts_can_overlap_but_cannot_exceed_denominators(self):
        fx = self.fixture("call_count_ai_session_detections")
        doc = smoke.assert_tool_result("count_ai_session_detections", fx["response"])
        self.assertGreater(sum(r["session_count"] for r in doc["items"]),
                           doc["sessions_with_detections"])
        for key, value in (("distinct_by", "occurrence"), ("returned", 99),
                           ("sessions_total", 1), ("sessions_total", True)):
            with self.subTest(key=key):
                invalid = copy.deepcopy(doc)
                invalid[key] = value
                with self.assertRaises(AssertionError):
                    smoke.assert_census(invalid)
        invalid = copy.deepcopy(doc)
        invalid["items"][0]["session_count"] = 101
        with self.assertRaises(AssertionError):
            smoke.assert_census(invalid)
        for total in (0, 100):
            smoke.assert_census({"items": [], "distinct_by": "session", "returned": 0,
                                 "sessions_total": total, "sessions_with_detections": 0})

    def fake_live(self, mismatch=False, secret_mismatch=False):
        calls = []

        def post(_url, headers, request, expect_response=True):
            method = request["method"]
            if method != "initialize":
                self.assertEqual(headers["Mcp-Protocol-Version"], "2025-03-26")
            if not expect_response:
                self.assertNotIn("id", request)
                return None, None
            if method == "tools/call":
                name = request["params"]["name"]
                smoke.assert_tool_call_request(smoke.load_contract(), {
                    "request": request, "response": {"jsonrpc": "2.0", "id": request["id"]}})
                calls.append(request["params"])
                response = self.fixture("call_" + name)["response"]
                if mismatch and name == "search_ai_sessions":
                    doc = json.loads(response["result"]["content"][0]["text"])
                    doc["total_count"] += 1
                    response["result"]["content"][0]["text"] = json.dumps(doc)
                if secret_mismatch and name == "search_secrets" and "detector_id" in request["params"]["arguments"]:
                    doc = json.loads(response["result"]["content"][0]["text"])
                    doc["total_count"] += 1
                    response["result"]["content"][0]["text"] = json.dumps(doc)
                return None, response
            if method in {"resources/read", "prompts/get"}:
                key = "uri" if method == "resources/read" else "name"
                fx = self.fixture(method.replace("/", "_"))
                return None, next(case["response"] for case in fx["cases"]
                                  if case["request"]["params"][key] == request["params"][key])
            return None, self.fixture(method.replace("/", "_"))["response"]

        with mock.patch.dict(smoke.os.environ, {"SPEKTION_MCP_URL": "https://example.invalid/mcp",
                                               "SPEKTION_API_KEY": "fixture-key"}), \
                mock.patch.object(smoke, "_post", side_effect=post):
            result = smoke.run_live(smoke.load_contract())
        return result, calls

    def test_live_exercises_every_tool_and_discovers_exact_drill_through_args(self):
        (code, errors), calls = self.fake_live()
        self.assertEqual((code, errors), (0, []))
        by_name = {call["name"]: call["arguments"] for call in calls}
        self.assertEqual(set(by_name), set(smoke.contract_by_name(smoke.load_contract())))
        self.assertEqual(by_name["search_secrets"]["asset_id"], "fixture-asset-001")
        self.assertNotIn("hostname", by_name["search_secrets"])
        self.assertEqual(by_name["search_ai_sessions"]["detection_id"], ["DET-AI-1020"])
        self.assertEqual(by_name["search_ai_sessions"]["recency_days"],
                         by_name["count_ai_session_detections"]["recency_days"])
        self.assertEqual(by_name["get_tenant_settings"], {})
        self.assertEqual(by_name["search_secrets"]["detector_id"], "SEC-JWT-001")
        self.assertEqual(by_name["count_secrets_by_detector"]["asset_id"],
                         by_name["search_secrets"]["asset_id"])
        self.assertEqual(by_name["get_ai_session_artifacts"]["session_id"],
                         "11111111-1111-4111-8111-111111111111")
        expected_hash = json.loads(self.fixture("call_search_executables")
                                  ["response"]["result"]["content"][0]["text"])["items"][0]["hash"]
        self.assertEqual(by_name["get_executable_details"]["hash"], expected_hash)

    def test_live_fails_on_census_drill_through_count_mismatch(self):
        (code, errors), _ = self.fake_live(mismatch=True)
        self.assertEqual(code, 1)
        self.assertTrue(any("census/session total mismatch" in error for error in errors), errors)

    def test_parameter_linter_rejects_invalid_boolean_and_cross_tool_param(self):
        contract = parity.load_contract()
        errors = []
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            skill_dir = root / "skills" / "example"
            skill_dir.mkdir(parents=True)
            (skill_dir / "SKILL.md").write_text(
                "Call `search_assets` with `is_online: maybe` and `hash: invented`.\n")
            old_root, old_skills = parity.REPO_ROOT, parity.SKILLS_DIR
            try:
                parity.REPO_ROOT = root
                parity.SKILLS_DIR = root / "skills"
                parity.validate_skill_params(contract, parity.tools_by_name(contract), errors)
            finally:
                parity.REPO_ROOT, parity.SKILLS_DIR = old_root, old_skills
        self.assertTrue(any("invalid literal" in error for error in errors), errors)
        self.assertTrue(any("unknown parameter" in error for error in errors), errors)

    def test_secret_census_allows_unidentified_findings_and_overlapping_assets(self):
        doc = json.loads(self.fixture("call_count_secrets_by_detector")
                         ["response"]["result"]["content"][0]["text"])
        doc["findings_total"] = 4
        doc["items"].append({"detector_id": "SEC-OTHER", "detector_name": "Other",
                             "finding_count": 1, "asset_count": 1})
        doc["count"] = doc["detectors_total"] = 2
        smoke.assert_secret_census(doc)
        for key, value in (("assets_scanned_for_secrets", 0), ("count", 99),
                           ("findings_total", 2), ("truncated", True)):
            with self.subTest(key=key):
                invalid = copy.deepcopy(doc)
                invalid[key] = value
                with self.assertRaises(AssertionError):
                    smoke.assert_secret_census(invalid)

    def test_live_fails_on_secret_detector_count_mismatch(self):
        (code, errors), _ = self.fake_live(secret_mismatch=True)
        self.assertEqual(code, 1)
        self.assertTrue(any("secret census/detector findings total mismatch" in e for e in errors), errors)

    def test_artifact_absence_states_and_paging_are_validated(self):
        doc = json.loads(self.fixture("call_get_ai_session_artifacts")
                         ["response"]["result"]["content"][0]["text"])
        invalid = copy.deepcopy(doc)
        invalid["items"][0]["linked_to_executable"] = "false"
        with self.assertRaisesRegex(AssertionError, "linked_to_executable"):
            smoke.assert_artifacts(invalid)
        invalid = copy.deepcopy(doc)
        invalid["truncated"] = True
        with self.assertRaisesRegex(AssertionError, "truncated"):
            smoke.assert_artifacts(invalid)
        doc.update(items=[], total_count=0, returned=0,
                   artifacts_state="compiler_activity_without_recorded_artifacts")
        smoke.assert_artifacts(doc)
        doc["artifacts_state"] = "artifacts_listed"
        with self.assertRaisesRegex(AssertionError, "state disagrees"):
            smoke.assert_artifacts(doc)

    def test_current_secret_arguments_reject_obsolete_severity(self):
        fx = self.fixture("call_search_secrets")
        fx["request"]["params"]["arguments"].update(detector_id="SEC-JWT-001", offset=1)
        smoke.assert_tool_call_request(smoke.load_contract(), fx)
        fx["request"]["params"]["arguments"]["severity"] = "high"
        with self.assertRaisesRegex(AssertionError, "unknown arguments"):
            smoke.assert_tool_call_request(smoke.load_contract(), fx)

    def test_scope_operator_casing_matches_wire_enum(self):
        spec = parity.tools_by_name(parity.load_contract())["search_assets"]
        allowed = parity.enum_for(spec, "asset_tags_op")
        self.assertIn(parity.normalize('"notEqual"'), allowed)
        self.assertNotIn(parity.normalize('"notequal"'), allowed)

    def test_secret_findings_can_have_incomplete_detector_identity(self):
        response = self.fixture("call_search_secrets")["response"]
        doc = json.loads(response["result"]["content"][0]["text"])
        del doc["items"][0]["detector_id"]
        del doc["items"][0]["detector_name"]
        response["result"]["content"][0]["text"] = json.dumps(doc)
        smoke.assert_tool_result("search_secrets", response)

    def test_fixture_suite_fails_when_tool_calls_are_removed(self):
        source = REPO_ROOT / "plugins" / "spektion" / "scripts" / "fixtures"
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            for name in ("initialize.json", "tools_list.json", "resources_list.json",
                         "prompts_list.json"):
                shutil.copy(source / name, target / name)
            _, errors = smoke.run_fixtures(target, smoke.load_contract())
        self.assertTrue(any("coverage missing" in error for error in errors), errors)

    def test_notification_has_no_id_and_accepts_empty_202(self):
        notification = smoke._notification("notifications/initialized")
        self.assertNotIn("id", notification)

        class Response:
            status = 202
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return b""

        with mock.patch.object(smoke.urllib.request, "urlopen", return_value=Response()):
            session, response = smoke._post(
                "https://example.invalid/mcp", {}, notification, expect_response=False)
        self.assertIsNone(session)
        self.assertIsNone(response)

    def test_contract_provenance_is_a_full_commit(self):
        contract = json.loads(smoke.CONTRACT_PATH.read_text())
        source = contract["source"]
        self.assertEqual(source["repository"], parity.SOURCE_REPOSITORY)
        self.assertRegex(source["revision"], r"^[0-9a-f]{40}$")

    def test_placeholder_sla_resource_is_rejected(self):
        response = {
            "result": {"contents": [{
                "uri": "spektion://sla-policy",
                "text": '{"message":"SLA policy will be available in a future update"}',
            }]},
        }
        with self.assertRaisesRegex(AssertionError, "missing keys"):
            smoke.assert_resource_result("spektion://sla-policy", response)

    def test_stale_prompt_body_is_rejected(self):
        response = {
            "result": {"messages": [{
                "role": "user",
                "content": {"type": "text", "text": "Use search_endpoints by risk_count."},
            }]},
        }
        with self.assertRaises(AssertionError):
            smoke.assert_prompt_result("security_review", response)


if __name__ == "__main__":
    unittest.main()
