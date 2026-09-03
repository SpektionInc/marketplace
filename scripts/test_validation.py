#!/usr/bin/env python3
"""Regression tests for marketplace validation and acceptance gates."""

import importlib.util
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

    def test_parameter_linter_rejects_invalid_boolean_and_cross_tool_param(self):
        contract = parity.load_contract()
        errors = []
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            skill_dir = root / "skills" / "example"
            skill_dir.mkdir(parents=True)
            (skill_dir / "SKILL.md").write_text(
                "Call `search_assets` with `is_online: maybe` and `offset: 3`.\n")
            old_root, old_skills = parity.REPO_ROOT, parity.SKILLS_DIR
            try:
                parity.REPO_ROOT = root
                parity.SKILLS_DIR = root / "skills"
                parity.validate_skill_params(contract, parity.tools_by_name(contract), errors)
            finally:
                parity.REPO_ROOT, parity.SKILLS_DIR = old_root, old_skills
        self.assertTrue(any("invalid literal" in error for error in errors), errors)
        self.assertTrue(any("unknown parameter" in error for error in errors), errors)

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
