#!/usr/bin/env python3
"""Deterministic MCP contract smoke tester for the Spektion plugin.

Two modes:

  --fixtures <dir>   (default) Replays curated JSON-RPC contract cases from the
                     fixtures directory and asserts the MCP surface matches the
                     pinned contract (plugins/spektion/contract/mcp-contract.json).
                     Deterministic; used by CI. No network, no credentials.

  --live             Connects to a real MCP server using the SPEKTION_MCP_URL and
                     SPEKTION_API_KEY environment variables (protocol 2025-03-26),
                     enumerates and exercises tools/resources/prompts, makes one
                     representative call per tool, and validates the results.

Exit codes: 0 = pass, 1 = fail, 2 = required environment missing.
"""

import argparse
import json
import os
import re
import sys
import urllib.request
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
CONTRACT_PATH = REPO_ROOT / "plugins" / "spektion" / "contract" / "mcp-contract.json"
DEFAULT_FIXTURES = Path(__file__).resolve().parent / "fixtures"

CORE_FIXTURES = {
    "initialize", "tools_list", "resources_list", "prompts_list",
    "resources_read", "prompts_get",
}

RESOURCE_URIS = {
    "spektion://platforms",
    "spektion://software-categories",
    "spektion://software-publishers",
    "spektion://sla-policy",
    "spektion://detection-rules",
}

PROMPT_REQUIREMENTS = {
    "security_review": {"get_security_posture", "search_assets", "get_detection_controls"},
    "investigate_cve": {"get_vulnerability_details", "get_asset_details"},
    "endpoint_risk_assessment": {"get_asset_details", "get_detection_controls"},
    "vulnerability_report": {"get_remediation_metrics", "get_vulnerability_trends"},
    "software_risk_analysis": {"search_software", "get_software_details", "client-side"},
}

RETIRED_PROMPT_TERMS = {
    "search_endpoints", "get_endpoint_details", "query_detection_events",
    "query_software_inventory", "query_vulnerability_data", "risk_count",
}

# ---------------------------------------------------------------------------
# Per-tool response assertions: envelope keys on the parsed JSON and, for
# list-style tools, required fields on the first item of `items` (or the named
# key for non-`items` tools, e.g. get_asset_details.endpoint).
# ---------------------------------------------------------------------------

def _first(doc, key):
    v = doc.get(key)
    if isinstance(v, list) and v:
        return v[0]
    if isinstance(v, dict):
        return v
    return None

TOOL_ENVELOPE = {
    "count_ai_session_detections": {"keys": ["items", "distinct_by",
        "sessions_with_detections", "sessions_total", "returned"]},
    "get_security_posture": {"keys": ["total_assets", "active_assets", "assets_by_platform",
                                      "software_by_platform", "vulnerabilities_by_severity"]},
    "search_vulnerabilities": {"keys": ["items"], "items": ["cve_id", "severity", "score",
                                                            "endpoint_count", "sla_status"]},
    "search_assets": {"keys": ["items"], "items": ["hostname", "exposure_score",
                                                   "exposure_severity", "importance", "asset_id", "secret_count"]},
    "search_software": {"keys": ["items"], "items": ["name", "grade", "cve_count", "score"]},
    "search_detections": {"keys": ["items"], "items": ["id", "endpoint_count",
                                                       "software_count", "cve_likelihood"]},
    "search_network_activity": {"keys": ["destinations", "listeners"],
                                "items": ["destination_value", "activity_type",
                                          "connection_count"]},
    "search_secrets": {"keys": ["items"], "items": ["event_id", "rule_name", "severity"]},
    "search_ai_security_risks": {"keys": ["items"], "items": ["event_id", "source",
                                                              "rule_name", "severity"]},
    "search_executables": {"keys": ["items"], "items": ["hash", "is_signed", "asset_count"]},
    "search_ai_sessions": {"keys": ["items"], "items": ["session_id", "agent",
                                                        "severity_max", "asset_id", "detections"]},
    "query_sensors": {"keys": ["items", "total_count", "count", "offset", "summary"],
                      "items": ["sensor_id", "hostname", "os_family", "agent_version"]},
    "get_asset_details": {"keys": ["endpoint", "installed_software", "network_activity"],
                          "items": ["hostname", "exposure_score", "risks", "asset_id", "secret_count"]},
    "get_software_details": {"keys": ["items"], "items": ["software"]},
    "get_vulnerability_details": {"keys": ["cve_id", "severity", "score", "sla_status",
                                           "impacted_software", "impacted_endpoints"]},
    "get_detection_events": {"keys": ["items", "detection_id"],
                             "items": ["software_name", "process_path", "outputs"]},
    "get_detection_controls": {"keys": ["preventive_controls", "vendor_fix_only",
                                        "detective_control"]},
    "get_remediation_metrics": {"keys": ["median_days_to_remediate", "mean_days_to_remediate",
                                         "p10_days_to_remediate", "p90_days_to_remediate",
                                         "sla_compliance"]},
    "get_vulnerability_trends": {"keys": ["vulnerability_delta", "vulnerability_distribution",
                                          "cve_blindspot", "preemptive_cve"]},
    "get_tenant_settings": {"keys": ["sla_matrix", "kev_override",
                                             "default_asset_importance"]},
}

# First-item key for the dict-style tools (get_asset_details "endpoint" object).
ITEM_KEY = {
    "get_asset_details": "endpoint",
    "search_network_activity": "destinations",
    "get_software_details": "software",
}


def load_contract():
    with open(CONTRACT_PATH) as f:
        return json.load(f)


def contract_by_name(contract):
    return {t["name"]: t for t in contract["mcp"]["tools"]}


def assert_tools_list(contract, result):
    """Assert tools/list matches the pinned contract exactly."""
    tools = {t["name"]: t for t in result.get("tools", [])}
    expected = set(contract_by_name(contract))
    actual = set(tools)
    if actual != expected:
        raise AssertionError(
            "tools/list mismatch: missing=%s extra=%s" % (
                sorted(expected - actual), sorted(actual - expected)))
    for name, spec in contract_by_name(contract).items():
        t = tools[name]
        ann = t.get("annotations") or {}
        if ann.get("readOnlyHint") is not True:
            raise AssertionError(f"tool {name}: readOnlyHint not true")
        schema = t.get("inputSchema") or {}
        if schema.get("type") != "object":
            raise AssertionError(f"tool {name}: inputSchema.type != object")
        props = schema.get("properties") or {}
        exp_params = {p["name"]: p for p in spec["params"]}
        if set(props) != set(exp_params):
            raise AssertionError(
                f"tool {name}: inputSchema.properties mismatch: missing=%s extra=%s" % (
                    sorted(set(exp_params) - set(props)),
                    sorted(set(props) - set(exp_params))))
        for pname, p in exp_params.items():
            expected_type = p.get("mcp_type", p["type"])
            if props[pname].get("type") != expected_type:
                raise AssertionError(
                    f"tool {name}.{pname}: type {props[pname].get('type')} != {expected_type}")
            value_schema = props[pname]
            if p["type"] == "array":
                value_schema = props[pname].get("items") or {}
                if value_schema.get("type") != p.get("item_type"):
                    raise AssertionError(f"tool {name}.{pname}: array item type mismatch")
            if p.get("enum"):
                if sorted(value_schema.get("enum", [])) != sorted(p["enum"]):
                    raise AssertionError(
                        f"tool {name}.{pname}: enum mismatch "
                        f"{props[pname].get('enum')} != {p['enum']}")
        exp_required = sorted(p["name"] for p in spec["params"] if p["required"])
        if sorted(schema.get("required", [])) != exp_required:
            raise AssertionError(
                f"tool {name}: required mismatch {schema.get('required')} != {exp_required}")


def assert_resources_list(contract, result):
    res = {r["uri"]: r for r in result.get("resources", [])}
    expected = {r["uri"]: r for r in contract["resources"]}
    if set(res) != set(expected):
        raise AssertionError(
            "resources/list mismatch: missing=%s extra=%s" % (
                sorted(set(expected) - set(res)), sorted(set(res) - set(expected))))
    for uri, r in expected.items():
        if res[uri].get("name") != r["name"]:
            raise AssertionError(f"resource {uri}: name mismatch")
        if res[uri].get("description") != r["registration_description"]:
            raise AssertionError(f"resource {uri}: registration description mismatch")


def assert_prompts_list(contract, result):
    prompts = {p["name"]: p for p in result.get("prompts", [])}
    expected = {p["name"]: p for p in contract["prompts"]}
    if set(prompts) != set(expected):
        raise AssertionError(
            "prompts/list mismatch: missing=%s extra=%s" % (
                sorted(set(expected) - set(prompts)),
                sorted(set(prompts) - set(expected))))
    for name, p in expected.items():
        if prompts[name].get("description") != p["description"]:
            raise AssertionError(f"prompt {name}: description mismatch")
        args = {a["name"]: a for a in prompts[name].get("arguments", [])}
        exp_args = {a["name"]: a for a in p["args"]}
        if set(args) != set(exp_args):
            raise AssertionError(
                f"prompt {name}: arguments mismatch missing=%s extra=%s" % (
                    sorted(set(exp_args) - set(args)),
                    sorted(set(args) - set(exp_args))))
        for aname, a in exp_args.items():
            if bool(args[aname].get("required")) != bool(a.get("required")):
                raise AssertionError(
                    f"prompt {name}.{aname}: required flag mismatch")


def _resource_text(uri, resp):
    if "error" in resp:
        raise AssertionError(f"resource {uri}: top-level JSON-RPC error: {resp['error']}")
    contents = (resp.get("result") or {}).get("contents") or []
    for item in contents:
        if item.get("uri") == uri and item.get("text") is not None:
            return item["text"]
    raise AssertionError(f"resource {uri}: matching text content not found")


def assert_resource_result(uri, resp):
    """Assert the behavior and response shape promised for a resource."""
    text = _resource_text(uri, resp)
    if uri == "spektion://platforms":
        platforms = [p.strip() for p in text.split(",") if p.strip()]
        if not platforms or any(p not in {"windows", "macos", "linux"} for p in platforms):
            raise AssertionError(f"resource {uri}: invalid platform list {text!r}")
        return

    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        raise AssertionError(f"resource {uri}: text is not JSON: {e}")

    if uri in {"spektion://software-categories", "spektion://software-publishers"}:
        if not isinstance(doc, list) or not doc:
            raise AssertionError(f"resource {uri}: expected a non-empty list")
        for item in doc:
            if not isinstance(item, dict) or set(("name", "count")) - set(item):
                raise AssertionError(f"resource {uri}: invalid count entry {item!r}")
    elif uri == "spektion://sla-policy":
        required = {"source", "sla_matrix", "kev_override", "default_asset_importance"}
        if not isinstance(doc, dict):
            raise AssertionError(f"resource {uri}: expected an object")
        if required - set(doc):
            raise AssertionError(f"resource {uri}: missing keys {sorted(required - set(doc))}")
        if doc["source"] not in {"tenant", "default"}:
            raise AssertionError(f"resource {uri}: invalid source {doc['source']!r}")
        if not isinstance(doc["sla_matrix"], dict) or not doc["sla_matrix"]:
            raise AssertionError(f"resource {uri}: sla_matrix must be a non-empty object")
    elif uri == "spektion://detection-rules":
        if not isinstance(doc, dict) or doc.get("status") != "loaded":
            raise AssertionError(f"resource {uri}: detection library is not loaded")


def _prompt_text(name, resp):
    if "error" in resp:
        raise AssertionError(f"prompt {name}: top-level JSON-RPC error: {resp['error']}")
    messages = (resp.get("result") or {}).get("messages") or []
    texts = []
    for message in messages:
        content = message.get("content") or {}
        if content.get("type") == "text" and content.get("text"):
            texts.append(content["text"])
    if not texts:
        raise AssertionError(f"prompt {name}: no text messages")
    return "\n".join(texts)


def assert_prompt_result(name, resp):
    """Assert prompt bodies use the current tools and preserve safety guidance."""
    text = _prompt_text(name, resp)
    missing = sorted(term for term in PROMPT_REQUIREMENTS[name] if term not in text)
    if missing:
        raise AssertionError(f"prompt {name}: missing required guidance {missing}")
    retired = sorted(
        term for term in RETIRED_PROMPT_TERMS
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(term)}(?![A-Za-z0-9_])", text))
    if retired:
        raise AssertionError(f"prompt {name}: contains retired guidance {retired}")


def extract_text(resp):
    result = resp.get("result") or {}
    for item in result.get("content", []):
        if isinstance(item, dict) and item.get("type") == "text":
            return item.get("text", "")
    return None


def assert_tool_result(tool_name, resp, require_schema=True):
    """Assert a tools/call response: no error, no isError, matching envelope."""
    if "error" in resp:
        raise AssertionError(f"tool {tool_name}: top-level JSON-RPC error: {resp['error']}")
    result = resp.get("result")
    if result is None:
        raise AssertionError(f"tool {tool_name}: missing result")
    if result.get("isError") is True:
        raise AssertionError(f"tool {tool_name}: MCP isError=true")
    text = extract_text(resp)
    if text is None or not text.strip():
        raise AssertionError(f"tool {tool_name}: no text content")
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        raise AssertionError(f"tool {tool_name}: content is not JSON: {e}")

    spec = TOOL_ENVELOPE.get(tool_name)
    if spec is None:
        raise AssertionError(f"tool {tool_name}: no envelope spec registered")
    for key in spec.get("keys", []):
        if key not in doc:
            raise AssertionError(f"tool {tool_name}: missing envelope key '{key}'")
    if tool_name == "count_ai_session_detections":
        assert_census(doc)
    item_keys = spec.get("items") or []
    if item_keys:
        first = doc.get("items") or doc.get(ITEM_KEY.get(tool_name))
        if isinstance(first, list):
            first = first[0] if first else None
        if not isinstance(first, dict):
            raise AssertionError(f"tool {tool_name}: expected items list, got {type(first)}")
        for key in item_keys:
            if key not in first:
                raise AssertionError(f"tool {tool_name}: first item missing '{key}'")
    return doc


def assert_census(doc):
    if doc["distinct_by"] != "session":
        raise AssertionError("census: distinct_by must be session")
    for key in ("sessions_total", "sessions_with_detections", "returned"):
        if not _type_matches(doc[key], "integer") or doc[key] < 0:
            raise AssertionError(f"census: invalid {key}")
    if doc["sessions_with_detections"] > doc["sessions_total"]:
        raise AssertionError("census: detected sessions exceed total sessions")
    if not isinstance(doc["items"], list) or doc["returned"] != len(doc["items"]):
        raise AssertionError("census: returned must match items length")
    ids = set()
    for row in doc["items"]:
        for key in ("detection_id", "detection_name"):
            if not isinstance(row.get(key), str) or not row[key]:
                raise AssertionError(f"census: missing {key}")
        count = row.get("session_count")
        if not _type_matches(count, "integer") or not 0 < count <= doc["sessions_with_detections"]:
            raise AssertionError("census: invalid session_count")
        if row["detection_id"] in ids:
            raise AssertionError("census: duplicate detection_id")
        ids.add(row["detection_id"])
    # Rule counts overlap. Their sum need not equal either denominator.


def _type_matches(value, expected):
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "array":
        return isinstance(value, list)
    return False


def assert_rpc_pair(fx, method):
    req = fx.get("request") or {}
    resp = fx.get("response") or {}
    if req.get("jsonrpc") != "2.0" or resp.get("jsonrpc") != "2.0":
        raise AssertionError("request/response jsonrpc must both be '2.0'")
    if req.get("method") != method:
        raise AssertionError(f"request method {req.get('method')!r} != {method!r}")
    if req.get("id") != resp.get("id"):
        raise AssertionError(f"response id {resp.get('id')!r} != request id {req.get('id')!r}")


def assert_tool_call_request(contract, fx):
    assert_rpc_pair(fx, "tools/call")
    params = (fx.get("request") or {}).get("params") or {}
    name = params.get("name")
    specs = contract_by_name(contract)
    if name not in specs:
        raise AssertionError(f"unknown tool {name!r}")
    args = params.get("arguments") or {}
    declared = {p["name"]: p for p in specs[name]["params"]}
    unknown = set(args) - set(declared)
    if unknown:
        raise AssertionError(f"tool {name}: unknown arguments {sorted(unknown)}")
    missing = [p["name"] for p in declared.values() if p["required"] and p["name"] not in args]
    if missing:
        raise AssertionError(f"tool {name}: missing required arguments {missing}")
    for arg_name, value in args.items():
        spec = declared[arg_name]
        if not _type_matches(value, spec["type"]):
            raise AssertionError(
                f"tool {name}.{arg_name}: value type does not match {spec['type']}")
        if spec["type"] == "array":
            if any(not _type_matches(item, spec["item_type"]) for item in value):
                raise AssertionError(f"tool {name}.{arg_name}: invalid array item type")
            if spec.get("enum") and any(item not in spec["enum"] for item in value):
                raise AssertionError(f"tool {name}.{arg_name}: invalid array item enum")
        elif spec.get("enum") and value not in spec["enum"]:
            raise AssertionError(f"tool {name}.{arg_name}: invalid enum value {value!r}")
    return name


def run_fixtures(fixture_dir, contract):
    errors = []
    checks = 0
    fixture_files = sorted(Path(fixture_dir).glob("*.json"))
    if not fixture_files:
        raise SystemExit(f"FATAL: no fixtures found in {fixture_dir}")
    loaded = []
    for path in fixture_files:
        with open(path) as f:
            loaded.append((path, json.load(f)))

    expected_names = CORE_FIXTURES | {f"call_{name}" for name in contract_by_name(contract)}
    actual_names = [fx.get("name", path.stem) for path, fx in loaded]
    missing_names = sorted(expected_names - set(actual_names))
    extra_names = sorted(set(actual_names) - expected_names)
    duplicates = sorted(name for name in set(actual_names) if actual_names.count(name) > 1)
    if missing_names:
        errors.append(f"fixture coverage missing {missing_names}")
    if extra_names:
        errors.append(f"unexpected fixture cases {extra_names}")
    if duplicates:
        errors.append(f"duplicate fixture cases {duplicates}")

    for path, fx in loaded:
        name = fx.get("name", path.stem)
        resp = fx.get("response") or {}
        checks += 1
        try:
            if "error" in resp:
                raise AssertionError(f"recorded response carries top-level error: {resp['error']}")
            if name == "initialize":
                assert_rpc_pair(fx, "initialize")
                req = fx.get("request") or {}
                if (req.get("params") or {}).get("protocolVersion") != "2025-03-26":
                    raise AssertionError("initialize: protocolVersion != 2025-03-26")
                result = resp.get("result") or {}
                if result.get("protocolVersion") != "2025-03-26":
                    raise AssertionError("initialize: result.protocolVersion != 2025-03-26")
                if not result.get("serverInfo"):
                    raise AssertionError("initialize: missing serverInfo")
            elif name == "tools_list":
                assert_rpc_pair(fx, "tools/list")
                assert_tools_list(contract, resp.get("result") or {})
            elif name == "resources_list":
                assert_rpc_pair(fx, "resources/list")
                assert_resources_list(contract, resp.get("result") or {})
            elif name == "prompts_list":
                assert_rpc_pair(fx, "prompts/list")
                assert_prompts_list(contract, resp.get("result") or {})
            elif name == "resources_read":
                cases = fx.get("cases") or []
                checks += max(0, len(cases) - 1)
                for case in cases:
                    assert_rpc_pair(case, "resources/read")
                    uri = ((case.get("request") or {}).get("params") or {}).get("uri")
                    if uri not in RESOURCE_URIS:
                        raise AssertionError(f"resources_read: unexpected URI {uri!r}")
                    assert_resource_result(uri, case.get("response") or {})
                case_uris = {
                    ((c.get("request") or {}).get("params") or {}).get("uri")
                    for c in fx.get("cases") or []
                }
                if case_uris != RESOURCE_URIS:
                    raise AssertionError(
                        f"resources_read coverage mismatch: missing={sorted(RESOURCE_URIS-case_uris)}")
            elif name == "prompts_get":
                cases = fx.get("cases") or []
                checks += max(0, len(cases) - 1)
                for case in cases:
                    assert_rpc_pair(case, "prompts/get")
                    prompt = ((case.get("request") or {}).get("params") or {}).get("name")
                    if prompt not in PROMPT_REQUIREMENTS:
                        raise AssertionError(f"prompts_get: unexpected prompt {prompt!r}")
                    assert_prompt_result(prompt, case.get("response") or {})
                case_prompts = {
                    ((c.get("request") or {}).get("params") or {}).get("name")
                    for c in fx.get("cases") or []
                }
                expected_prompts = set(PROMPT_REQUIREMENTS)
                if case_prompts != expected_prompts:
                    raise AssertionError(
                        f"prompts_get coverage mismatch: missing={sorted(expected_prompts-case_prompts)}")
            elif name.startswith("call_"):
                tool = assert_tool_call_request(contract, fx)
                if name != f"call_{tool}":
                    raise AssertionError(f"fixture name {name!r} does not match tool {tool!r}")
                assert_tool_result(tool, resp)
            else:
                raise AssertionError(f"{name}: unrecognized fixture type")
        except AssertionError as e:
            errors.append(f"{path.name}: {e}")
    return checks, errors


# ---------------------------------------------------------------------------
# Live mode (credentialed acceptance; never in CI)
# ---------------------------------------------------------------------------

def _post(url, headers, body, expect_response=True):
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        session = resp.headers.get("Mcp-Session-Id")
        raw = resp.read().decode("utf-8")
        if not expect_response:
            if resp.status != 202:
                raise ValueError(f"notification returned HTTP {resp.status}, expected 202")
            if raw.strip():
                raise ValueError("notification returned a response body")
            return session, None
        if not raw.strip():
            raise ValueError(f"request returned HTTP {resp.status} with no response body")
        return session, _parse(raw)


def _parse(raw):
    raw = raw.strip()
    if raw.startswith("{"):
        return json.loads(raw)
    for line in raw.split("\n"):
        line = line.strip()
        if line.startswith("data:"):
            payload = line[len("data:"):].strip()
            if payload:
                try:
                    parsed = json.loads(payload)
                    if "jsonrpc" in parsed:
                        return parsed
                except json.JSONDecodeError:
                    continue
    raise ValueError(f"could not parse MCP response: {raw[:300]}")


def _rpc(method, params=None, rid=None):
    return {"jsonrpc": "2.0", "id": rid or str(uuid.uuid4()),
            "method": method, "params": params or {}}


def _notification(method, params=None):
    return {"jsonrpc": "2.0", "method": method, "params": params or {}}


def run_live(contract):
    url = os.environ.get("SPEKTION_MCP_URL")
    key = os.environ.get("SPEKTION_API_KEY")
    if not url or not key:
        return 2, ["SPEKTION_MCP_URL and SPEKTION_API_KEY are required in --live mode"]
    if not url.endswith("/mcp"):
        url = url.rstrip("/") + "/mcp"
    headers = {"Content-Type": "application/json",
               "Accept": "application/json, text/event-stream",
               "Authorization": f"Bearer {key}"}
    errors = []

    def call(method, params=None):
        session, resp = _post(url, headers, _rpc(method, params))
        if session:
            headers["Mcp-Session-Id"] = session
        return resp

    def notify(method, params=None):
        session, _ = _post(
            url, headers, _notification(method, params), expect_response=False)
        if session:
            headers["Mcp-Session-Id"] = session

    init = call("initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                               "clientInfo": {"name": "spektion-contract-smoke", "version": "1.0"}})
    if "error" in init:
        raise SystemExit(f"FATAL: initialize failed: {init['error']}")
    if (init.get("result") or {}).get("protocolVersion") != "2025-03-26":
        raise SystemExit("FATAL: server did not negotiate protocol 2025-03-26")
    headers["Mcp-Protocol-Version"] = "2025-03-26"
    notify("notifications/initialized")

    tl = call("tools/list")
    assert_tools_list(contract, tl.get("result") or {})
    rl = call("resources/list")
    assert_resources_list(contract, rl.get("result") or {})
    pl = call("prompts/list")
    assert_prompts_list(contract, pl.get("result") or {})

    for uri in sorted(RESOURCE_URIS):
        assert_resource_result(uri, call("resources/read", {"uri": uri}))

    prompt_args = {
        "security_review": {"platform": "windows", "time_period": "30d"},
        "investigate_cve": {"cve_id": "CVE-2025-21298"},
        "endpoint_risk_assessment": {"hostname": "PROD-WEB-01"},
        "vulnerability_report": {"time_period": "30d", "severity": "critical"},
        "software_risk_analysis": {"software_name": "Google Chrome", "grade": "F"},
    }
    for name in sorted(PROMPT_REQUIREMENTS):
        assert_prompt_result(name, call("prompts/get", {
            "name": name, "arguments": prompt_args[name],
        }))

    # Discovery order matters: run searches first so dependent tools have args.
    discovered = {}
    order = ["search_vulnerabilities", "search_assets", "search_software", "search_detections",
             "count_ai_session_detections"]
    for name in order:
        args = {"recency_days": 30} if name == "count_ai_session_detections" else {"limit": 5}
        resp = call("tools/call", {"name": name, "arguments": args})
        try:
            doc = assert_tool_result(name, resp)
        except AssertionError as e:
            errors.append(f"{name}: {e}")
            continue
        items = doc.get("items") or []
        if items:
            first = items[0]
            if name == "search_assets":
                first = next((item for item in items if item.get("secret_count", 0) > 0), first)
            if name == "search_vulnerabilities" and "cve_id" not in discovered:
                discovered["cve_id"] = first.get("cve_id")
            elif name == "search_assets" and "hostname" not in discovered:
                discovered["hostname"] = first.get("hostname")
                discovered["asset_id"] = first.get("asset_id")
                discovered["secret_count"] = first.get("secret_count")
            elif name == "search_software" and "name" not in discovered:
                discovered["software_name"] = first.get("name")
            elif name == "search_detections" and "id" not in discovered:
                discovered["detection_id"] = first.get("id")
            elif name == "count_ai_session_detections":
                discovered["ai_detection_id"] = first.get("detection_id")
                discovered["ai_session_count"] = first.get("session_count")

    args_for = {
        "search_vulnerabilities": {"limit": 5},
        "search_assets": {"limit": 5},
        "search_software": {"limit": 5},
        "search_detections": {"limit": 5},
        "search_secrets": {"asset_id": discovered.get("asset_id") or "", "limit": 5},
        "search_ai_security_risks": {"limit": 5},
        "search_executables": {"limit": 5},
        "search_ai_sessions": {"limit": 5, "recency_days": 30,
                               "detection_id": [discovered["ai_detection_id"]]
                               if discovered.get("ai_detection_id") else []},
        "query_sensors": {"limit": 5},
        "get_security_posture": {},
        "get_remediation_metrics": {},
        "get_vulnerability_trends": {},
        "get_tenant_settings": {},
        "search_network_activity": {"software_name": discovered.get("software_name") or "", "limit": 5},
        "get_software_details": {"software_name": discovered.get("software_name") or ""},
        "get_asset_details": {"hostname": discovered.get("hostname") or ""},
        "get_vulnerability_details": {"cve_id": discovered.get("cve_id") or ""},
        "get_detection_events": {"detection_id": discovered.get("detection_id") or ""},
        "get_detection_controls": {"detection_id": discovered.get("detection_id") or ""},
    }

    for name, spec in contract_by_name(contract).items():
        if name in order:  # already exercised above
            continue
        args = args_for.get(name)
        if args is None:
            errors.append(f"{name}: no call args defined in live mode")
            continue
        missing = [k for k, v in args.items() if not v]
        if missing:
            errors.append(f"{name}: cannot exercise - missing discovery value for {', '.join(missing)}")
            continue
        resp = call("tools/call", {"name": name, "arguments": args})
        try:
            doc = assert_tool_result(name, resp)
            if name == "search_ai_sessions" and doc.get("total_count") != discovered["ai_session_count"]:
                raise AssertionError("census/session total mismatch with the same 30-day window; "
                                     "check service parity or telemetry changes between calls")
            if name == "search_ai_sessions" and any(
                    discovered["ai_detection_id"] not in {d.get("id") for d in row.get("detections", [])}
                    for row in doc["items"]):
                raise AssertionError("session drill-through returned a row without the requested detection")
            if name == "search_secrets" and doc.get("total_count") != discovered.get("secret_count"):
                raise AssertionError("asset secret_count differs from exact-asset findings total_count")
            if name == "get_asset_details" and "secret_types" not in doc["endpoint"]:
                raise AssertionError("asset secret_types unavailable; enrichment did not answer")
        except AssertionError as e:
            errors.append(f"{name}: {e}")

    return (1 if errors else 0), errors


def main():
    ap = argparse.ArgumentParser(description="Spektion MCP contract smoke tester")
    ap.add_argument("--fixtures", default=str(DEFAULT_FIXTURES),
                    help="directory of recorded JSON-RPC fixtures")
    ap.add_argument("--live", action="store_true",
                    help="credentialed acceptance against SPEKTION_MCP_URL (never CI)")
    args = ap.parse_args()

    contract = load_contract()
    if args.live:
        try:
            code, notes = run_live(contract)
        except (AssertionError, OSError, ValueError) as e:
            code, notes = 1, [str(e)]
        for n in notes:
            print(n)
        if code == 0:
            print("LIVE PASS")
        elif code == 2:
            print("LIVE BLOCKED (credentials unavailable)")
        else:
            print(f"LIVE FAIL ({len(notes)} issue(s))")
        sys.exit(code)

    checks, errors = run_fixtures(args.fixtures, contract)
    print(f"fixture checks: {checks}, errors: {len(errors)}")
    for e in errors:
        print(f"  FAIL {e}")
    if errors:
        sys.exit(1)
    print("FIXTURE PASS")
    sys.exit(0)


if __name__ == "__main__":
    main()
