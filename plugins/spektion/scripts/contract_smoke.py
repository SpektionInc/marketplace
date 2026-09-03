#!/usr/bin/env python3
"""Deterministic MCP contract smoke tester for the Spektion plugin.

Two modes:

  --fixtures <dir>   (default) Replays recorded JSON-RPC message pairs from the
                     fixtures directory and asserts the MCP surface matches the
                     pinned contract (plugins/spektion/contract/mcp-contract.json).
                     Deterministic; used by CI. No network, no credentials.

  --live             Connects to a real MCP server using the SPEKTION_MCP_URL and
                     SPEKTION_API_KEY environment variables (protocol 2025-03-26),
                     enumerates tools/resources/prompts, makes one representative
                     call per non-placeholder tool, and validates the results.

Exit codes: 0 = pass, 1 = fail, 2 = required environment missing.
"""

import argparse
import json
import os
import sys
import urllib.request
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
CONTRACT_PATH = REPO_ROOT / "plugins" / "spektion" / "contract" / "mcp-contract.json"
DEFAULT_FIXTURES = Path(__file__).resolve().parent / "fixtures"

# Registered-but-placeholder tools/resources: asserted for presence, never called.
PLACEHOLDER_TOOLS = {"get_tenant_settings"}
PLACEHOLDER_RESOURCES = {"spektion://sla-policy", "spektion://detection-rules"}

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
    "get_security_posture": {"keys": ["total_assets", "active_assets", "assets_by_platform",
                                      "software_by_platform", "vulnerabilities_by_severity"]},
    "search_vulnerabilities": {"keys": ["items"], "items": ["cve_id", "severity", "score",
                                                            "endpoint_count", "sla_status"]},
    "search_assets": {"keys": ["items"], "items": ["hostname", "exposure_score",
                                                   "exposure_severity", "importance"]},
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
                                                        "severity_max"]},
    "query_sensors": {"keys": ["items", "total_count", "count", "offset", "summary"],
                      "items": ["sensor_id", "hostname", "os_family", "agent_version"]},
    "get_asset_details": {"keys": ["endpoint", "installed_software", "network_activity"],
                          "items": ["hostname", "exposure_score", "risks"]},
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
    "get_tenant_settings": {"keys": [], "placeholder": True},
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
            if props[pname].get("type") != p["type"]:
                raise AssertionError(
                    f"tool {name}.{pname}: type {props[pname].get('type')} != {p['type']}")
            if p.get("enum"):
                if sorted(props[pname].get("enum", [])) != sorted(p["enum"]):
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


def assert_prompts_list(contract, result):
    prompts = {p["name"]: p for p in result.get("prompts", [])}
    expected = {p["name"]: p for p in contract["prompts"]}
    if set(prompts) != set(expected):
        raise AssertionError(
            "prompts/list mismatch: missing=%s extra=%s" % (
                sorted(set(expected) - set(prompts)),
                sorted(set(prompts) - set(expected))))
    for name, p in expected.items():
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
    if spec.get("placeholder"):
        return doc
    for key in spec.get("keys", []):
        if key not in doc:
            raise AssertionError(f"tool {tool_name}: missing envelope key '{key}'")
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


def run_fixtures(fixture_dir, contract):
    errors = []
    checks = 0
    fixture_files = sorted(Path(fixture_dir).glob("*.json"))
    if not fixture_files:
        raise SystemExit(f"FATAL: no fixtures found in {fixture_dir}")
    for path in fixture_files:
        with open(path) as f:
            fx = json.load(f)
        name = fx.get("name", path.stem)
        resp = fx.get("response") or {}
        checks += 1
        try:
            if "error" in resp:
                raise AssertionError(f"recorded response carries top-level error: {resp['error']}")
            if name == "initialize":
                req = fx.get("request") or {}
                if (req.get("params") or {}).get("protocolVersion") != "2025-03-26":
                    raise AssertionError("initialize: protocolVersion != 2025-03-26")
                result = resp.get("result") or {}
                if result.get("protocolVersion") != "2025-03-26":
                    raise AssertionError("initialize: result.protocolVersion != 2025-03-26")
                if not result.get("serverInfo"):
                    raise AssertionError("initialize: missing serverInfo")
            elif name == "tools_list":
                assert_tools_list(contract, resp.get("result") or {})
            elif name == "resources_list":
                assert_resources_list(contract, resp.get("result") or {})
            elif name == "prompts_list":
                assert_prompts_list(contract, resp.get("result") or {})
            elif name.startswith("call_"):
                tool = (fx.get("request") or {}).get("params", {}).get("name")
                if tool is None:
                    raise AssertionError(f"{name}: tools/call fixture missing params.name")
                assert_tool_result(tool, resp)
            else:
                raise AssertionError(f"{name}: unrecognized fixture type")
        except AssertionError as e:
            errors.append(f"{path.name}: {e}")
    return checks, errors


# ---------------------------------------------------------------------------
# Live mode (credentialed acceptance; never in CI)
# ---------------------------------------------------------------------------

def _post(url, headers, body):
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        session = resp.headers.get("Mcp-Session-Id")
        raw = resp.read().decode("utf-8")
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


def run_live(contract):
    url = os.environ.get("SPEKTION_MCP_URL")
    key = os.environ.get("SPEKTION_API_KEY")
    if not url or not key:
        print("FATAL: SPEKTION_MCP_URL and SPEKTION_API_KEY are required in --live mode",
              file=sys.stderr)
        return 2, []
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

    init = call("initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                               "clientInfo": {"name": "spektion-contract-smoke", "version": "1.0"}})
    if "error" in init:
        raise SystemExit(f"FATAL: initialize failed: {init['error']}")
    if (init.get("result") or {}).get("protocolVersion") != "2025-03-26":
        raise SystemExit("FATAL: server did not negotiate protocol 2025-03-26")
    call("notifications/initialized")

    tl = call("tools/list")
    assert_tools_list(contract, tl.get("result") or {})
    rl = call("resources/list")
    assert_resources_list(contract, rl.get("result") or {})
    pl = call("prompts/list")
    assert_prompts_list(contract, pl.get("result") or {})

    # Discovery order matters: run searches first so dependent tools have args.
    discovered = {}
    order = ["search_vulnerabilities", "search_assets", "search_software", "search_detections"]
    for name in order:
        resp = call("tools/call", {"name": name, "arguments": {"limit": 5}})
        try:
            doc = assert_tool_result(name, resp)
        except AssertionError as e:
            errors.append(f"{name}: {e}")
            continue
        items = doc.get("items") or []
        if items:
            first = items[0]
            if name == "search_vulnerabilities" and "cve_id" not in discovered:
                discovered["cve_id"] = first.get("cve_id")
            elif name == "search_assets" and "hostname" not in discovered:
                discovered["hostname"] = first.get("hostname")
            elif name == "search_software" and "name" not in discovered:
                discovered["software_name"] = first.get("name")
            elif name == "search_detections" and "id" not in discovered:
                discovered["detection_id"] = first.get("id")

    args_for = {
        "search_vulnerabilities": {"limit": 5},
        "search_assets": {"limit": 5},
        "search_software": {"limit": 5},
        "search_detections": {"limit": 5},
        "search_secrets": {"limit": 5},
        "search_ai_security_risks": {"limit": 5},
        "search_executables": {"limit": 5},
        "search_ai_sessions": {"limit": 5},
        "query_sensors": {"limit": 5},
        "get_security_posture": {},
        "get_remediation_metrics": {},
        "get_vulnerability_trends": {},
        "search_network_activity": {"software_name": discovered.get("software_name") or "", "limit": 5},
        "get_software_details": {"software_name": discovered.get("software_name") or ""},
        "get_asset_details": {"hostname": discovered.get("hostname") or ""},
        "get_vulnerability_details": {"cve_id": discovered.get("cve_id") or ""},
        "get_detection_events": {"detection_id": discovered.get("detection_id") or ""},
        "get_detection_controls": {"detection_id": discovered.get("detection_id") or ""},
    }

    skips = []
    for name, spec in contract_by_name(contract).items():
        if name in PLACEHOLDER_TOOLS:
            continue
        if name in order:  # already exercised above
            continue
        args = args_for.get(name)
        if args is None:
            errors.append(f"{name}: no call args defined in live mode")
            continue
        missing = [k for k, v in args.items() if not v]
        if missing:
            skips.append(f"{name}: skipped - missing discovery value for {', '.join(missing)}")
            continue
        resp = call("tools/call", {"name": name, "arguments": args})
        try:
            assert_tool_result(name, resp)
        except AssertionError as e:
            errors.append(f"{name}: {e}")

    return (1 if errors else 0), errors + skips


def main():
    ap = argparse.ArgumentParser(description="Spektion MCP contract smoke tester")
    ap.add_argument("--fixtures", default=str(DEFAULT_FIXTURES),
                    help="directory of recorded JSON-RPC fixtures")
    ap.add_argument("--live", action="store_true",
                    help="credentialed acceptance against SPEKTION_MCP_URL (never CI)")
    args = ap.parse_args()

    contract = load_contract()
    if args.live:
        code, notes = run_live(contract)
        for n in notes:
            print(n)
        print("LIVE PASS" if code == 0 else f"LIVE FAIL ({len(notes)} issue(s))")
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
