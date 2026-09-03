#!/usr/bin/env python3
"""Marketplace contract parity gate for the Spektion plugin.

Loads the pinned MCP contract (plugins/spektion/contract/mcp-contract.json) and
checks that every shipped surface agrees with it:

  - README, marketplace manifest, plugin manifest, and all skill files must not
    reference retired tools, and every referenced tool must be in the contract
    MCP tool set (chat-only tools are not exposed to MCP and must not be cited).
  - Skill parameter names and enum literals (e.g. sort_by, category,
    highest_impact, severity, platform) must match the contract when the tool is
    named on the same line / quick-reference row.
  - plugins/spektion/.mcp.json must use Streamable HTTP with environment-only
    credentials (no literal URLs or keys).
  - plugin.json version must match marketplace.json metadata.version.
  - README must document all 5 resources and all 5 prompts from the contract.

Exit code: 0 = pass, 1 = violation. --json prints a machine-readable report.
"""

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = REPO_ROOT / "plugins" / "spektion" / "contract" / "mcp-contract.json"
MCP_JSON = REPO_ROOT / "plugins" / "spektion" / ".mcp.json"
README = REPO_ROOT / "README.md"
MARKETPLACE_JSON = REPO_ROOT / ".claude-plugin" / "marketplace.json"
PLUGIN_JSON = REPO_ROOT / "plugins" / "spektion" / ".claude-plugin" / "plugin.json"
SKILLS_DIR = REPO_ROOT / "plugins" / "spektion" / "skills"

RETIRED_TOOLS = {
    "search_endpoints", "get_endpoint_details", "query_detection_events",
    "query_software_inventory", "query_vulnerability_data", "get_host_details",
    "get_environment_summary", "generate_report", "get_report_status",
    "list_report_entities",
}

# MalloryAI tools are NOT Spektion MCP tools. They are only permitted inside the
# skills' gated "External Enrichment (Optional)" block (which must reference the
# mallory-api skill) — anywhere else they are a parity violation.
EXTERNAL_TOOLS = {
    "get_vulnerability_exploitations", "get_mentioned_threat_actors",
    "get_vulnerability_detection_signatures",
}

TOOL_RE = re.compile(r"\b(search|get|query)_[a-z0-9_]+\b")
# param literal captures like "sort_by: grade" or "highest_impact: Critical".
PARAM_VALUE_RE = re.compile(r"([a-z_]+)\s*[:=]\s*([`'\"\[]?[A-Za-z0-9 _./+-]+)`?")
# parenthesized enum lists that follow a backticked param name: `sort_by` (a, b, c)
PARAM_ENUM_LIST_RE = re.compile(r"`([a-z_]+)`\s*\(([^)]*)\)")
BACKTICK_RE = re.compile(r"`([^`]+)`")

# Boolean params (no enum in the contract, true/false literals only).
BOOLEAN_PARAMS = {"kev", "has_remote_exploitability", "is_used", "is_online",
                  "is_linked_to_software", "is_signed"}


def load_contract():
    with open(CONTRACT_PATH) as f:
        return json.load(f)


def tools_by_name(contract):
    return {t["name"]: t for t in contract["mcp"]["tools"]}


def enum_for(tool_spec, param):
    for p in tool_spec["params"]:
        if p["name"] == param:
            return set(p.get("enum") or [])
    return None


def _external_section_allowed(text, line_idx):
    """Return True when line_idx sits inside a gated External Enrichment section."""
    if "mallory-api" not in text.lower() and "malloryai" not in text.lower():
        return False
    heading = -1
    for i, line in enumerate(text.splitlines()[:line_idx]):
        if line.startswith("#"):
            heading = i
    if heading < 0:
        return False
    heading_line = text.splitlines()[heading].lower()
    return "external enrichment" in heading_line or "(optional)" in heading_line


def scan_tool_references(text, path, mcp_tools, errors):
    """Fail on retired tools and on any referenced tool outside the MCP set."""
    lines = text.splitlines()
    for lineno, line in enumerate(lines):
        for match in TOOL_RE.finditer(line):
            name = match.group(0)
            if name in RETIRED_TOOLS:
                errors.append(f"{path}:{lineno+1}: retired tool reference '{name}'")
            elif name in EXTERNAL_TOOLS:
                if not _external_section_allowed(text, lineno):
                    errors.append(
                        f"{path}:{lineno+1}: external tool '{name}' used outside a gated "
                        f"External Enrichment block")
            elif name not in mcp_tools:
                errors.append(f"{path}:{lineno+1}: tool '{name}' not in the MCP contract tool set")


def normalize(value):
    return (value.strip().strip("`'\",.:;()[]").lower())


def validate_skill_params(contract, mcp_tools, errors):
    """Check quick-reference rows and inline param/enum literals per skill."""
    for skill_md in sorted(SKILLS_DIR.glob("*/SKILL.md")):
        rel = str(skill_md.relative_to(REPO_ROOT))
        text = skill_md.read_text()
        for line in text.splitlines():
            names = [m for m in TOOL_RE.findall(line)]
            if not names:
                continue
            # Only validate when exactly one tool is named on the line so the
            # param/enum context is unambiguous.
            tools = [n for n in names if n in mcp_tools]
            if len(tools) != 1:
                continue
            tool = tools[0]
            spec = mcp_tools[tool]
            param_set = {p["name"] for p in spec["params"]}

            # Inline "param: value" literals (e.g. "sort_by: grade").
            for pm, val in PARAM_VALUE_RE.findall(line):
                if pm not in param_set:
                    continue  # not a param of this tool; ignore prose
                enum = enum_for(spec, pm)
                if enum is None:
                    continue  # no enum to check for this param
                val_norm = normalize(val)
                if val_norm not in enum:
                    errors.append(
                        f"{rel}:{line.strip()[:60]}... tool '{tool}' param '{pm}' "
                        f"literal '{val}' not in enum {sorted(enum)}")

            # Parenthesized lists that follow a backticked param:
            # `sort_by` (cve_count, endpoint_count, ...)
            for pm, inner in PARAM_ENUM_LIST_RE.findall(line):
                enum = enum_for(spec, pm)
                if enum is None:
                    continue
                for lit in inner.split(","):
                    lit = normalize(lit)
                    if lit and lit not in enum:
                        errors.append(
                            f"{rel}: tool '{tool}' param '{pm}' literal '{lit}' "
                            f"not in enum {sorted(enum)}")

            # Quick-reference rows (lines starting with '|'): validate the third
            # cell's param names against the tool.
            if line.lstrip().startswith("|"):
                cells = [c.strip() for c in line.split("|")]
                if len(cells) >= 4:
                    tool_cell = cells[2]
                    if tool_cell == f"`{tool}`":
                        param_cell = cells[3]
                        param_names = {p["name"] for p in spec["params"]}
                        for token in BACKTICK_RE.findall(param_cell):
                            if token.startswith("spektion://"):
                                continue
                            token_clean = token.split()[0]
                            if token_clean in ("resources", "Resource:") or token_clean == "N/A":
                                continue
                            if token_clean not in param_names and token_clean != "none":
                                errors.append(
                                    f"{rel}: quick-ref row for '{tool}' has unknown "
                                    f"parameter '{token_clean}'")


def validate_mcp_json(errors):
    if not MCP_JSON.exists():
        errors.append(f"{MCP_JSON}: missing .mcp.json")
        return
    try:
        data = json.loads(MCP_JSON.read_text())
    except json.JSONDecodeError as e:
        errors.append(f"{MCP_JSON}: invalid JSON: {e}")
        return
    servers = data.get("mcpServers") or {}
    if not servers:
        errors.append(f"{MCP_JSON}: no mcpServers")
        return
    for name, srv in servers.items():
        if srv.get("type") != "http":
            errors.append(f"{MCP_JSON}: server '{name}' type must be 'http', got {srv.get('type')!r}")
        url = srv.get("url") or ""
        if not re.fullmatch(r"\$\{[A-Z0-9_]+\}", url):
            errors.append(f"{MCP_JSON}: server '{name}' url must be an environment "
                          f"placeholder (${{VAR}}), got {url!r}")
        headers = srv.get("headers") or {}
        for hname, hval in headers.items():
            if not isinstance(hval, str):
                errors.append(f"{MCP_JSON}: server '{name}' header '{hname}' must be a string")
                continue
            if hname.lower() == "authorization":
                if not re.fullmatch(r"Bearer \$\{[A-Z0-9_]+\}", hval):
                    errors.append(f"{MCP_JSON}: Authorization must be 'Bearer ${{ENV_VAR}}', "
                                  f"got {hval!r}")
            else:
                if re.fullmatch(r"\$\{[A-Z0-9_]+\}", hval) is None:
                    errors.append(f"{MCP_JSON}: header '{hname}' must be an environment "
                                  f"placeholder, got {hval!r}")
        # No literal credentials anywhere in the file.
        mcp_text = MCP_JSON.read_text()
        if re.search(r"sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|Bearer [A-Za-z0-9+/=]{20,}", mcp_text):
            errors.append(f"{MCP_JSON}: literal credential pattern found")


def validate_versions(errors):
    for path in (MARKETPLACE_JSON, PLUGIN_JSON):
        if not path.exists():
            errors.append(f"{path}: missing")
    plugin = json.loads(PLUGIN_JSON.read_text())
    marketplace = json.loads(MARKETPLACE_JSON.read_text())
    pv = plugin.get("version")
    mv = (marketplace.get("metadata") or {}).get("version")
    if not pv or not mv:
        errors.append("missing version in plugin.json / marketplace.json metadata")
    elif pv != mv:
        errors.append(f"version mismatch: plugin.json={pv} marketplace.json={mv}")


def validate_readme_surface(contract, errors):
    if not README.exists():
        errors.append(f"{README}: missing README.md")
        return
    text = README.read_text()
    for r in contract["resources"]:
        if r["uri"] not in text:
            errors.append(f"README: resource '{r['uri']}' not documented")
    for p in contract["prompts"]:
        if p["name"] not in text:
            errors.append(f"README: prompt '{p['name']}' not documented")


def run():
    contract = load_contract()
    mcp_tools = tools_by_name(contract)
    errors = []

    scan_targets = [README, MARKETPLACE_JSON, PLUGIN_JSON]
    for path in scan_targets:
        if path.exists():
            scan_tool_references(path.read_text(), str(path.relative_to(REPO_ROOT)),
                                 mcp_tools, errors)
    if SKILLS_DIR.exists():
        for skill_md in sorted(SKILLS_DIR.glob("*/SKILL.md")):
            scan_tool_references(skill_md.read_text(),
                                 str(skill_md.relative_to(REPO_ROOT)), mcp_tools, errors)

    validate_skill_params(contract, mcp_tools, errors)
    validate_mcp_json(errors)
    validate_versions(errors)
    validate_readme_surface(contract, errors)

    return {"ok": not errors, "errors": errors,
            "contract_tools": sorted(mcp_tools)}


def main():
    ap = argparse.ArgumentParser(description="Spektion marketplace contract parity gate")
    ap.add_argument("--json", action="store_true", help="emit JSON report")
    args = ap.parse_args()
    report = run()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        if report["errors"]:
            print(f"PARITY FAIL ({len(report['errors'])} violation(s)):")
            for e in report["errors"]:
                print(f"  - {e}")
        else:
            print(f"PARITY PASS ({len(report['contract_tools'])} contract tools checked)")
    sys.exit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
