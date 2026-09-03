#!/usr/bin/env python3
"""Marketplace contract parity gate for the Spektion plugin.

Loads the pinned MCP contract (plugins/spektion/contract/mcp-contract.json) and
checks that every shipped surface agrees with it:

  - README, marketplace manifest, plugin manifest, and all skill files must not
    reference retired tools, and every referenced tool must be in the contract
    MCP tool set (chat-only tools are not exposed to MCP and must not be cited).
  - Skill quick-reference parameters and unambiguous inline enum/boolean
    literals (e.g. sort_by, category, highest_impact, severity, platform) must
    match the contract.
  - plugins/spektion/.mcp.json must use Streamable HTTP with environment-only
    credentials (no literal URLs or keys).
  - plugin.json version must match marketplace.json metadata.version.
  - README resource and prompt tables must exactly cover the contract, including
    prompt arguments and resource behavior classifications.
  - The contract must identify the exact service repository and source revision.

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

TOOL_RE = re.compile(r"\b(?:search|get|query)_[a-z0-9_]+\b")
# Full inline-code assignments such as `sort_by: grade` or `source: runtime|scan`.
CODE_PARAM_VALUE_RE = re.compile(r"^([a-z_]+)\s*[:=]\s*(.+)$")
# parenthesized enum lists that follow a backticked param name: `sort_by` (a, b, c)
PARAM_ENUM_LIST_RE = re.compile(r"`([a-z_]+)`\s*\(([^)]*)\)")
BACKTICK_RE = re.compile(r"`([^`]+)`")

# Boolean params (no enum in the contract, true/false literals only).
BOOLEAN_PARAMS = {"kev", "has_remote_exploitability", "is_used", "is_online",
                  "is_linked_to_software", "is_signed"}

SOURCE_REPOSITORY = "https://github.com/SpektionInc/spektionapi"
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")


def load_contract():
    with open(CONTRACT_PATH) as f:
        return json.load(f)


def tools_by_name(contract):
    return {t["name"]: t for t in contract["mcp"]["tools"]}


def validate_contract(contract, errors):
    if contract.get("schema_version") != "1.1":
        errors.append("contract: schema_version must be '1.1'")
    source = contract.get("source") or {}
    if source.get("repository") != SOURCE_REPOSITORY:
        errors.append(f"contract: source.repository must be {SOURCE_REPOSITORY!r}")
    revision = source.get("revision") or ""
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        errors.append("contract: source.revision must be a full 40-character git SHA")
    if source.get("generator") != "cmd/mcp-contract":
        errors.append("contract: source.generator must be 'cmd/mcp-contract'")

    tools = contract.get("mcp", {}).get("tools", [])
    names = [t.get("name") for t in tools]
    duplicates = sorted(name for name in set(names) if names.count(name) > 1)
    if duplicates:
        errors.append(f"contract: duplicate MCP tools {duplicates}")
    for tool in tools:
        name = tool.get("name", "<unnamed>")
        if tool.get("read_only") is not True:
            errors.append(f"contract: MCP tool '{name}' must be read-only")
        if "mcp" not in (tool.get("lanes") or []):
            errors.append(f"contract: MCP tool '{name}' is missing the mcp lane")
    for resource in contract.get("resources", []):
        if not resource.get("registration_description"):
            errors.append(
                f"contract: resource '{resource.get('uri', '<unnamed>')}' lacks "
                "registration_description")


def enum_for(tool_spec, param):
    for p in tool_spec["params"]:
        if p["name"] == param:
            values = p.get("enum")
            return set(values) if values is not None else None
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
            for span in BACKTICK_RE.findall(line):
                assignment = CODE_PARAM_VALUE_RE.fullmatch(span.strip())
                if not assignment:
                    continue
                pm, raw_values = assignment.groups()
                if pm not in param_set:
                    errors.append(
                        f"{rel}: tool '{tool}' uses unknown parameter '{pm}'")
                    continue
                enum = enum_for(spec, pm)
                for val in raw_values.split("|"):
                    val_norm = normalize(val)
                    if enum is not None and val_norm not in enum:
                        errors.append(
                            f"{rel}:{line.strip()[:60]}... tool '{tool}' param '{pm}' "
                            f"literal '{val}' not in enum {sorted(enum)}")
                    if pm in BOOLEAN_PARAMS and val_norm not in {"true", "false"}:
                        errors.append(
                            f"{rel}: tool '{tool}' boolean param '{pm}' has invalid "
                            f"literal '{val}'")

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
                            token_clean = re.split(r"[:\s]", token, maxsplit=1)[0]
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
    elif not SEMVER_RE.fullmatch(pv):
        errors.append(f"plugin version is not release SemVer: {pv!r}")


def _table_rows(text, heading):
    """Return Markdown table rows under heading up to the next heading."""
    lines = text.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == heading)
    except StopIteration:
        return []
    rows = []
    for line in lines[start + 1:]:
        if line.startswith("#"):
            break
        if not line.lstrip().startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if cells and not set(cells[0]) <= {"-", ":"}:
            rows.append(cells)
    return rows[1:] if rows and rows[0][0] in {"Resource", "Prompt"} else rows


def validate_readme_surface(contract, errors):
    if not README.exists():
        errors.append(f"{README}: missing README.md")
        return
    text = README.read_text()

    resource_rows = _table_rows(text, f"### {len(contract['resources'])} Resources")
    actual_resources = {}
    for cells in resource_rows:
        if len(cells) >= 2:
            names = BACKTICK_RE.findall(cells[0])
            if names:
                actual_resources[names[0]] = cells[1]
    expected_resources = {r["uri"]: r for r in contract["resources"]}
    if set(actual_resources) != set(expected_resources):
        errors.append(
            "README: resource table mismatch: missing=%s extra=%s" % (
                sorted(set(expected_resources) - set(actual_resources)),
                sorted(set(actual_resources) - set(expected_resources))))
    for uri, spec in expected_resources.items():
        description = actual_resources.get(uri, "").lower()
        if spec.get("behavior") == "placeholder" and not any(
                word in description for word in ("placeholder", "unavailable", "coming soon")):
            errors.append(f"README: placeholder resource '{uri}' is not labeled as such")
        if spec.get("behavior") == "live" and any(
                word in description for word in ("placeholder", "unavailable", "coming soon")):
            errors.append(f"README: live resource '{uri}' is described as unavailable")
        if spec.get("behavior") == "instructional" and "query" not in description:
            errors.append(f"README: instructional resource '{uri}' lacks query guidance")

    prompt_rows = _table_rows(text, f"### {len(contract['prompts'])} MCP Prompts")
    actual_prompts = {}
    for cells in prompt_rows:
        if len(cells) >= 2:
            names = BACKTICK_RE.findall(cells[0])
            if names:
                actual_prompts[names[0]] = BACKTICK_RE.findall(cells[1])
    expected_prompts = {p["name"]: p for p in contract["prompts"]}
    if set(actual_prompts) != set(expected_prompts):
        errors.append(
            "README: prompt table mismatch: missing=%s extra=%s" % (
                sorted(set(expected_prompts) - set(actual_prompts)),
                sorted(set(actual_prompts) - set(expected_prompts))))
    for name, spec in expected_prompts.items():
        expected_args = {
            a["name"] + ("" if a.get("required") else "?") for a in spec["args"]
        }
        actual_args = set(actual_prompts.get(name, []))
        if actual_args != expected_args:
            errors.append(
                f"README: prompt '{name}' arguments mismatch: "
                f"expected={sorted(expected_args)} actual={sorted(actual_args)}")


def run():
    contract = load_contract()
    errors = []
    validate_contract(contract, errors)
    mcp_tools = tools_by_name(contract)

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
