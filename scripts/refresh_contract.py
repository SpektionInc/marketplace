#!/usr/bin/env python3
"""Refresh tool schemas from a clean spektionapi checkout; retain release requirements.

Resource/prompt metadata and behavioral fixtures are separately sourced release
expectations. This command does not invent or overwrite response fixtures.
"""
import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "plugins/spektion/contract/mcp-contract.json"
DISCOVERY = ROOT / "plugins/spektion/scripts/fixtures/tools_list.json"


def run(api, *args):
    return subprocess.check_output(args, cwd=api, text=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", type=Path, default=ROOT.parent / "spektionapi")
    parser.add_argument("--check", action="store_true", help="compare without writing")
    args = parser.parse_args()
    api = args.api.resolve()
    if run(api, "git", "status", "--porcelain", "--untracked-files=no").strip():
        parser.error("API checkout has tracked changes; provenance requires a clean revision")
    revision = run(api, "git", "rev-parse", "HEAD").strip()
    exported = json.loads(run(api, "go", "run", str(ROOT / "scripts/export_mcp_tools.go")))
    wire_tools = {tool["name"]: tool for tool in exported["tools_list"]}
    for tool in exported["mcp"]["tools"]:
        props = wire_tools[tool["name"]]["inputSchema"]["properties"]
        for param in tool["params"]:
            wire_type = props[param["name"]]["type"]
            if wire_type != param["type"]:
                param["mcp_type"] = wire_type
    if run(api, "git", "rev-parse", "HEAD").strip() != revision:
        parser.error("API revision changed during export")
    if run(api, "git", "status", "--porcelain", "--untracked-files=no").strip():
        parser.error("API tracked files changed during export")
    for group in (exported["mcp"]["tools"], exported["chat_only_tools"]):
        for index, tool in enumerate(group):
            tool["params"] = [{key: param[key] for key in
                               ("name", "type", "required", "enum", "item_type", "mcp_type")
                               if key in param} for param in tool["params"]]
            group[index] = {key: tool[key] for key in
                            ("name", "description", "read_only", "lanes", "params")}
    contract = json.loads(CONTRACT.read_text())
    # The prior API hardening candidate supplies the SLA and prompt requirements.
    contract.setdefault("release_surface_source", dict(contract["source"]))
    contract["schema_version"] = "1.2"
    contract["generated_at"] = run(api, "git", "show", "-s", "--format=%cI", "HEAD").strip()
    contract["source"] = {
        "repository": "https://github.com/SpektionInc/spektionapi",
        "revision": revision,
        "generator": "scripts/export_mcp_tools.go",
        "scope": "tool registry and MCP input schemas",
    }
    contract["mcp"] = exported["mcp"]
    contract["chat_only_tools"] = exported["chat_only_tools"]
    discovery = json.loads(DISCOVERY.read_text())
    discovery["response"]["result"]["tools"] = exported["tools_list"]
    for path, doc in ((CONTRACT, contract), (DISCOVERY, discovery)):
        if args.check:
            if json.loads(path.read_text()) != doc:
                parser.error(f"{path.relative_to(ROOT)} differs from API export")
        else:
            path.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"{'Verified' if args.check else 'Refreshed'} {len(exported['mcp']['tools'])} MCP tools at {revision}")


if __name__ == "__main__":
    main()
