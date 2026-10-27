#!/usr/bin/env python3
"""Validate that every MCP tool name referenced in plugin docs exists.

Extracts tool-name-shaped tokens (search_*/get_*/query_*/count_*) from all
SKILL.md, README.md and plugin.json files and resolves them against the
canonical MCP-visible tool list (spektionapi src/aitools/registry.go,
lanes LaneBoth + LaneMCP). Fails on any unknown name. ENG-3616; the
registry-side CI check is ENG-3547.
"""

import json
import re
import sys
from pathlib import Path

# Generated contract is the source of truth; do not maintain a second tool list.
CONTRACT_PATH = Path(__file__).resolve().parents[1] / "plugins/spektion/contract/mcp-contract.json"
CANONICAL_TOOLS = {tool["name"] for tool in json.loads(CONTRACT_PATH.read_text())["mcp"]["tools"]}

# Referenced but deliberately not validated against the Spektion registry.
ALLOWLIST = {
    # MalloryAI third-party tools, gated behind "if the mallory-api skill is available".
    "get_vulnerability_exploitations",
    "get_mentioned_threat_actors",
    "get_vulnerability_detection_signatures",
}

TOKEN_RE = re.compile(r"\b(?:search|get|query|count)_[a-z0-9_]+\b")

def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    files = sorted(
        list(root.rglob("SKILL.md"))
        + list(root.rglob("README.md"))
        + list(root.rglob("plugin.json"))
    )
    files = [f for f in files if ".git" not in f.parts]

    failures = []
    seen = set()
    for f in files:
        for lineno, line in enumerate(f.read_text().splitlines(), 1):
            for token in TOKEN_RE.findall(line):
                seen.add(token)
                if token not in CANONICAL_TOOLS and token not in ALLOWLIST:
                    failures.append(f"{f.relative_to(root)}:{lineno}: unknown tool '{token}'")

    unreferenced = CANONICAL_TOOLS - seen
    print(f"Scanned {len(files)} files; {len(seen)} distinct tool tokens.")
    if unreferenced:
        print(f"Note: canonical tools never referenced: {', '.join(sorted(unreferenced))}")
    if failures:
        print(f"\nFAILED — {len(failures)} unknown tool reference(s):")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("PASSED — every referenced tool resolves.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
