#!/usr/bin/env python3
"""Validate that every MCP tool name referenced in plugin docs exists.

Extracts tool-name-shaped tokens (search_*/get_*/query_*/count_*) from all
SKILL.md, README.md and plugin.json files and resolves them against the
canonical MCP-visible tool list (spektionapi src/aitools/registry.go,
lanes LaneBoth + LaneMCP). Fails on any unknown name. ENG-3616; the
registry-side CI check is ENG-3547.
"""

import re
import sys
from pathlib import Path

# Canonical MCP-visible tools (LaneBoth + LaneMCP), spektionapi origin/master 2026-09-24.
CANONICAL_TOOLS = {
    "search_assets",
    "search_vulnerabilities",
    "search_software",
    "search_detections",
    "search_executables",
    "search_secrets",
    "count_secrets_by_detector",
    "search_network_activity",
    "search_ai_sessions",
    "search_ai_security_risks",
    "count_ai_session_detections",
    "get_ai_session_artifacts",
    "get_asset_details",
    "get_asset_executables",
    "get_executable_details",
    "get_vulnerability_details",
    "get_software_details",
    "get_detection_events",
    "get_detection_controls",
    "get_security_posture",
    "get_remediation_metrics",
    "get_vulnerability_trends",
    "get_tenant_settings",
    "query_sensors",
}

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
