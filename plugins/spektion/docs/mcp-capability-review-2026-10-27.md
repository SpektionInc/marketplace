# MCP capability review — October 27, 2026

## Sources and release target

This review reconciles marketplace PR #3 with fetched marketplace master
`9d2083109088c3cc17d86b17be39ddaedb641a3c` and fetched spektionapi master
`b737be2593d99e13f35880d9e88a6fd361756246`. The registry and actual MCP adapter
export **24 read-only MCP tools and five chat-only tools**. Plugin and marketplace
manifests target **1.2.0**, following master's 1.1.4 and adding the seventh skill.

Tool names, lanes, input schemas, array element types, and numeric wire types
were regenerated from an isolated, clean checkout of that API revision using
`scripts/export_mcp_tools.go`; `scripts/refresh_contract.py --check` reproduced
the result. This establishes source parity, not deployment parity.

The contract's `release_surface_source` remains the separate API hardening
candidate `0eb0f636896543df64e1be01ac9acc47366043de`. Resource and prompt fixtures
are synthetic release requirements from that candidate. Tool response fixtures
are also synthetic, reviewed against the current handlers; they are not captured
production traffic.

## Reconciled changes

| Area | Current source evidence and resulting guidance |
|---|---|
| Tool surface | Add fixtures and live calls for `count_secrets_by_detector`, `get_ai_session_artifacts`, `get_asset_executables`, and `get_executable_details`. The tool-name checker now reads the generated contract instead of maintaining another list. |
| Secret coverage | `tool_secrets_census.go` distinguishes findings, distinct assets, scanned assets, and all assets. Asset counts overlap across detectors; unidentified findings can contribute to totals without a detector row. Read messages and truncation before interpreting an empty census. |
| Secret detail | `tool_secrets.go` supports offset paging, asset scope, and exact `detector_id`. Copy census filters and use that ID for drill-through; a substring detector name does not reproduce a row. Remove obsolete severity filtering and severity sorting. Preserve opt-in scanning and latest-scan finding semantics. |
| AI artifacts | `tool_ai_session_artifacts.go` lists binary/path outputs, not distinct programs. Preserve `artifacts_state`, filter boundaries, and `linked_to_executable`. Inspect only linked hashes through executable detail. Session records themselves remain chat-only. |
| Executable inventory | Preserve master's paging and independent API/analytics compatibility guidance. Add asset inventory and hash-detail workflows; confirm the returned asset identity and distinguish asset paths from fleet-wide hash attributes. |
| Asset paging | `tool_assets.go` now exposes offset. Prefer unsorted enumeration, deduplicate asset IDs, and disclose refresh-boundary movement. Online-status filtering remains a bounded-window query; it cannot establish authoritative fleet totals. |
| Detection impact | `tool_detections.go` now filters and sorts on the enriched returned impact and counts after filtering. Remove claims that the bug is still universal; retain a fallback for deployments without the fix. The current enum includes `informational`. |
| Detection evidence | Preserve master's grouped-evidence paging, unattributed-group semantics, and API/analytics compatibility checks. Asset risk inheritance through installed software does not establish observed behavior on that asset. Fleet-wide evidence must not be labeled as scoped evidence. |
| Vulnerabilities | Retain current `sla_status` filtering and `risk_score` sorting. Keep direct CVE evidence separate from runtime-rule hypotheses. |
| Software flags | `software_projection.go` derives software high-risk and remote-exploitability flags from enabled runtime rules, not CVE severity. Preserve fleet-versus-scope boundaries and signing-label semantics. |
| Existing safeguards | Retain returned-control-only guidance, correct network response field names, SLA counts rather than inferred compliance rates, and scope/error boundaries. |

The five chat-only tools are `get_ai_session_details`, `get_asset_software`,
`get_org_exposure`, `search_ai_inventory`, and `search_software_cve_risks`.
They remain excluded from callable MCP skill steps and the advertised MCP table.

## Validation

- Structural, tool-name, parameter/enum, README surface, and version parity passed.
- Deterministic smoke: **38 checks**, zero errors, covering all 24 tools, five
  resources, and five prompts.
- Validator regressions: **19 tests passed**, including simulated live discovery
  and dependent calls, both census drill-through checks, coverage denominator
  failures, artifact absence/paging, obsolete secret parameters, and case-sensitive
  scope operators.
- API tests passed: `CGO_ENABLED=0 go test ./src/aitools ./src/aitools/mcpadapter`.
- Regeneration check passed against the pinned API revision.
- `claude plugin validate .` and whitespace validation passed.

These are repository and source checks. Simulated live calls do not establish
endpoint, native-client, or deployment acceptance.

## Remaining release requirements

Current API master still contains:

1. A placeholder tenant-settings handler in `src/aitools/tool_analytics.go`.
2. A placeholder SLA policy resource in `src/mcp/resources.go`.
3. Prompt gaps in `src/mcp/prompts.go`: security review and asset assessment
   lack the required returned-control guidance; software analysis lacks explicit
   client-side grade-filter guidance.

The live gate retains those requirements and must reject the placeholder or
incomplete responses. Do not weaken the gate to turn a source check into a
release approval. The release requires the current tool surface plus the
hardening behavior on the target deployment.

The credentialed command returned **LIVE BLOCKED** because `SPEKTION_MCP_URL`
and `SPEKTION_API_KEY` were not available in this session:

```bash
python3 plugins/spektion/scripts/contract_smoke.py --live
```

Acceptance needs a seeded tenant with recent AI detections, a known asset with
secret findings and working type enrichment, executable inventory, and the
existing CVE/software/runtime data. Artifact absence is checked through its
explicit state; live count reconciliation can fail if telemetry changes between
calls and requires investigation. Native-client acceptance remains outstanding.

PR #3 must retain draft/release-blocked status until the combined service behavior
is deployed and credentialed and native-client acceptance are recorded. Resolving
Git conflicts and passing CI alone do not satisfy those requirements.
