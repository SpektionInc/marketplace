# MCP capability review — September 11, 2026

## Sources and release target

Reviewed API master `b9c71bc191bfecd782a9895ed872e3c1b0ecc9e3` against
the plugin's previous tool snapshot at `0eb0f636896543df64e1be01ac9acc47366043de`.
The current registry has **20 MCP tools and eight chat-only tools**. The previous
snapshot already contained those eight chat-only tools; there is one new MCP tool.

The contract's `source` identifies the current registry and MCP input schemas.
`release_surface_source` separately identifies the existing API hardening
candidate for resource/prompt behavior. Response fixtures are synthetic release
expectations, not captured production responses. The combined release target
requires both sets of API behavior.

## New and changed MCP capabilities

| Capability | Source and verified behavior | Plugin use |
|---|---|---|
| `count_ai_session_detections` | `src/aitools/tool_ai_session_detections.go`: both lanes; enabled rules only; distinct sessions per rule, with detected-session and all-session denominators. Hostname, agent, classification, severity, recency and asset scope narrow counts and denominators together. | New `ai-security-analysis` skill and reporting workflow use server aggregation, never inventory-wide client counting. Overlapping rule counts are not summed. |
| `search_ai_sessions` filters | `src/aitools/tool_ai_sessions.go`: new `recency_days` and array-valued `detection_id`; IDs combine with OR. Invalid empty IDs fail closed; unknown IDs match nothing. | Drill-through copies the census window and shared scope, resolves IDs from returned evidence, and separates page size from total matches. |
| Asset secret counts | `src/aitools/tool_assets.go`: `search_assets` and `get_asset_details.endpoint` return exact `asset_id` and latest-scan `secret_count`. Count grain is detector-and-location findings. Zero cannot distinguish unscanned from clean; tombstoned sensors report zero. | Exact-asset `search_secrets` drill-through compares `total_count` with the asset count, without adding filters or treating a capped page as complete. |
| Asset secret types | `get_asset_details.endpoint.secret_types`: optional deduplicated detector names from the detail enrichment; absent means unanswered, empty means no named types, including unnamed findings. The shared MCP asset-list projection still omits types even though analytics list rows carry them. | Asset workflow uses `outputs.name`, not `rule_name`, and preserves unknown/empty/positive-count distinctions. |
| Shared scope arrays | Asset tags are strings; importance values are integers; operators include case-sensitive `notEqual`. | Refreshed contract retains item types. Request and discovery validators reject array type drift. |

Other MCP tools retain their names and parameter sets. Existing asset scope,
AI risk pagination, executable risk enrichment, network context, and vulnerability
and remediation tools remain part of the 20-tool surface. `search_secrets` still
has no offset; `search_assets` remains capped and has no detection-ID filter.
No compiled-artifact tool is registered: the new REST artifact endpoints do not
create MCP access automatically.

## Tools reviewed but unavailable through MCP

All eight entries below are `LaneChat` in the reviewed registry. They remain in
the snapshot's `chat_only_tools` inventory and are excluded from advertised tools
and callable skill steps. Exposing them requires an API lane change and service
deployment before a marketplace workflow can rely on them.

| Tool | Current chat capability | MCP alternative or limit |
|---|---|---|
| `search_ai_inventory` | Canonical AI/ML software inventory | General software searches can provide product context; no equivalent dedicated AI inventory tool. |
| `get_ai_session_details` | Session identity, actor/activity/context metrics and data notes | Session summary fields and console links only. |
| `get_asset_executables` | Asset executable inventory | No exact-asset executable listing tool. |
| `get_executable_details` | Per-hash paths, signatures, detections and endpoints | General executable search and console links. |
| `get_asset_software` | Asset software listing with filters | Installed software embedded in `get_asset_details`. |
| `get_org_exposure` | Organization exposure detail | Headline exposure fields from posture when present. |
| `search_extensions` | Browser-extension findings | No dedicated MCP equivalent. |
| `search_software_cve_risks` | Preemptive and blind-spot software detail | Aggregate blind-spot/preemptive metrics from vulnerability trends; no equivalent detail listing. |

## Existing API release dependencies

The prior snapshot's API hardening revision is on
`eng/2026-09-03-mcp-sla-policy-contract`, not current master. Comparing the
two revisions confirms current master still has:

- A placeholder `get_tenant_settings` implementation in `tool_analytics.go`.
- A placeholder SLA policy resource in `src/mcp/resources.go`.
- Prompt gaps in `src/mcp/prompts.go`: security review and asset assessment omit
  the required returned-control guidance; software analysis lacks the explicit
  client-side grade-filter instruction.

The plugin retains its functional SLA and safe-prompt release requirements.
Live acceptance must fail against those placeholders or incomplete prompts.
Repository fixture success does not show those service changes are merged or
deployed. Bundled workflows must not infer SLA values from unavailable settings.

## Validation and acceptance

The tool snapshot and discovery fixture are reproducible with
`python3 scripts/refresh_contract.py --api ../spektionapi --check`, which executes
the registry and actual MCP adapter. Scalar integer inputs are advertised as
JSON Schema `number` by this adapter; array integer elements remain `integer`.
The contract retains neutral types for argument validation and records differing
MCP types explicitly.

Deterministic checks cover all 20 tools, five resources and five prompts. Added
regressions cover census denominators and overlapping counts, array element
validation, chat-only tool rejection, and simulated live discovery/drill-through.
Live acceptance now includes tenant settings, census-to-session count checks
with the same 30-day window, and exact-asset secret count reconciliation.

Credentialed acceptance needs a seeded tenant with a recent enabled AI detection,
an asset in the discovery page with secret findings and successful type enrichment, plus the existing
CVE/software/runtime-detection fixtures. Concurrent telemetry changes can cause
count reconciliation to fail and require investigation. The read-only checks do
not create tenant data. Deployment and native client acceptance remain separate
from repository checks.

Verified locally: 20-tool parity, 34 fixture checks, 13 validator regressions,
marketplace and changed-skill validation, Python compilation, and API tests for
`./src/aitools` and `./src/aitools/mcpadapter`. The live gate returned
`LIVE BLOCKED` because credentials were unavailable; no endpoint or native-client
acceptance was performed.
