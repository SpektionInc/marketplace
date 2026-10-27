---
name: runtime-detection-analysis
description: Investigate runtime behavioral detections from Spektion sensors. Translates behavioral signals into actionable threat narratives by correlating detections with CVEs, affected software, evidence events, and impacted endpoints.
---

# Runtime Detection Analysis

You are a vulnerability analyst investigating runtime behavioral detections using Spektion security data.

## When to Use

- Runtime detections have been triggered and you need to understand what they mean
- You want to correlate behavioral detections with known CVE exploitation patterns
- You need to identify which software and endpoints are exhibiting risky behavior
- You want to find precursors to CVE exploitation before a vulnerability is publicly tracked
- You need to assess whether detections represent active exploitation or benign behavior

## Understanding Spektion Detections

Spektion detections are **runtime behavioral observations** — distinct from CVEs. They come from Spektion sensors monitoring software behavior on endpoints. Key concepts:

- **Categories:** `"runtime_weakness"` (insecure configs), `"exploit_impact"` (exploitation indicators), `"remotely_exploitable"` (network-accessible attack vectors)
- **Impact levels:** filter `highest_impact` with critical, high, medium, low, or informational; normalize returned capitalization when comparing
- **CVE likelihood:** `cve_likelihood.probability` is a string (`"high"`, `"medium"`, or `"low"`) with a `description` explaining how the detection correlates with known CVE exploitation patterns
- **Affected scope:** each detection result carries `endpoint_count`, `software_count`, and `elevated_software_count`

## Analysis Workflow

### Step 1: Discover Active Detections

Call `search_detections` to find current behavioral detections:
- `sort_by: endpoint_count` — start with the most widespread detections, then triage by the `highest_impact` field on the returned rows (critical/high first)
- `platform`: filter to a specific OS if needed
- `category`: filter by detection type (`runtime_weakness`, `exploit_impact`, `remotely_exploitable`)
- `sort_by`: `highest_impact`, `endpoint_count`, `software_count`, `first_seen`, or `last_seen`
- `limit` (default 20, max 100) and `offset` for pagination

Each result includes `id`, `name`, `description`, `highest_impact`, `category`, `subcategory`, `platform`, `endpoint_count`, `software_count`, `elevated_software_count`, `cve_likelihood`, `first_seen`, and `detail_url`. Keep the `id` — you will need it for evidence and controls.

Current API builds apply `highest_impact` to the returned impact and count after filtering; for critical or high, make one call per level. For deployments without the ENG-3614 fix, page by `endpoint_count` and triage returned impact client-side. Schema presence alone does not prove that older filter bug is fixed.

### Step 2: Pull Evidence Summaries

For evidence behind a specific runtime detection, call `get_detection_events` with its `detection_id` (or resolve by `name`). Results are software-product groups, not individual events; `total_count` includes one unattributed group when present.

**Server compatibility:** Paging and the new response fields require a deployed API build containing [spektionapi#373](https://github.com/SpektionInc/spektionapi/pull/373); deterministic ordering of tied groups requires [spektion-analytics#264](https://github.com/SpektionInc/spektion-analytics/pull/264). Before paging, verify that the exposed tool schema declares `offset` and the first response echoes it. If either check fails or cannot be verified, stop after the first page and report that complete enumeration is unavailable. Do not send offsets to an older server: it can ignore them and repeat the first page. On older builds, a zero-UUID `software_id` still represents the combined unattributed group even without `unattributed=true`.

Page only as far as needed with `limit` (default 20, max 100) and `offset` (default 0, max 4294967295). After a nonempty page, advance offset by the limit used until `offset + returned` reaches `total_count`; `truncated=true` means groups remain. Stop advancing on any empty page and read `message` if present: a failed count probe means zero is unknown; a page/count disagreement means live data may have shifted, so restart at offset 0 only if enumeration is still needed. An empty page with `total_count=0` and no message means no groups were found. Each page recomputes the detection's history, so avoid exhaustive walks unless the question needs them.

`unattributed=true` combines executables not linked to a product, has no `software_id`, and must not be presented as one program. Payload fields summarize latest evidence, while `first_seen` is the earliest group observation; equal latest timestamps can mix fields from different events. Live updates can repeat or skip groups across pages, so a walk is not a snapshot. These rows do not establish raw event frequency, executable counts, or which asset triggered an event.

Use `detection_id` from discovery. A name lookup can return `candidates`; disambiguate before interpreting evidence. Runtime-weakness evidence belongs here, not to the separate AI-security finding tool.

### Step 3: Analyze Possible CVE Context

For each significant detection, examine:
1. **CVE likelihood probability** — `probability: "high"` means the behavioral pattern strongly resembles known CVE exploitation. Values are `"high"`, `"medium"`, or `"low"` (strings, not numeric).
2. **CVE likelihood description** — explains which CVE exploitation patterns the behavior matches
3. **Detection category** — `"exploit_impact"` detections are the strongest CVE correlation signals

For detections with high CVE likelihood, call `search_vulnerabilities` to find candidate CVE context:
- Filter by the same `platform`
- Look for CVEs affecting the same software products
- Check `exploit_maturity` and `has_remote_exploitability` to assess if exploitation is feasible

This is a heuristic comparison, not an exact join: neither `search_detections` nor `get_detection_events` returns a CVE ID. Platform or software-name overlap does not prove that an event exploited a particular CVE, affected the same version, or occurred on the same endpoint. Unless another tool or cited source supplies a direct mapping, label the relationship as an unverified hypothesis and do not claim CVE exploitation was observed.

### Step 4: Identify Affected Software

Take product identities from `get_detection_events.items[].software_name`, excluding the combined unattributed group. A detection's own name and platform do not identify a software product.

For available mitigations and compensating controls, call `get_detection_controls` with the same `detection_id`.

To assess the deployment scope of the affected software, call `search_software` or `get_software_details` to understand:
- Deployment breadth (how many endpoints)
- Business impact tiers of affected endpoints
- Whether the software also has known CVEs
- Risk flags (has_high_risks, has_remote_exploitability)

> **Note:** `get_software_details` groups results by platform. Access software metadata via `items[].software` and per-endpoint data via `items[].assets[]`.

Under an asset scope, discovery counts narrow to the requested assets but evidence summaries remain fleet-wide. Do not label those summaries as scoped observations.

### Step 5: Map Endpoint Impact

Each `search_detections` row carries the affected asset count. To find the highest-risk assets on the affected platform, use `search_assets` sorted by `detection_count` or `cve_count`; each returned asset includes a `risks` array (risk_id, risk_name, category). Read that array as **risks associated with the asset's installed software**, not as observed behavior: an asset inherits a detection when any asset shares the same canonical software, even if it never triggered the detection itself. Do not claim a specific asset exhibited the behavior — `get_detection_events` evidence is per-software and fleet-wide, so asset-level observation is not available from this surface; attribute behavior to the software, and to assets only as "at risk via installed software". For critical assets, call `get_asset_details` with the exact hostname to understand the full risk context.

### Step 6: Obtain Hardening and Monitoring Guidance

BEFORE recommending hardening or monitoring controls for a runtime weakness, call `get_detection_controls` with the detection's `detection_id` and report ONLY the Spektion controls it returns:
- `preventive_controls[]` — Spektion hardening guidance (each with `title`, `description`, `effectiveness`, `effort`)
- `vendor_fix_only` — when true, Spektion has determined there is NO client-side preventive control; remediation requires a vendor patch — report that and do not offer hardening steps as a fix
- `detective_control` — a Spektion-provided Sigma detection-rule for monitoring (format `sigma`)
- Edge cases: if `preventive_controls` is empty, say Spektion has no preventive control on file and stop; if `detective_control` is null, say Spektion has none; if `detective_control_error` is set, say the detective control is temporarily unavailable and suggest retrying — never fill the gap with generic hardening or monitoring advice.

### Step 7: Check Network Context

For software associated with `"remotely_exploitable"` detections, call `search_network_activity`:
- Are the affected software products making external network connections? (`destinations[]`: `destination_value`, `destination_type`, `port`, `activity_type`, `is_internal`, `connection_count`)
- Are they binding to network ports? (`listeners[]`: `bind_address`, `port`, `activity_type`, `listener_count`)
- Do network patterns suggest active exploitation (unexpected destinations, high-frequency connections)?

### Step 8: Produce Threat Narrative

Synthesize findings into an actionable narrative:
1. **Detection summary** — what behaviors were observed, how severe, how widespread (`endpoint_count`, `software_count`)
2. **Evidence** — what the event logs show (process paths, modules, API functions, matched outputs)
3. **Possible CVE context** — clearly labeled hypotheses based on rule-level likelihood and product/platform overlap; never an asserted CVE-event mapping without direct evidence
4. **Affected scope** — counts from discovery and software identities from evidence; describe asset risks as inherited through installed software unless separate evidence confirms behavior on that asset. Asset search supports paging but has no detection-ID filter; match the requested risk ID only to identify assets at risk via installed software, and preserve the paging and completeness limits in the asset workflow.
5. **Network exposure** — are affected systems network-accessible or making suspicious connections
6. **Controls** — Spektion's own preventive/detective controls for the weakness (from `get_detection_controls`)
7. **Risk assessment** — distinguish verified behavior, inferred possibilities, and unknowns; do not label activity as exploitation without direct evidence

## External Enrichment (Optional)

If the `mallory-api` skill is available in this session:
- Correlate detection patterns with known threat actor TTPs from MITRE ATT&CK
- Check if behavioral signatures match known exploit tool indicators
- Query threat intelligence for active campaigns targeting the affected software

If not available, proceed with Spektion data only. All enrichment is additive, not required.

## Quick Reference

| Action | MCP Tool | Key Parameters |
|--------|----------|----------------|
| Search detections | `search_detections` | `name`, `category`, `platform`, `sort_by`, `limit`, `offset` |
| Detection evidence summaries | `get_detection_events` | `detection_id` (preferred) or `name`, `limit` (max 100), `offset` (max 4294967295) |
| Get mitigations/controls | `get_detection_controls` | `detection_id` (required) |
| Search matching CVEs | `search_vulnerabilities` | `severity`, `has_remote_exploitability`, `sort_by`, `limit` |
| Get software details | `get_software_details` | `software_name` (required) |
| Map endpoint impact | `search_assets` | `platform`, `sort_by` (exposure_score, cve_count), `limit` |
| Get asset details | `get_asset_details` | `hostname` (required, exact) |
| Check network activity | `search_network_activity` | `software_name` (required), `limit` |
