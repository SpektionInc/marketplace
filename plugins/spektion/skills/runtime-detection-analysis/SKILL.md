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
- **Impact levels:** `highest_impact` values are lowercase: critical, high, medium, low
- **CVE likelihood:** `cve_likelihood.probability` is a string (`"high"`, `"medium"`, or `"low"`) with a `description` explaining how the detection correlates with known CVE exploitation patterns
- **Affected scope:** each detection result carries `endpoint_count`, `software_count`, and `elevated_software_count`

## Analysis Workflow

### Step 1: Discover Active Detections

Call `search_detections` to find current behavioral detections:
- `highest_impact: critical` — start with the most severe detections
- `platform`: filter to a specific OS if needed
- `category`: filter by detection type (`runtime_weakness`, `exploit_impact`, `remotely_exploitable`)
- `sort_by`: `highest_impact`, `endpoint_count`, `software_count`, `first_seen`, or `last_seen`
- `limit` (default 20, max 100) and `offset` for pagination

Each result includes `id`, `name`, `description`, `highest_impact`, `category`, `subcategory`, `platform`, `endpoint_count`, `software_count`, `elevated_software_count`, `cve_likelihood`, `first_seen`, and `detail_url`. Keep the `id` — you will need it for evidence and controls.

### Step 2: Pull Evidence Events

For each significant detection, call `get_detection_events` with its `detection_id` (the `id` from `search_detections`; `name` is accepted only when the id is unknown and may return a `candidates` list to disambiguate). The response lists, per affected software product: `software_id`, `software_name`, `first_seen` (event time), `process_path`, `module_name`, `api_function_name` (when present), and `outputs` (the matched evidence parameters).

Use this to answer "show the evidence / events / logs" for a runtime weakness. Never route runtime-weakness evidence requests to `search_ai_security_risks` (that covers the separate AI-security surface).

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

Take affected software names from `get_detection_events.items[].software_name`; `search_detections.software_count` is only a count and cannot identify products. To assess deployment breadth and business impact:
- Call `search_software` for the associated software names to see `endpoint_count`, `cve_count`, `detection_count`, and risk flags (`has_high_risks`, `has_runtime_weakness`, `has_remote_exploitability`)
- Call `get_software_details` for a specific product to see which endpoints have it installed

> **Note:** `get_software_details` groups results by platform. Access software metadata via `items[].software` and per-endpoint data via `items[].assets[]`.

### Step 5: Map Endpoint Impact

`search_detections.endpoint_count` gives the affected count but not endpoint identities. `search_assets` has no detection filter and is capped at 100 with no offset, so never treat high-risk assets on the same platform as affected by this detection.

For bounded corroboration, call `search_assets` for the platform and treat an individual asset as detection-affected only when its `risks[]` contains the exact `risk_id`/detection ID under investigation. State that the result is incomplete whenever the asset search is truncated or the fleet can exceed the returned window. Call `get_asset_details` only for an exact hostname already corroborated this way. If exhaustive endpoint identities are requested, report that the current MCP surface provides the count but cannot enumerate the full set.

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
4. **Affected scope** — exact counts from `search_detections`; software identities from evidence; only individually corroborated endpoint identities, with bounded-search limitations disclosed
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
| Search detections | `search_detections` | `category`, `highest_impact`, `platform`, `sort_by`, `limit`, `offset` |
| Get detection evidence | `get_detection_events` | `detection_id` (preferred) or `name`, `limit` |
| Search matching CVEs | `search_vulnerabilities` | `severity`, `platform`, `has_remote_exploitability`, `sort_by`, `limit`, `offset` |
| Get software details | `get_software_details` | `software_name` (required) |
| Map endpoint impact | `search_assets` | `platform`, `sort_by` (exposure_score, cve_count), `limit` |
| Get asset details | `get_asset_details` | `hostname` (required, exact) |
| Get controls for a weakness | `get_detection_controls` | `detection_id` (required) |
| Check network activity | `search_network_activity` | `software_name` (required), `limit` |
