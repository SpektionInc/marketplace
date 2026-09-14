---
name: runtime-detection-analysis
description: Investigate runtime behavioral detections from Spektion sensors. Translates behavioral signals into actionable threat narratives by correlating detections with CVEs, affected software, and impacted endpoints.
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
- **Impact levels:** critical, high, medium, low — based on potential damage
- **CVE likelihood:** `probability` is a string (`"high"`, `"medium"`, or `"low"`) with a `description` explaining how the detection correlates with known CVE exploitation patterns
- **Affected scope:** which software products and endpoints exhibit the behavior

## Analysis Workflow

### Step 1: Discover Active Detections

Call `search_detections` to find current behavioral detections:
- `sort_by: endpoint_count` — start with the most widespread detections, then triage by the `highest_impact` field on the returned rows (critical/high first)
- `platform`: filter to a specific OS if needed
- `category`: filter by detection type
- `limit`: up to 100 results, with `offset` for pagination

> **Note:** do not use the server-side `highest_impact` filter or `sort_by: highest_impact` — they currently return zero rows / mis-ordered results for every documented value (ENG-3614). Triage impact client-side from the returned `highest_impact` field instead.

### Step 2: Analyze CVE Correlation

For each significant detection, examine:
1. **CVE likelihood probability** — `probability: "high"` means the behavioral pattern strongly resembles known CVE exploitation. Values are `"high"`, `"medium"`, or `"low"` (strings, not numeric).
2. **CVE likelihood description** — explains which CVE exploitation patterns the behavior matches
3. **Detection category** — `"exploit_impact"` detections are the strongest CVE correlation signals

For detections with high CVE likelihood, call `search_vulnerabilities` to find matching CVEs:
- Filter by the same `platform`
- Look for CVEs affecting the same software products
- Check `exploit_maturity` and `has_remote_exploitability` to assess if exploitation is feasible

### Step 3: Identify Affected Software

From detection results, identify affected software by the detection's `name` and `platform`. The `search_detections` response includes `name`, `highest_impact`, `category`, `subcategory`, `platform`, `cve_likelihood`, `first_seen`, and affected asset and software counts.

For the evidence behind a detection — the per-software event log (process path, module, API function, matched outputs) — call `get_detection_events` with the `detection_id` from the search results (or `name` to resolve it). For available mitigations and compensating controls, call `get_detection_controls` with the same `detection_id`.

To assess the deployment scope of the affected software, call `search_software` or `get_software_details` to understand:
- Deployment breadth (how many endpoints)
- Business impact tiers of affected endpoints
- Whether the software also has known CVEs
- Risk flags (has_high_risks, has_remote_exploitability)

> **Note:** `get_software_details` groups results by platform. Access software metadata via `items[].software` and per-endpoint data via `items[].assets[]`.

### Step 4: Map Endpoint Impact

Each `search_detections` row carries the affected asset count. To find the highest-risk assets on the affected platform, use `search_assets` sorted by `detection_count` or `cve_count`; each returned asset includes a `risks` array (risk_id, risk_name, category), so you can confirm which assets exhibit the specific detection. For critical assets, call `get_asset_details` with the exact hostname to understand the full risk context.

### Step 5: Check Network Context

For software associated with `"remotely_exploitable"` detections, call `search_network_activity`:
- Are the affected software products making external network connections?
- Are they binding to network ports (check `search_network_activity` for listener data)?
- Do network patterns suggest active exploitation (unexpected destinations, high-frequency connections)?

### Step 6: Produce Threat Narrative

Synthesize findings into an actionable narrative:
1. **Detection summary** — what behaviors were observed, how severe, how widespread
2. **CVE correlation** — which detections map to known CVE exploitation patterns
3. **Affected scope** — which software and endpoints, business impact tiers
4. **Network exposure** — are affected systems network-accessible or making suspicious connections
5. **Risk assessment** — is this active exploitation, precursor activity, or benign behavior?
6. **Recommended actions:**
   - **Immediate:** isolate high-risk endpoints, restrict network access
   - **Short-term:** patch software with correlated CVEs
   - **Monitoring:** establish baselines for detection frequency

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
| Get detection evidence | `get_detection_events` | `detection_id` (preferred) or `name`, `limit` |
| Get mitigations/controls | `get_detection_controls` | `detection_id` (required) |
| Search matching CVEs | `search_vulnerabilities` | `severity`, `has_remote_exploitability`, `sort_by`, `limit` |
| Get software details | `get_software_details` | `software_name` (required) |
| Check network activity | `search_network_activity` | `software_name` (required), `limit` |
| Find affected assets | `search_assets` | `hostname`, `platform`, `sort_by`, `limit` |
| Get asset details | `get_asset_details` | `hostname` (required, exact) |
