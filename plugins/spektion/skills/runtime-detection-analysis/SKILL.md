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
- `highest_impact: critical` — start with the most severe detections
- `platform`: filter to a specific OS if needed
- `category`: filter by detection type
- `sort_by: highest_impact` — find the most impactful detections first
- `limit`: up to 100 results

For large datasets, use `query_detection_events` for paginated results with `offset` and `sort`.

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

From detection results, identify affected software by the detection's `name` and `platform`. The `search_detections` response includes `name`, `highest_impact`, `category`, `subcategory`, `platform`, `cve_likelihood`, and `first_seen` — but does not include software or endpoint counts directly.

To assess the scope of a detection, call `search_software` or `get_software_details` for the associated software to understand:
- Deployment breadth (how many endpoints)
- Business impact tiers of affected endpoints
- Whether the software also has known CVEs
- Risk flags (has_high_risks, has_remote_exploitability)

> **Note:** `get_software_details` groups results by platform. Access software metadata via `items[].software` and per-endpoint data via `items[].assets[]`.

### Step 4: Map Endpoint Impact

To assess endpoint impact, use `search_endpoints` sorted by `risk_count` or `cve_count` to find the highest-risk endpoints on the affected platform. For critical endpoints, call `get_endpoint_details` to understand the full risk context.

> **Note:** `search_detections` does not return endpoint counts directly. Use `search_endpoints` filtered by platform to identify affected endpoints, or use `query_detection_events` which returns `asset_count` and `software_count` per detection.

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
| Search detections | `search_detections` | `category`, `highest_impact`, `platform`, `sort_by`, `limit` |
| Paginated detection query | `query_detection_events` | `category`, `severity`, `platform`, `name`, `sort`, `limit`, `offset` |
| Search matching CVEs | `search_vulnerabilities` | `severity`, `has_remote_exploitability`, `sort_by`, `limit` |
| Get software details | `get_software_details` | `software_name` (required) |
| Check network activity | `search_network_activity` | `software_name` (required), `limit` |
| Get endpoint details | `get_endpoint_details` | `hostname` (required) |
