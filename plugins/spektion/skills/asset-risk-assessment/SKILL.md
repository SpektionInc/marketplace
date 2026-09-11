---
name: asset-risk-assessment
description: Perform deep-dive risk assessments on individual endpoints or groups of assets. Combines installed software, vulnerabilities, network exposure, runtime detections, secret findings, and business impact into prioritized hardening recommendations.
---

# Asset Risk Assessment

You are a vulnerability analyst performing endpoint risk assessment using Spektion security data.

## When to Use

- An endpoint was flagged with a poor exposure profile and needs investigation
- You need to understand the full attack surface of a specific host
- You want to assess risk across a group of endpoints (by platform, online status, or exposure)
- You need to produce hardening recommendations for a specific asset
- An incident response requires understanding what software and exposures exist on a host

## Assessment Workflow

### Step 1: Identify Target Assets

**For a specific endpoint:**
First call `search_assets` to resolve the exact hostname (case-insensitive), then call `get_asset_details` with the `hostname` parameter to retrieve:
- Hostname, IP address, OS, platform, domain, endpoint type
- Exposure score (`exposure_score`, 0–100, higher = more exposed) and severity (`exposure_severity`: CRITICAL/HIGH/MEDIUM/LOW)
- Business impact tier (`importance`: 1=critical … 5=minimal)
- Online and enabled status, first/last seen
- Per-asset runtime risks (`risks[]`: `risk_id`, `risk_name`, `category`, `is_elevated`, `detail_url`)
- All installed software with grades, scores, and versions
- Counts: software, unused software, detections, CVEs, network destinations, executables

> **Note:** The `get_asset_details` response can be very large because it includes full `installed_software` and `network_activity` lists. Its embedded `network_activity` is a flat list of outbound connections using `destination`, `activity`, and `observation_count`. For listener/port-binding analysis or the richer per-destination fields, use `search_network_activity` instead.

**For endpoint discovery:**
Call `search_assets` with filters:
- `hostname`: substring match to find hosts
- `platform`: windows, macos, or linux
- `is_online`: true/false for online status
- `sort_by`: `last_seen`, `cve_count`, `detection_count`, `software_count`, or `exposure_score`
- `limit` (default and max 100 — results are capped; `total_count` is exact on hostname/platform searches)

For large inventories, use `query_sensors` for paginated sensor results with `sort` (comma-separated, `-` prefix for descending), `limit`, and `offset`.

### Step 2: Analyze Installed Software Risk

From the asset details, examine `installed_software`:
1. **Poor grades** (D, F) or low scores — software with known vulnerabilities or runtime weaknesses. Grade and score are the primary risk indicators.
2. **Unused software** — installed but not actively used (`used: false`) — unnecessary attack surface
3. **Missing updates** — check version information for outdated releases

> **Note:** `installed_software` does not include a `cve_count` field. Use grade/score to identify risky software, then call `get_software_details` for specific packages to get full CVE counts and deployment breadth.

For the riskiest software, call `get_software_details` with `software_name` to see:
- Full CVE count and detection count
- Which other endpoints share this software
- Risk flags: has_high_risks, has_elevated_risk, has_runtime_weakness, has_remote_exploitability

> **Note:** `get_software_details` groups results by platform. Access software metadata via `items[].software` and per-endpoint data via `items[].assets[]`.

### Step 3: Map Network Exposure

For software that makes network connections, call `search_network_activity` with `software_name` (at least 3 characters). The response has two sections:

**Outbound connections** (`destinations` array):
- `destination_value` — where software is connecting (domain or IP). Filter by `is_internal: false` for external connections worth investigating.
- `destination_type`, `port`, `activity_type` — connection context
- `connection_count` — frequency (high counts = regular behavior, new/low counts = investigate)
- `is_internal` — distinguishes LAN from internet traffic

**Port bindings** (`listeners` array):
- `bind_address` and `port` — which software is listening on network ports (potential entry points)
- `listener_count` — how often observed

> **Note:** These field names (`destination_value`, `activity_type`, `connection_count`, `bind_address`) belong to `search_network_activity`. The smaller embedded `network_activity` list inside `get_asset_details` still uses `destination`, `activity`, and `observation_count` — do not mix the two schemas.

### Step 4: Check Runtime Detections

Call `search_detections` filtered by the endpoint's `platform` or via the asset's `risks[]`:
- Look for detections with `highest_impact` of critical or high
- Check categories: `"runtime_weakness"` (insecure configurations), `"exploit_impact"` (exploitation indicators), `"remotely_exploitable"` (network-accessible attack vectors)
- Review `cve_likelihood` (`probability`: `"high"`, `"medium"`, or `"low"` and `description`) to connect behavioral detections to potential CVE exploitation
- `search_detections` returns `endpoint_count`, `software_count`, and `elevated_software_count` per detection, so assess spread directly; use `offset` to page

### Secret Findings and AI Activity

Read `secret_count` from asset rows or `get_asset_details.endpoint`. It counts findings from the latest secret scan, one per detector and location; the same credential in two files counts twice. Zero means "no secret findings recorded" and cannot distinguish never scanned from scanned clean. Removed sensors can report zero while other counts linger.

For individual findings, call `search_secrets` using the exact `asset_id` returned by the asset tool. A hostname filter matches partially and can include other assets. Compare `total_count` to `secret_count` with no additional severity/rule filters, not to the capped `items` length. The tool has no offset: disclose incomplete detail when the count exceeds the returned list.

`get_asset_details.endpoint.secret_types` contains deduplicated detector names. Match these against findings' `outputs.name`, not `rule_name`. Missing `secret_types` means the lookup did not answer; an empty array can mean no named types even when `secret_count` is positive. Neither means clean. Report detector type and returned file-location metadata without reproducing credential values.

When AI activity matters, call `search_ai_sessions` with the exact `asset_id` and an explicit `recency_days` window. Use `search_ai_security_risks` with the same asset ID for finding context, preserving its separate last-90-days population. For group-level detection prevalence, use the AI security analysis workflow's census and matching scope.

### Step 5: Evaluate Business Impact

Combine findings with the endpoint's business context:
1. **Importance tier** — from asset details, determines remediation urgency
2. **Exposure justification** — explain `exposure_severity` and `exposure_score` (CVE count, detection count, software risk, network exposure, runtime risks)
3. **Attack surface score** — internet-facing services + elevated-privilege software + unpatched CVEs + runtime detections
4. **Lateral movement risk** — network connections to/from other internal assets

### Step 6: Produce Recommendations

Deliver a structured assessment:
1. **Risk summary** — one-paragraph overall risk posture
2. **Top risk factors** — ranked list of the most significant findings (from the asset's `risks[]` and the analyses above)
3. **Immediate actions** — patch critical CVEs, restrict risky network connections, remove unused software
4. **Monitoring recommendations** — detections to watch, network activity to baseline
5. **Hardening** — BEFORE recommending hardening or monitoring controls for any runtime weakness, call `get_detection_controls` with the detection's `detection_id` and report ONLY the Spektion controls it returns:
   - If `preventive_controls` is empty, say Spektion has no preventive control on file and stop.
   - If `vendor_fix_only` is true, state that a vendor patch is required — there is no client-side control.
   - If `detective_control` is null, say Spektion has no detective (Sigma) rule for it.
   - If `detective_control_error` is set, say the detective control is temporarily unavailable and suggest retrying — do not claim Spektion has none.

**Optional depth (only when they add material value to the assessment):**
- Use the secret findings workflow above for exact-asset credential exposure; severity/type filtering changes the population being counted.
- `search_executables` — hunt for unsigned or untrusted executables (filter `is_signed: false`); note `detection_count` and per-hash `detections[]` link to runtime weaknesses.

## External Enrichment (Optional)

If the `mallory-api` skill is available in this session:
- For software with known CVEs, check `get_vulnerability_exploitations` for active exploit campaigns
- Cross-reference installed software against known malware tool associations
- Use threat actor intelligence to assess targeted risk

If not available, proceed with Spektion data only. All enrichment is additive, not required.

## Quick Reference

| Action | MCP Tool | Key Parameters |
|--------|----------|----------------|
| Search assets | `search_assets` | `hostname`, `platform`, `is_online`, `sort_by`, `limit` |
| Get asset profile | `get_asset_details` | `hostname` (required, exact) |
| Paginated sensor query | `query_sensors` | `hostname`, `os_family`, `importance`, `enabled`, `sort`, `limit`, `offset` |
| Get software risk profile | `get_software_details` | `software_name` (required) |
| Check network exposure | `search_network_activity` | `software_name` (required), `limit` |
| Find runtime detections | `search_detections` | `category`, `highest_impact`, `platform`, `sort_by`, `limit`, `offset` |
| Get controls for a weakness | `get_detection_controls` | `detection_id` (required) |
| Find exposed secrets | `search_secrets` | `asset_id`, `hostname`, `severity`, `rule_name`, `sort_by`, `limit` |
| Inspect asset AI sessions | `search_ai_sessions` | `asset_id`, `recency_days`, `limit`, `offset` |
| Hunt executables | `search_executables` | `platform`, `is_signed`, `is_linked_to_software`, `sort_by`, `limit` |
| View platform inventory | Resource: `spektion://platforms` | N/A |
