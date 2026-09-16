---
name: asset-risk-assessment
description: Perform deep-dive risk assessments on individual endpoints or groups of assets. Combines installed software, vulnerabilities, network exposure, runtime detections, and business impact into prioritized hardening recommendations.
---

# Asset Risk Assessment

You are a vulnerability analyst performing endpoint risk assessment using Spektion security data.

## When to Use

- An endpoint was flagged with a poor security grade and needs investigation
- You need to understand the full attack surface of a specific host
- You want to assess risk across a group of endpoints (by platform, online status, or grade)
- You need to produce hardening recommendations for a specific asset
- An incident response requires understanding what software and exposures exist on a host

## Assessment Workflow

### Step 1: Identify Target Assets

**For a specific asset:**
Call `get_asset_details` with the `hostname` parameter (exact hostname, case-insensitive — use `search_assets` first to resolve it) to retrieve:
- Hostname, IP address, OS, platform, domain
- Exposure score (0-100, higher = more exposed) and exposure severity (CRITICAL/HIGH/MEDIUM/LOW)
- Business impact tier (`importance`: 1=critical … 5=minimal, null=unassigned)
- Online status and last seen timestamp
- All installed software with grades and versions
- Network activity (software_name, destination, activity, observation_count, `is_internal`)
- Runtime risks array, plus software/detection/CVE/executable counts
- `secret_count` and `secret_types` — findings from the asset's latest secret scan (see Step 5)

> **Note:** The `get_asset_details` response can be very large because it includes full network activity and installed software lists. For network analysis, prefer using `search_network_activity` separately rather than relying on the embedded data.

**For asset discovery:**
Call `search_assets` with filters:
- `hostname`: substring match to find hosts
- `platform`: windows, macos, or linux
- `is_online`: true/false for online status
- `sort_by`: last_seen (oldest first), or cve_count, detection_count, software_count, exposure_score (descending)
- `limit`: up to 100 results

For large inventories, use `query_sensors` for paginated results with `offset`.

### Step 2: Analyze Installed Software Risk

From the asset details, examine `installed_software`:
1. **Poor grades** (D, F) — software with known vulnerabilities or runtime weaknesses. Grade and score are the primary risk indicators.
2. **Unused software** — installed but not actively used (`used: false`) — unnecessary attack surface
3. **Missing updates** — check version information for outdated releases

> **Note:** `installed_software` does not include a `cve_count` field. Use grade/score to identify risky software, then call `get_software_details` for specific packages to get full CVE counts.

For the riskiest software, call `get_software_details` with `software_name` to see:
- Full CVE count and detection count
- Which other endpoints share this software
- Risk flags: has_high_risks, has_elevated_risk, has_runtime_weakness, has_remote_exploitability

> **Note:** `get_software_details` groups results by platform. Access software metadata via `items[].software` and per-endpoint data via `items[].assets[]`.

### Step 3: Map Network Exposure

For software that makes network connections, call `search_network_activity` with `software_name`. The response has two sections:

**Outbound connections** (`destinations` array):
- `destination` — where software is connecting. Filter by `is_internal: false` for external connections worth investigating.
- `activity` — connection type (e.g., `"connection"`)
- `observation_count` — frequency (high counts = regular behavior, new/low counts = investigate)
- `is_internal` — distinguishes LAN from internet traffic

**Port bindings** (`listeners` array):
- `ip_address` and `port` — which software is listening on network ports (potential entry points)

> **Note:** `get_asset_details` also includes a `network_activity` flat list, but it can be very large (1000+ entries). Use `search_network_activity` for targeted analysis including listener/port binding data.

### Step 4: Check Runtime Detections

Call `search_detections` filtered by the asset's `platform`:
- Look for detections with `highest_impact` of critical or high in the returned rows (triage client-side; the server-side `highest_impact` filter currently returns zero rows — ENG-3614)
- Check categories: `"runtime_weakness"` (insecure configurations), `"exploit_impact"` (exploitation indicators), `"remotely_exploitable"` (network-accessible attack vectors)
- Review `cve_likelihood` (`probability`: `"high"`, `"medium"`, or `"low"` and `description`) to connect behavioral detections to potential CVE exploitation
- To assess spread of a specific detection, use `get_software_details` or `search_software` for the associated software to get endpoint and software counts

### Step 5: Check Secrets and AI Activity Exposure

**Secrets:** from the asset details, read `secret_count` and `secret_types` (deduplicated detector names like "SSH Private Key", "JWT Token"). A positive `secret_count` with an empty `secret_types` is a real state — every finding came from a detector that reports no name — not a contradiction and not a clean asset. For the individual findings and their file locations, call `search_secrets` with `asset_id` (the `asset_id` field from the asset details, not the hostname) and read `total_count`.

> **Note:** a `secret_count` of 0 means "no secret findings recorded" — secret scanning is opt-in, so 0 covers both "never scanned" and "scanned, clean". Never report it as "clean".

**AI agent activity:** call `search_ai_sessions` with `asset_id` (exact match — the `hostname` filter is a partial substring match, so "PROD-WEB-01" also returns "PROD-WEB-010"'s sessions) to see AI coding-agent sessions on the asset (agent, classification, severity, detections fired), and `search_ai_security_risks` with `asset_id` for AI-related risk findings. Sessions with critical/high severity detections are an attack-surface dimension the software inventory does not show.

**Unattributed binaries:** call `search_executables` with `is_linked_to_software: false` (optionally `is_signed: "false"`) to surface unlinked executables among the newest ~100 fleet-wide — unsigned, unattributed binaries on a high-importance asset warrant investigation. (Reach caveat: newest ~100 executables only; `sort_by`/`total_count` unreliable until ENG-3606.)

### Step 6: Evaluate Business Impact

Combine findings with the asset's business context:
1. **Importance tier** — from asset details, determines remediation urgency
2. **Grade justification** — explain why the grade is what it is (CVE count, detection count, software risk)
3. **Attack surface score** — internet-facing services + elevated-privilege software + unpatched CVEs + runtime detections
4. **Lateral movement risk** — network connections to/from other internal assets

### Step 7: Produce Recommendations

Deliver a structured assessment:
1. **Risk summary** — one-paragraph overall risk posture
2. **Top risk factors** — ranked list of the most significant risks
3. **Immediate actions** — patch critical CVEs, restrict risky network connections, remove unused software
4. **Monitoring recommendations** — detections to watch, network activity to baseline
5. **Hardening checklist** — OS hardening, software updates, network segmentation

## External Enrichment (Optional)

If the `mallory-api` skill is available in this session:
- For software with known CVEs, check `get_vulnerability_exploitations` for active exploit campaigns
- Cross-reference installed software against known malware tool associations
- Use threat actor intelligence to assess targeted risk

If not available, proceed with Spektion data only. All enrichment is additive, not required.

## Scoping to a Fleet Subset

Most `search_*` tools accept asset-scope parameters to answer questions like "assess my production servers": `asset_tags` (tag names as the user says them, e.g. "Production", "PCI"), `asset_importance` (Business Impact tiers 1=critical … 5=minimal), and `asset_type` (workstation or server). Each has an `_op` companion (`equals`/`notEqual`). Exceptions: `search_secrets`, `search_ai_security_risks`, and `search_network_activity` do not accept scope parameters — do not pass them there, since results would come back unscoped.

## Quick Reference

| Action | MCP Tool | Key Parameters |
|--------|----------|----------------|
| Get asset profile | `get_asset_details` | `hostname` (required, exact) |
| Search assets | `search_assets` | `hostname`, `platform`, `is_online`, `sort_by`, `limit` |
| Paginated sensor query | `query_sensors` | `hostname`, `os_family`, `importance`, `enabled`, `sort`, `limit`, `offset` |
| Get software risk profile | `get_software_details` | `software_name` (required) |
| Check network exposure | `search_network_activity` | `software_name` (required), `limit` |
| Find runtime detections | `search_detections` | `category`, `platform`, `sort_by`, `limit`, `offset` |
| List secret findings | `search_secrets` | `asset_id`, `detector_name`, `sort_by` (`event_time`/`detector_name`) — `detector_name` filter/sort need server ≥ 2026-09-15 (ENG-3617), `limit` |
| List AI agent sessions | `search_ai_sessions` | `asset_id` (exact; prefer over substring-matching `hostname`), `severity`, `recency_days`, `sort_by`, `limit`, `offset` |
| Find AI risk findings | `search_ai_security_risks` | `asset_id`, `severity`, `source`, `limit`, `offset` |
| Find unattributed binaries | `search_executables` | `platform`, `is_signed`, `is_linked_to_software`, `limit` (newest ~100; ENG-3606) |
| View platform inventory | Resource: `spektion://platforms` | N/A |
