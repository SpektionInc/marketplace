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
- Business impact tier (`importance`: 1=critical … 5=minimal, null=unassigned)
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
- `sort_by`: last_seen (oldest first), or cve_count, detection_count, software_count, exposure_score (descending)
- `limit`: up to 100 results, with `offset` for pagination

For asset enumeration, verify the deployed schema declares `offset` and the response echoes it. Page without `sort_by`, advancing by the requested limit, and deduplicate by `asset_id`: sorted ties can skip or repeat assets, and a walk across the 15-minute refresh boundary can move even without sorting. An `is_online` filter scans a bounded window; inspect `window_incomplete`, `scanned`, `truncated`, and `message`, and do not present that count as a full-fleet total. Use posture for authoritative active/stale/disabled counts. Older servers without offset support return only a capped sample. For sensor-specific fields, use `query_sensors` with `sort`, `limit`, and `offset`.

### Step 2: Analyze Installed Software Risk

From the asset details, examine `installed_software`:
1. **Poor grades** (D, F) — software with known vulnerabilities or runtime weaknesses. Grade and score are the primary risk indicators.
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

Use the asset's `risks[]` to identify relevant detection IDs, then use `search_detections` for rule context. Platform-only matches are fleet context, not evidence of behavior on this asset. Asset risks can be inherited through installed software:
- Look for detections with `highest_impact` of critical or high
- Check categories: `"runtime_weakness"` (insecure configurations), `"exploit_impact"` (exploitation indicators), `"remotely_exploitable"` (network-accessible attack vectors)
- Review `cve_likelihood` (`probability`: `"high"`, `"medium"`, or `"low"` and `description`) to connect behavioral detections to potential CVE exploitation
- `search_detections` returns `endpoint_count`, `software_count`, and `elevated_software_count` per detection, so assess spread directly; use `offset` to page

### Step 5: Check Secrets, AI Activity, and Executables

Read `secret_count` from asset rows or `get_asset_details.endpoint`. It counts findings from the latest secret scan, one per detector and location; the same credential in two files counts twice. Zero means "no secret findings recorded" and cannot distinguish never scanned from scanned clean. Removed sensors can report zero while other counts linger.

For individual findings, call `search_secrets` using the exact `asset_id` returned by the asset tool. A hostname filter matches partially and can include other assets. Compare `total_count` to `secret_count` with no additional detector filters, not to the `items` length. Current builds support `offset`; advance it by the requested limit until `offset + returned` reaches `total_count`. Verify the exposed schema declares `offset` and the response echoes it before paging an older deployment; otherwise label the returned list as a sample. Secret scanning is opt-in. Do not filter or rank findings by the constant wrapper `severity` or `rule_name`.

`get_asset_details.endpoint.secret_types` contains deduplicated detector names. Match these against findings' `detector_name`, with `outputs.name` as a fallback for older builds; never use the wrapper `rule_name` as the secret type. Missing `secret_types` means the lookup did not answer; an empty array can mean no named types even when `secret_count` is positive. Neither means clean. Report detector type and returned file-location metadata without reproducing credential values.

When AI activity matters, call `search_ai_sessions` with the exact `asset_id` and an explicit `recency_days` window. Use `search_ai_security_risks` with the same asset ID for finding context, preserving its separate last-90-days population. For group-level detection prevalence, use the AI security analysis workflow's census and matching scope.

**Asset executable inventory:** when available, call `get_asset_executables` with the resolved hostname. Confirm the returned `hostname`, `sensor_id`, and `enabled` state before attributing rows to the asset; hostname lookup permits partial matches. Page by the echoed `limit` and `offset`, and deduplicate hashes across changing pages. Paths, execution counts, and first/last seen belong to this asset, while signing and detection summaries describe the hash across the fleet. Call `get_executable_details` with a returned hash for paths, certificates, endpoints, and detections; preserve any supported asset scope. A detail path can be historical, so inspect its last-seen fields.

The fleet search below does not accept an exact asset ID or hostname. Do not attribute one of its rows to this asset without the asset inventory or executable endpoint evidence.

For signing labels and scoped detection/provenance limits, follow the software-risk-analysis workflow.

**Unattributed binaries:** call `search_executables` with `is_linked_to_software: false` (optionally `is_signed: "false"`) to surface unlinked executables — unsigned, unattributed binaries on a high-importance asset warrant investigation. Both filters run server-side, so `total_count` describes the filtered set rather than a sample of it.

Page with `limit` (default 20, max 100) and `offset` (default 0). Advance offset by the **echoed** `limit` — a larger request is clamped to `max_limit` and advancing by what you asked for skips the difference every page — until `offset + returned` reaches `total_count`; `truncated=true` means executables remain. Do **not** stop because a page returned fewer items than the limit — `returned` counts the rows left after software-linkage filtering, so a short page can still be followed by more.

**Dedupe by hash, and report the distinct count.** Ordering is total within one snapshot of the list, but the list is rebuilt every 15 minutes (a scoped list is computed live and can move between any two pages), and a walk that crosses a rebuild can both repeat and skip rows: newly seen executables enter at the head of the default order and push unvisited ones past the offset already reached. The two cancel out, so the rows collected still equal `total_count` even when some are missing — that arithmetic is not evidence of completeness. Prefer the default order for an exhaustive walk; `sort_by=last_seen` re-ranks every recently active executable to the head at each rebuild, so treat it and `asset_count` as ways to see the top of a ranking rather than all of it.

**Server compatibility.** Two halves deploy independently ([spektionapi#374](https://github.com/SpektionInc/spektionapi/pull/374) and [spektion-analytics#261](https://github.com/SpektionInc/spektion-analytics/pull/261)), and they fail in **different** ways. Check both.

**Is the API new?** The exposed tool schema declares `offset`, and the first response echoes `offset` and `limit`. If not, this build cannot page: the reach is the newest ~100 executables fleet-wide, `sort_by` is inert, and an offset it never declared is ignored, so asking for one returns the first page again. Stop after one page and say that complete enumeration is unavailable — never present a repeated first page as further results.

**Is analytics new?** The response does **not** carry `total_count_unavailable: true`. If it does, paging still works — keep advancing `offset` while `truncated` is present — but the server applied **none** of `platform`, `is_signed` or `sort_by`. Only `is_linked_to_software` was honoured, and the API filtered it after the fact rather than in the query. In that state:

- **Re-check `is_signed` and `platform` on every returned row yourself** and discard the ones that do not match what you asked for. Trusting them is how a signed binary gets reported as unsigned — the exact mistake this step exists to avoid.
- Treat any ranking as arrival order, not as `sort_by`. Do not describe results as "most widespread".
- `total_count` is absent, not zero. Never read its absence as an empty inventory, and give a count only for what you actually collected and deduped.

### Step 6: Evaluate Business Impact

Combine findings with the asset's business context:
1. **Importance tier** — from asset details, determines remediation urgency
2. **Exposure justification** — explain `exposure_score` and `exposure_severity` using the returned risk factors
3. **Attack surface score** — internet-facing services + elevated-privilege software + unpatched CVEs + runtime detections
4. **Lateral movement risk** — network connections to/from other internal assets

### Step 7: Produce Recommendations

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
- Use the secret findings workflow above for exact-asset credential exposure; detector filtering changes the population being counted.
- `search_executables` — hunt for unsigned or untrusted executables (filter `is_signed: "false"`); note `detection_count` and per-hash `detections[]` link to runtime weaknesses.

## External Enrichment (Optional)

If the `mallory-api` skill is available in this session:
- For software with known CVEs, check `get_vulnerability_exploitations` for active exploit campaigns
- Cross-reference installed software against known malware tool associations
- Use threat actor intelligence to assess targeted risk

If not available, proceed with Spektion data only. All enrichment is additive, not required.

## Scoping to a Fleet Subset

Most `search_*` tools accept asset-scope parameters to answer questions like "assess my production servers": `asset_tags` (tag names as the user says them, e.g. "Production", "PCI"), `asset_importance` (an array of integer Business Impact tiers 1=critical … 5=minimal), and `asset_type` (workstation or server). Each has an `_op` companion (`equals`/`notEqual`). Exceptions: `search_ai_security_risks` and `search_network_activity` do not accept scope parameters — do not pass them there, since results would come back unscoped.

## Quick Reference

| Action | MCP Tool | Key Parameters |
|--------|----------|----------------|
| Get asset profile | `get_asset_details` | `hostname` (required, exact) |
| Search assets | `search_assets` | `hostname`, `platform`, `is_online`, `sort_by`, `limit`, `offset` |
| Paginated sensor query | `query_sensors` | `hostname`, `os_family`, `importance`, `enabled`, `sort`, `limit`, `offset` |
| Get software risk profile | `get_software_details` | `software_name` (required) |
| Check network exposure | `search_network_activity` | `software_name` (required), `limit` |
| Find runtime detections | `search_detections` | `category`, `platform`, `sort_by`, `limit`, `offset` |
| Get returned controls | `get_detection_controls` | `detection_id` |
| List asset executables | `get_asset_executables` | `hostname`, `limit`, `offset` |
| Inspect an executable | `get_executable_details` | `hash`, `asset_tags`, `asset_importance`, `asset_type` |
| List secret findings | `search_secrets` | `asset_id`, `detector_id`, `detector_name`, `sort_by`, `limit`, `offset` |
| List AI agent sessions | `search_ai_sessions` | `asset_id` (exact; prefer over substring-matching `hostname`), `severity`, `recency_days`, `sort_by`, `limit`, `offset` |
| Find AI risk findings | `search_ai_security_risks` | `asset_id`, `severity`, `source`, `limit`, `offset` |
| Find unattributed binaries | `search_executables` | `platform`, `is_signed`, `is_linked_to_software`, `sort_by`, `limit`, `offset` |
| View platform inventory | Resource: `spektion://platforms` | N/A |
