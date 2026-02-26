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

**For a specific endpoint:**
Call `get_endpoint_details` with the `hostname` parameter to retrieve:
- Hostname, IP address, OS, platform, domain
- Security grade and score
- Business impact tier (`importance`)
- Online status and last seen timestamp
- All installed software with grades and versions
- Network activity (flat list of connections with `is_internal` classification)
- Software count, risk count, CVE count

> **Note:** The `get_endpoint_details` response can be very large (80KB+) because it includes full `network_activity` and `installed_software` lists. For network analysis, prefer using `search_network_activity` separately rather than relying on the embedded data.

**For endpoint discovery:**
Call `search_endpoints` with filters:
- `hostname`: substring match to find hosts
- `platform`: windows, macos, or linux
- `is_online`: true/false for online status
- `sort_by`: risk_count, cve_count, score, software_count, last_seen
- `limit`: up to 100 results

For large inventories, use `query_sensors` for paginated results with `offset`.

### Step 2: Analyze Installed Software Risk

From the endpoint details, examine `installed_software`:
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

> **Note:** `get_endpoint_details` also includes a `network_activity` flat list, but it only contains outbound connections (no listener data) and can be very large (1000+ entries). Use `search_network_activity` for targeted analysis including listener/port binding data.

### Step 4: Check Runtime Detections

Call `search_detections` filtered by the endpoint's `platform`:
- Look for detections with `highest_impact` of critical or high
- Check categories: `"runtime_weakness"` (insecure configurations), `"exploit_impact"` (exploitation indicators), `"remotely_exploitable"` (network-accessible attack vectors)
- Review `cve_likelihood` (`probability`: `"high"`, `"medium"`, or `"low"` and `description`) to connect behavioral detections to potential CVE exploitation
- To assess spread of a specific detection, use `get_software_details` or `search_software` for the associated software to get endpoint and software counts

### Step 5: Evaluate Business Impact

Combine findings with the endpoint's business context:
1. **Importance tier** — from endpoint details, determines remediation urgency
2. **Grade justification** — explain why the grade is what it is (CVE count, detection count, software risk)
3. **Attack surface score** — internet-facing services + elevated-privilege software + unpatched CVEs + runtime detections
4. **Lateral movement risk** — network connections to/from other internal assets

### Step 6: Produce Recommendations

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

## Quick Reference

| Action | MCP Tool | Key Parameters |
|--------|----------|----------------|
| Get endpoint profile | `get_endpoint_details` | `hostname` (required) |
| Search endpoints | `search_endpoints` | `hostname`, `platform`, `is_online`, `sort_by`, `limit` |
| Paginated endpoint query | `query_sensors` | `hostname`, `os_family`, `importance`, `enabled`, `sort`, `limit`, `offset` |
| Get software risk profile | `get_software_details` | `software_name` (required) |
| Check network exposure | `search_network_activity` | `software_name` (required), `limit` |
| Find runtime detections | `search_detections` | `category`, `highest_impact`, `platform`, `sort_by`, `limit` |
| View platform inventory | Resource: `spektion://platforms` | N/A |
