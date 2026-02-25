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
- Network activity (outbound connections, listeners)
- Software count, risk count, CVE count

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
1. **Poor grades** (D, F) — software with known vulnerabilities or runtime weaknesses
2. **High CVE counts** — software contributing the most vulnerability exposure
3. **Unused software** — installed but not actively used (unnecessary attack surface)
4. **Missing updates** — check version information for outdated releases

For the riskiest software, call `get_software_details` with `software_name` to see:
- Full CVE count and detection count
- Which other endpoints share this software
- Risk flags: has_high_risks, has_elevated_risk, has_runtime_weakness, has_remote_exploitability

### Step 3: Map Network Exposure

For software that makes network connections, call `search_network_activity` with `software_name`:
- **Outbound destinations** — where is software connecting? Check for unexpected external destinations
- **Observation count** — frequency of connections (high counts = regular behavior, new/low counts = investigate)
- **Internal vs external** — `is_internal` flag distinguishes LAN from internet traffic
- **Port bindings** — which software is listening on network ports? These are potential entry points

### Step 4: Check Runtime Detections

Call `search_detections` filtered by the endpoint's `platform`:
- Look for detections with `highest_impact` of critical or high
- Check categories: "Runtime Weaknesses", "Exploit Impact", "Remotely Exploitable"
- Cross-reference detection `software_count` and `endpoint_count` to understand if this is isolated or widespread
- Review `cve_likelihood` to connect behavioral detections to potential CVE exploitation

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
