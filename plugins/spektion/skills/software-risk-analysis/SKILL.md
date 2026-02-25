---
name: software-risk-analysis
description: Analyze and prioritize software portfolio risk by combining CVE exposure, runtime detections, network behavior, and deployment breadth. Identifies the riskiest software products and produces actionable risk rankings.
---

# Software Risk Analysis

You are a vulnerability analyst performing software portfolio risk analysis using Spektion security data.

## When to Use

- You need to identify the riskiest software in your environment
- You want to decide which software to sunset, restrict, or prioritize for patching
- You need to understand the risk contribution of a specific software product
- You want to find software with unexpected network behavior or runtime anomalies
- You need to assess supply chain risk by examining software deployment breadth

## Analysis Workflow

### Step 1: Identify Riskiest Software

Start with a broad risk assessment:

**By vulnerability exposure:**
Call `search_software` with `sort_by: cve_count` and `limit: 20` to find software with the most CVEs.

**By runtime risk:**
Call `search_software` with `sort_by: detection_count` to find software triggering the most behavioral detections.

**By deployment breadth:**
Call `search_software` with `sort_by: endpoint_count` to find the most widely deployed software.

**By grade:**
Call `search_software` with `sort_by: grade` to find the worst-graded software products.

For large inventories, use `query_software_inventory` for paginated results with `offset` and `sort` (prefix with `-` for descending, e.g., `-asset_count`).

### Step 2: Deep-Dive Riskiest Products

For each high-risk software product, call `get_software_details` with `software_name` to see:
- **Deployment scope** — which endpoints have it installed, their business impact tiers
- **Version spread** — how many versions are deployed (version fragmentation = patch gaps)
- **Usage status** — which endpoints actively use it vs having it installed but unused
- **Risk flags:**
  - `has_high_risks` — has critical/high severity CVEs
  - `has_elevated_risk` — has elevated risk detections
  - `has_runtime_weakness` — has runtime weakness detections
  - `has_remote_exploitability` — has remotely exploitable CVEs

### Step 3: Analyze Network Behavior

For software that makes network connections (`makes_network_connection: true`), call `search_network_activity` with `software_name`:
- **External destinations** — software connecting outside the network (potential data exfiltration, C2, or legitimate SaaS)
- **Unexpected listeners** — software binding to network ports (potential backdoor or unnecessary service)
- **Connection frequency** — high observation counts indicate regular behavior; new/low counts warrant investigation
- **Internal connections** — lateral movement pathways between hosts

### Step 4: Correlate Runtime Detections

Call `search_detections` to find detections associated with the software:
- Filter by `platform` matching the software's platform
- Look for detections with high `cve_likelihood` — these indicate the software's behavior patterns resemble CVE exploitation
- Check categories: "Runtime Weaknesses" (insecure configurations), "Exploit Impact" (observed exploitation indicators), "Remotely Exploitable" (network-accessible attack vectors)

### Step 5: Produce Risk Ranking

Combine all signals into a composite risk ranking:

| Factor | Source | Weight |
|--------|--------|--------|
| **CVE exposure** | `cve_count`, severity distribution | High |
| **Runtime detections** | `detection_count`, cve_likelihood | High |
| **Deployment breadth** | `endpoint_count` + importance tiers | High |
| **Network exposure** | External connections, listeners | Medium |
| **Exploit availability** | `has_remote_exploitability`, `exploit_impacts` | Medium |
| **Usage status** | Unused installs = unnecessary risk | Low |

Deliver a structured report:
1. **Top 10 riskiest software** — ranked by composite risk score
2. **Highest deployment breadth** — software on the most endpoints (risk amplifiers)
3. **Unused software candidates** — installed but unused (remove to reduce attack surface)
4. **Network exposure concerns** — software with unexpected external connections or listeners
5. **Runtime anomalies** — software triggering behavioral detections
6. **Recommendations** — patch, restrict, sunset, or monitor each product

## External Enrichment (Optional)

If the `mallory-api` skill is available in this session:
- Check if any high-risk software has known malware associations
- Query supply chain risk intelligence for targeted software products
- Cross-reference software versions against known exploit databases

If not available, proceed with Spektion data only. All enrichment is additive, not required.

## Quick Reference

| Action | MCP Tool | Key Parameters |
|--------|----------|----------------|
| Search software | `search_software` | `name`, `sort_by` (cve_count, endpoint_count, detection_count, grade), `limit` |
| Get software details | `get_software_details` | `software_name` (required) |
| Paginated software query | `query_software_inventory` | `name`, `platform`, `sort`, `limit`, `offset` |
| Check network behavior | `search_network_activity` | `software_name` (required), `limit` |
| Find runtime detections | `search_detections` | `category`, `highest_impact`, `platform`, `sort_by`, `limit` |
| View categories | Resource: `spektion://software-categories` | N/A |
| View publishers | Resource: `spektion://software-publishers` | N/A |
