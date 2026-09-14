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

**By score:**
Call `search_software` with `sort_by: score` to find the worst-scored software products.

For large inventories, page through `search_software` with `offset` (results are capped at 100 per page).

### Step 2: Deep-Dive Riskiest Products

For each high-risk software product, call `get_software_details` with `software_name` to see:

> **Note:** `get_software_details` groups results by platform. Access software metadata via `items[].software` and per-endpoint data via `items[].assets[]`.

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
- Look for detections with high `cve_likelihood` (`probability: "high"`) — these indicate the software's behavior patterns resemble CVE exploitation
- Check categories: `"runtime_weakness"` (insecure configurations), `"exploit_impact"` (observed exploitation indicators), `"remotely_exploitable"` (network-accessible attack vectors)
- Note: `search_detections` returns `name`, `highest_impact`, `category`, `subcategory`, `platform`, `cve_likelihood`, `first_seen`, and affected asset/software counts; use `get_detection_events` for the per-software evidence behind a detection

### Step 5: Check Binary-Level Evidence

For risk that software-level views miss, call `search_executables`:
- `is_linked_to_software: false` — binaries not attributed to any canonical software (shadow IT, droppers, custom tooling)
- `is_signed: "false"` — unsigned executables; combine with `sort_by: asset_count` to find widespread unsigned binaries
- Each result includes signing/trust status, asset count, detection categories, and per-detection details (name, category, severity, cve_likelihood)

### Step 6: Produce Risk Ranking

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
| Search software | `search_software` | `name`, `platform`, `category`, `sort_by` (cve_count, endpoint_count, detection_count, score), `limit`, `offset` |
| Get software details | `get_software_details` | `software_name` (required) |
| Check network behavior | `search_network_activity` | `software_name` (required), `limit` |
| Find runtime detections | `search_detections` | `name`, `category`, `platform`, `sort_by`, `limit`, `offset` |
| Find risky executables | `search_executables` | `platform`, `is_signed`, `is_linked_to_software`, `sort_by`, `limit` |
| View categories | Resource: `spektion://software-categories` | N/A |
| View publishers | Resource: `spektion://software-publishers` | N/A |
