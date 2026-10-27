---
name: remediation-tracking
description: Track vulnerability remediation performance, SLA compliance, and trending direction. Identifies areas falling behind, blindspots with runtime risk but no CVE tracking, and provides actionable improvement recommendations.
---

# Remediation Tracking

You are a vulnerability analyst tracking remediation performance using Spektion security data.

## When to Use

- You need to check SLA compliance across vulnerability severity tiers
- You want to understand if remediation velocity is improving or declining
- You need to identify areas where remediation is falling behind
- You want to find blindspots: software with runtime risk but no tracked CVEs
- You need metrics for a remediation performance review or executive briefing

## Tracking Workflow

### Step 1: Pull Remediation Metrics

Call `get_remediation_metrics` (filters: `severity`, `platform`, `start_time` / `end_time` in ISO 8601) to retrieve:
- **Median days to remediate** — `median_days_to_remediate` with `current`, `previous`, and `total_vulns` (previous = same-length prior window, for trend direction)
- **Mean days to remediate** — `mean_days_to_remediate` with the same shape
- **P10 days** — `p10_days_to_remediate` (best-case remediation speed, top 10% fastest)
- **P90 days** — `p90_days_to_remediate` (worst-case remediation speed, bottom 10% slowest)
- **KEV-specific metrics** — `kev_mean_days_to_remediate` for CISA Known Exploited Vulnerabilities
- **SLA compliance** — `sla_compliance`, a list of items per severity tier: `{severity, onTrack, overdue, totalVulns}`

> **Note:** `sla_compliance` reflects the CURRENT-OPEN population only — it is counts of open vulnerabilities (`onTrack`, `overdue`, `totalVulns`), not a percentage and not a historical-period rate. Report it as counts ("X overdue of Y open critical"), and do not compare P90 remediation time against an SLA threshold — the tools do not return the thresholds. For per-vulnerability compliance, use `sla_status` / `sla_due_date` from `search_vulnerabilities` or `get_vulnerability_details` (see Step 3).

### Step 2: Analyze Vulnerability Trends

Call `get_vulnerability_trends` (same `severity`, `platform`, `start_time`, `end_time` filters) to understand:
- **Vulnerability delta** — `vulnerability_delta[]`: daily `new` vs `resolved`, `delta`, `total_open_vulns`, and `asset_count` (are you keeping up?)
- **Distribution by age/severity** — `vulnerability_distribution[]`: `days` open, `severity`, `count`
- **CVE blindspots** — `cve_blindspot`: `{software, assets, installs}` counts for software with runtime risk detections but no tracked CVE
- **Preemptive CVE exposure** — `preemptive_cve`: `{software, assets, installs}` for software where behavioral detections suggest future CVE risk

### Step 3: Evaluate SLA Compliance

Use `sla_due_date` / `sla_status` from vulnerability data to assess compliance:
1. Call `search_vulnerabilities` per severity tier to review `sla_status` (`overdue`, `due_today`, `due_soon`, `on_track`) on open CVEs
2. Corroborate with `get_remediation_metrics.sla_compliance` counts — identify tiers with large `overdue` counts relative to `totalVulns`
3. Identify severity tiers where P90 remediation time is high (the long tail of slow remediations)
4. Note KEV-specific remediation speed (`kev_mean_days_to_remediate`) against general mean

> **Note:** `sla_status` and `sla_due_date` are computed server-side against the tenant SLA matrix; for SLA questions prefer them over comparing dates yourself.

### Step 4: Identify Problem Areas

Look for patterns in the data:
- **Worsening trend** — mean/median increasing period-over-period (`current` vs `previous`)
- **Severity imbalance** — critical/high vulns meeting SLA but medium/low accumulating
- **Platform gaps** — one platform significantly slower than others
- **KEV lag** — KEV remediation slower than general vuln remediation
- **Growing backlog** — new vulns outpacing resolved vulns in the daily `delta`

For specific problem areas, call `search_vulnerabilities` with `sort_by: endpoint_count` to find the highest-impact unresolved CVEs.

### Step 5: Find Blindspots

From vulnerability trends, review blindspot data:
1. **CVE blindspots** — software with runtime detections but no CVE tracked. These represent risk that traditional vulnerability scanning misses.
2. **Preemptive CVE exposure** — software where behavioral patterns suggest a CVE may emerge. These are early warnings.

For blindspot software, call `get_software_details` to assess deployment breadth and business impact.

> **Note:** `get_software_details` groups results by platform. Access software metadata via `items[].software` and per-endpoint data via `items[].assets[]`.

### Step 6: Produce Status Report

Deliver a structured remediation status:
1. **Overall velocity** — current median/mean vs previous period (improving/declining)
2. **SLA compliance** — open-count status per severity tier (`onTrack`/`overdue`/`totalVulns`) plus `sla_status`-based per-CVE compliance
3. **KEV performance** — KEV remediation speed vs general
4. **Trend direction** — new vs resolved velocity, backlog growth/shrinkage
5. **Problem areas** — specific severity/platform combinations falling behind
6. **Blindspots** — runtime risk not captured by CVE tracking
7. **Recommendations** — where to focus remediation effort for maximum SLA improvement

## Quick Reference

| Action | MCP Tool | Key Parameters |
|--------|----------|----------------|
| Get remediation metrics | `get_remediation_metrics` | `severity`, `platform`, `start_time`, `end_time` |
| Get vulnerability trends | `get_vulnerability_trends` | `severity`, `platform`, `start_time`, `end_time` |
| Search high-impact CVEs | `search_vulnerabilities` | `severity`, `kev`, `sort_by: endpoint_count`, `limit`, `offset` |
| Get software details | `get_software_details` | `software_name` (required) |
