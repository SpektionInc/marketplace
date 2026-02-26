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

Call `get_remediation_metrics` to retrieve:
- **Median days to remediate** — current period, previous period, total vulns
- **Mean days to remediate** — current vs previous for trend direction
- **P10 days** — best-case remediation speed (top 10% fastest)
- **P90 days** — worst-case remediation speed (bottom 10% slowest)
- **KEV-specific metrics** — remediation speed for CISA Known Exploited Vulnerabilities
- **SLA compliance rates** — percentage meeting SLA by severity tier

Use filters to drill down:
- `severity`: focus on a specific severity tier (critical, high, medium, low)
- `platform`: compare remediation across Windows, macOS, Linux
- `start_time` / `end_time`: ISO 8601 format for custom time ranges

### Step 2: Analyze Vulnerability Trends

Call `get_vulnerability_trends` to understand:
- **Vulnerability delta** — daily new vs resolved CVEs (are you keeping up?)
- **Distribution by age** — how old are your open vulnerabilities?
- **Distribution by severity** — concentration in critical/high vs medium/low
- **CVE blindspots** — software with runtime risk detections but no tracked CVE (preemptive exposure)
- **Preemptive CVE exposure** — software where behavioral detections suggest future CVE risk

Use the same `severity`, `platform`, `start_time`, `end_time` filters for consistency.

### Step 3: Evaluate SLA Compliance

Use `sla_due_date` from vulnerability data to assess compliance:
1. Call `search_vulnerabilities` with each severity tier to review `sla_due_date` on open CVEs
2. For each severity tier, check if median/mean days are within SLA thresholds from `get_remediation_metrics`
3. Identify severity tiers where P90 exceeds SLA (the long tail of slow remediations)
4. Check if KEV remediation meets the faster KEV-specific SLA targets

### Step 4: Identify Problem Areas

Look for patterns in the data:
- **Worsening trend** — mean/median increasing period-over-period
- **Severity imbalance** — critical/high vulns meeting SLA but medium/low accumulating
- **Platform gaps** — one platform significantly slower than others
- **KEV lag** — KEV remediation slower than general vuln remediation
- **Growing backlog** — new vulns outpacing resolved vulns in the delta

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
2. **SLA compliance** — pass/fail by severity tier with specific metrics
3. **KEV performance** — dedicated metrics for CISA mandated vulnerabilities
4. **Trend direction** — new vs resolved velocity, backlog growth/shrinkage
5. **Problem areas** — specific severity/platform combinations falling behind
6. **Blindspots** — runtime risk not captured by CVE tracking
7. **Recommendations** — where to focus remediation effort for maximum SLA improvement

## Quick Reference

| Action | MCP Tool | Key Parameters |
|--------|----------|----------------|
| Get remediation metrics | `get_remediation_metrics` | `severity`, `platform`, `start_time`, `end_time` |
| Get vulnerability trends | `get_vulnerability_trends` | `severity`, `platform`, `start_time`, `end_time` |
| Search high-impact CVEs | `search_vulnerabilities` | `severity`, `kev`, `sort_by: endpoint_count`, `limit` |
| Get software details | `get_software_details` | `software_name` (required) |
