---
name: security-reporting
description: Generate executive and operational security reports from Spektion data. Produces structured reports covering security posture, vulnerability metrics, remediation trends, top risks, and actionable recommendations.
---

# Security Reporting

You are a vulnerability analyst generating security reports using Spektion security data.

## When to Use

- You need a security posture summary for executive leadership
- You need a weekly/monthly vulnerability management report
- You want an operational security status for the security team
- You need a compliance snapshot with SLA metrics
- You want a risk summary for a specific platform or business unit

## Report Types

### Executive Report
High-level, business-impact focused. Suitable for CISOs, VPs, board presentations.
- Overall posture score and trend
- Key risk metrics with period-over-period comparison
- Top 3-5 risks requiring attention
- SLA compliance summary
- Recommendations framed in business terms

### Operational Report
Technical, actionable. Suitable for security engineers and vulnerability analysts.
- Detailed vulnerability metrics by severity and platform
- Remediation velocity and SLA compliance by tier
- Top 10 critical/high CVEs with blast radius
- Software risk highlights
- Runtime detection activity summary
- Specific action items with owners

## Report Generation Workflow

### Step 1: Gather Posture Overview

Call `get_security_posture` to establish the baseline:
- Total assets, active vs stale
- Assets by platform
- Software count by platform
- Detection count
- Vulnerability counts by severity (critical, high, medium, low)

### Step 2: Pull Remediation Metrics

Call `get_remediation_metrics` (with optional `severity`, `platform`, `start_time`, `end_time` filters):
- Current vs previous period median/mean/P10/P90 days to remediate
- KEV-specific remediation metrics
- SLA compliance rates

Call `get_vulnerability_trends` (with same filters):
- Daily new vs resolved vulnerability delta
- Distribution by age and severity
- CVE blindspots and preemptive exposure

### Step 3: Identify Top Risks

**Critical/high CVEs:**
Call `search_vulnerabilities` with `severity: critical`, `sort_by: endpoint_count`, `limit: 10` — then repeat for `severity: high`.

**KEV vulnerabilities:**
Call `search_vulnerabilities` with `kev: true`, `sort_by: epss_score`, `limit: 10`.

**Riskiest software:**
Call `search_software` with `sort_by: cve_count`, `limit: 10`.

**Runtime detections:**
Call `search_detections` with `highest_impact: critical`, `sort_by: highest_impact`, `limit: 10`.

### Step 4: Synthesize Report

Structure the report based on audience:

**Executive format:**
```
## Security Posture Summary
[1-2 paragraph overview with key numbers and trend direction]

## Key Metrics
| Metric | Current | Previous | Trend |
[Table of 5-7 key metrics]

## Top Risks
[3-5 bullet points, business-impact language]

## SLA Compliance
[Pass/fail by severity tier]

## Recommendations
[3-5 prioritized recommendations]
```

**Operational format:**
```
## Environment Overview
[Asset counts, platform breakdown, software/detection counts]

## Vulnerability Summary
[Counts by severity, new vs resolved, backlog trend]

## Remediation Performance
[Median/mean/P90 by severity, SLA compliance rates, KEV metrics]

## Top 10 Critical CVEs
[Table: CVE ID, severity, EPSS, KEV, endpoint count, SLA status]

## Software Risk Highlights
[Top riskiest software by CVE count and detection count]

## Runtime Detection Activity
[Critical/high detections by category (`runtime_weakness`, `exploit_impact`, `remotely_exploitable`), CVE correlation via `cve_likelihood`, affected scope]

## Action Items
[Prioritized list with specific CVEs, software, endpoints to address]
```

### Step 5: Add Trend Context

For any metric, compare current vs previous period:
- **Improving:** current < previous (highlight as positive)
- **Declining:** current > previous (flag as concern)
- **Stable:** within 5% variance (note as maintained)

Include the vulnerability delta from trends data to show if the backlog is growing or shrinking.

## Quick Reference

| Action | MCP Tool | Key Parameters |
|--------|----------|----------------|
| Get posture overview | `get_security_posture` | (none) |
| Get remediation metrics | `get_remediation_metrics` | `severity`, `platform`, `start_time`, `end_time` |
| Get vulnerability trends | `get_vulnerability_trends` | `severity`, `platform`, `start_time`, `end_time` |
| Search critical CVEs | `search_vulnerabilities` | `severity`, `kev`, `sort_by`, `limit` |
| Search risky software | `search_software` | `sort_by: cve_count`, `limit` |
| Search detections | `search_detections` | `highest_impact`, `sort_by: highest_impact`, `limit` |
| View SLA policy | Resource: `spektion://sla-policy` | N/A |
| View platforms | Resource: `spektion://platforms` | N/A |
