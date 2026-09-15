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
Call `search_detections` with `sort_by: endpoint_count`, `limit: 100`, and page with `offset` until a page returns fewer than `limit` rows; then select the critical/high rows by their returned `highest_impact` field. Filtering a single page instead misses low-prevalence critical rules — a critical detection on one endpoint sorts below every widespread low-impact rule. If you deliberately stop paging early, label the detections section of the report as partial. (Do not use the server-side `highest_impact` filter or `sort_by: highest_impact` — they currently return zero rows / mis-ordered results; ENG-3614.)

**Secrets exposure:**
Call `search_secrets` with `sort_by: severity`, `limit: 10` and read `total_count` for the tenant-wide finding count. Report it as "recorded secret findings" — secret scanning is opt-in per asset, so the absence of findings is not evidence of absence.

**AI agent activity:**
Call `count_ai_session_detections` (with `recency_days: 30` for a current view) for a census of AI-session detections by rule, then `search_ai_sessions` with `severity: critical` or `high` and the same `recency_days` for the sessions behind them. Call `search_ai_security_risks` for AI-related risk findings outside sessions. *(`count_ai_session_detections` requires a server build newer than 2026-09; if it is not in your tool list, use `search_ai_sessions` alone.)*

**SLA context:**
Read the server-computed `sla_status` field on `search_vulnerabilities` results to report overdue vs within-SLA per CVE. (`get_tenant_settings` currently returns a placeholder message, not the SLA policy — do not source thresholds from it.)

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

## Secrets & AI Agent Activity
[Recorded secret findings by severity; AI session counts, detection census, critical/high sessions]

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
| Search detections | `search_detections` | `sort_by: endpoint_count`, `limit` (impact triage client-side — ENG-3614) |
| Count secret findings | `search_secrets` | `severity`, `sort_by`, `limit` (read `total_count`) |
| AI detection census | `count_ai_session_detections` | `severity`, `recency_days` |
| Search AI sessions | `search_ai_sessions` | `severity`, `recency_days`, `sort_by`, `limit`, `offset` |
| Search AI risk findings | `search_ai_security_risks` | `severity`, `source`, `limit`, `offset` |
| Per-CVE SLA status | `search_vulnerabilities` | read `sla_status` on results (`get_tenant_settings` is a placeholder today) |
| View platforms | Resource: `spektion://platforms` | N/A |
