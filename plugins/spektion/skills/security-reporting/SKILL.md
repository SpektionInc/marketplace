---
name: security-reporting
description: Generate executive and operational security reports from Spektion data. Produces structured reports covering security posture, vulnerability metrics, remediation trends, top risks, AI detection prevalence, and actionable recommendations.
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
- AI security and secrets exposure (when relevant)
- Specific action items with owners

## Report Generation Workflow

### Step 1: Gather Posture Overview

Call `get_security_posture` to establish the baseline:
- Total assets, with an active / stale / disabled breakdown (`active_assets`, `stale_assets`, `disabled_assets` — disjoint and summing to `total_assets`; `stale_threshold_days` = 30)
- Assets by platform (`assets_by_platform`)
- Total canonical software and software by platform (`total_software`, `software_by_platform`)
- Vulnerability counts by severity (`vulnerabilities_by_severity`: critical, high, medium, low, unknown) and `total_vulnerabilities`
- Total runtime detections (`total_detections`, when available)
- Organizational exposure headline when present: `org_exposure_score`, `org_exposure_severity`, `org_exposure_delta` (change vs previous period; negative means improving)

### Step 2: Pull Remediation Metrics

Call `get_remediation_metrics` (with optional `severity`, `platform`, `start_time`, `end_time` filters):
- Current vs previous period `median`/`mean`/`p10`/`p90_days_to_remediate` (each `{current, previous, total_vulns}`)
- `kev_mean_days_to_remediate` for CISA KEV vulnerabilities
- `sla_compliance` — current-open counts per severity tier (`{severity, onTrack, overdue, totalVulns}`)

> **Note:** Report SLA compliance as counts of the currently open population, not as a percentage or pass/fail rate. Do not compare remediation times against SLA thresholds — the tools do not return thresholds; use `sla_status`/`sla_due_date` from `search_vulnerabilities` / `get_vulnerability_details` for per-CVE compliance statements.

Call `get_vulnerability_trends` (with the same filters):
- Daily new vs resolved vulnerability delta (`vulnerability_delta[]`: `date`, `delta`, `new`, `resolved`, `total_open_vulns`, `asset_count`)
- Distribution by age and severity (`vulnerability_distribution[]`: `days`, `severity`, `count`)
- CVE blindspots and preemptive exposure (`cve_blindspot`, `preemptive_cve`: `{software, assets, installs}`)

### Step 3: Identify Top Risks

**Critical/high CVEs:**
Call `search_vulnerabilities` with `severity: critical`, `sort_by: endpoint_count`, `limit: 10` — then repeat for `severity: high`. Include `sla_status` for compliance context.

**KEV vulnerabilities:**
Call `search_vulnerabilities` with `kev: true`, `sort_by: epss_score`, `limit: 10`.

**Riskiest software:**
Call `search_software` with `sort_by: cve_count`, `limit: 10`.

**Runtime detections:**
Call `search_detections` with `highest_impact: critical`, then repeat with `highest_impact: high`; current builds filter the returned impact, and `total_count` counts the filtered population before paging. Page with `limit` and `offset` when the question needs every match. On a deployment without the ENG-3614 fix, page by `sort_by: endpoint_count` without an impact filter and select returned impact client-side. Label an incomplete walk as partial; schema presence alone does not establish the filter fix is deployed.

**Secrets exposure:**
Use `count_secrets_by_detector` for totals and detector coverage. Report `finding_count` and distinct `asset_count` per detector alongside `findings_total`, `assets_with_findings`, `assets_scanned_for_secrets`, and `assets_total`. Per-detector asset counts overlap; findings with incomplete detector identities can contribute to the total without a row. Inspect `message` and `truncated` before interpreting zeros or claiming all detector types are listed.

For selected findings, call `search_secrets` with the returned exact `detector_id` and the SAME hostname, asset ID, and asset scope as the census. A substring `detector_name` filter can include other detectors and cannot reproduce an exact census row. Current builds page using `offset`; verify that schema and response support it before paging older deployments. If census or paging is unavailable, disclose that any returned detector list is a sample. Use `detector_name` (or `outputs.name` on older builds), never the constant wrapper severity/rule name, to describe types. Do not copy secret values. Zero findings do not establish that unscanned assets are clean.

**AI agent activity:**
Follow the AI workflow below for census and matching session drill-through. If the census tool is absent from discovery, use session search for a bounded investigation and disclose that detection prevalence is unavailable.

**SLA context:**
Read the server-computed `sla_status` field on `search_vulnerabilities` results to report overdue vs within-SLA per CVE. (`get_tenant_settings` currently returns a placeholder message, not the SLA policy — do not source thresholds from it.)

**AI security and secrets (operational reports, when relevant):**
- Call `search_ai_security_risks` to surface AI/agent security detections (filter by `severity` or `source: runtime|scan`; results include CVSS v3.1/v4.0 scores and matched params)
- Call `count_ai_session_detections` for AI detection prevalence with a stated `recency_days` window and requested asset scope. Report distinct sessions per rule alongside `sessions_with_detections` and `sessions_total`; counts overlap and must not be summed. Inspect scope/error messages before interpreting zeros. Scanner findings are outside this census.
- Call `search_ai_sessions` to drill into a census row using its returned `detection_id` as an array, copying the same recency window and all shared scope filters. Its `total_count` is the matching population; `returned` is a page size.
- Call `search_secrets` for finding metadata; use exact `asset_id` for a single asset. Report `total_count` as findings, not unique credentials or a count of returned rows. Asset `secret_count` is latest-scan findings; zero does not distinguish unscanned from clean. Detector types come from `detector_name`, falling back to `outputs.name` on older builds; do not copy credential values into the report.

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
[Open-vulnerability counts by severity tier, per-vulnerability sla_status]

## Recommendations
[3-5 prioritized recommendations]
```

**Operational format:**
```
## Environment Overview
[Asset counts, active/stale/disabled, platform breakdown, software/detection counts]

## Vulnerability Summary
[Counts by severity, new vs resolved, backlog trend]

## Remediation Performance
[Median/mean/P90 by severity, SLA open counts, KEV metrics]

## Top 10 Critical CVEs
[Table: CVE ID, severity, EPSS, KEV, endpoint count, sla_status]

## Software Risk Highlights
[Top riskiest software by CVE count and detection count]

## Runtime Detection Activity
[Critical/high detections by category (`runtime_weakness`, `exploit_impact`, `remotely_exploitable`), CVE correlation via `cve_likelihood`, affected scope (`endpoint_count`, `software_count`)]

## Secrets & AI Agent Activity
[Recorded secret findings by detector type (`detector_name`); AI session counts, detection census, critical/high sessions]

## Action Items
[Prioritized list with specific CVEs, software, endpoints to address]
```

### Step 5: Add Trend Context

For any metric, compare current vs previous period:
- **Improving:** current < previous (highlight as positive)
- **Declining:** current > previous (flag as concern)
- **Stable:** within 5% variance (note as maintained)

Include the vulnerability delta from trends data to show if the backlog is growing or shrinking, and the `org_exposure_delta` from posture where available.

## Quick Reference

| Action | MCP Tool | Key Parameters |
|--------|----------|----------------|
| Get posture overview | `get_security_posture` | (none) |
| Get remediation metrics | `get_remediation_metrics` | `severity`, `platform`, `start_time`, `end_time` |
| Get vulnerability trends | `get_vulnerability_trends` | `severity`, `platform`, `start_time`, `end_time` |
| Search critical CVEs | `search_vulnerabilities` | `severity`, `kev`, `sort_by`, `limit`, `offset` |
| Search risky software | `search_software` | `sort_by: cve_count`, `limit` |
| Search detections | `search_detections` | `highest_impact`, `sort_by: highest_impact`, `limit` |
| Count AI detection prevalence | `count_ai_session_detections` | `recency_days`, `hostname`, `agent`, `classification`, `severity`, `asset_tags`, `asset_importance`, `asset_type` |
| Drill into AI sessions | `search_ai_sessions` | `detection_id`, `recency_days`, `hostname`, `agent`, `classification`, `severity`, `asset_tags`, `asset_importance`, `asset_type`, `limit`, `offset` |
| Search AI security risks | `search_ai_security_risks` | `severity`, `source`, `rule_name`, `sort_by`, `limit` |
| Count secret coverage | `count_secrets_by_detector` | `hostname`, `asset_id`, `asset_tags`, `asset_importance`, `asset_type` |
| Search exposed secrets | `search_secrets` | `detector_id`, `detector_name`, `asset_id`, `hostname`, `sort_by`, `limit`, `offset` |
| View platforms | Resource: `spektion://platforms` | N/A |
