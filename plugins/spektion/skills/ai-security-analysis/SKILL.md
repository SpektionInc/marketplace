---
name: ai-security-analysis
description: Investigate AI agent security in Spektion. Use for AI detection prevalence, affected sessions, agent activity, and runtime versus scanner findings, including scoped census and session drill-through.
---

# AI Security Analysis

## Choose the Evidence Surface

- For which AI detections fired or how widespread they are, use `count_ai_session_detections`. It counts distinct sessions on the server; never page the session inventory just to calculate prevalence.
- For sessions behind a detection or agent activity, use `search_ai_sessions`.
- For individual AI security findings, use `search_ai_security_risks`. Its runtime and scanner findings cover the last 90 days, a different population from session summaries.
- Runtime software weaknesses belong to `search_detections` and their logs to `get_detection_events`. AI session rule IDs do not establish a mapping to those software weaknesses.

## Count and Investigate

1. Establish the requested scope and recency window. For current activity without a specified period, use 30 days and state that assumption. Omit `recency_days` only for an explicitly all-history census. Preserve hostname, agent, classification, severity, and asset scope throughout the drill-through. Severity filters a session's maximum severity, not the individual census rule's severity.
2. Call `count_ai_session_detections` with that scope. Report each row's `detection_name`, `detection_id`, and `session_count` alongside both `sessions_with_detections` and `sessions_total`. Rows count distinct sessions, not occurrences. One session can fire several rules: do not sum row counts into a total. Only enabled rules are included; scanner findings are excluded.
3. For a selected row, call `search_ai_sessions` with `detection_id` as an array containing its returned ID. Copy the SAME `recency_days` and all shared filters from the census. Use `total_count` for the matching population and `returned` for the page size; retrieve further pages with `limit` and `offset` only when the user needs session identities. Counts can change between calls as new telemetry arrives.
4. Present returned session links, hostname, agent, classification, severity, detections, and activity metrics. `detections[]` supplies rule IDs and names. Never invent IDs from names. Multiple IDs have OR semantics; they cannot answer which sessions fired both rules. An unknown ID matches nothing.
5. When finding-level context is needed, call `search_ai_security_risks` with the returned `asset_id` and an appropriate source. Page using `limit` and `offset`. Its severity sort is within the returned page. There is no session-ID filter on this tool: asset/rule/time overlap is context, not proof that a finding belongs to a specific session. Preserve the distinction between scanner findings and runtime findings.

## Scope and Empty Results

For both census and session search, supported asset scope is `asset_tags` (an array of user-provided tag names), `asset_importance` (integer tiers 1–5, with 1 most critical), and `asset_type` (`workstation` or `server`). Each dimension supports an operator of `equals` or `notEqual`; tag equality matches any provided tag. Pass the same values and operators to both calls. Census does not accept `asset_id` or `platform`; label hostname scope as a partial match. Session search accepts exact `asset_id` when investigating an individual asset, but that additional restriction changes the census population.

Inspect `message` and `applied_scope` before drawing conclusions from an empty response. An invalid filter or unavailable scope lookup answers nothing; do not treat its zeroed denominators as a clean environment or retry without the user's scope. Distinguish no sessions in scope, sessions with no enabled detections, and an unknown detection ID. An empty page beyond the end is not an empty population.

## Reporting Boundaries

Report observed activity, inferred concerns, and unknowns separately. A session metric or detection does not prove credential theft, exploitation, or exfiltration. Return useful source links and metadata without copying secret values or prompt/response content into reports. Detailed session and executable drill-down tools are not exposed by this MCP contract; use returned console links when deeper evidence is needed. Do not claim those tools are available through the plugin.

## Quick Reference

| Action | MCP Tool | Key Parameters |
|--------|----------|----------------|
| Count AI detections | `count_ai_session_detections` | `hostname`, `agent`, `classification`, `severity`, `recency_days`, `asset_tags`, `asset_importance`, `asset_type` |
| Inspect matching sessions | `search_ai_sessions` | `detection_id`, `recency_days`, `hostname`, `asset_id`, `agent`, `classification`, `severity`, `asset_tags`, `asset_importance`, `asset_type`, `sort_by`, `limit`, `offset` |
| Inspect AI findings | `search_ai_security_risks` | `asset_id`, `hostname`, `severity`, `rule_name`, `source`, `sort_by`, `limit`, `offset` |
