HISTORICAL (2026-02-25): superseded by the generated MCP contract (plugins/spektion/contract/mcp-contract.json) and the parity gate (scripts/parity_check.py). Do not treat contents as current.

# Spektion MCP Tool Schema Audit

> **Audit date:** 2026-02-25
> **Purpose:** Document every MCP tool's actual response schema, identify mismatches between skills and API responses, and recommend server-side additions.

## Table of Contents

- [Search Tools](#search-tools)
  - [search_detections](#search_detections)
  - [search_endpoints](#search_endpoints)
  - [search_software](#search_software)
  - [search_vulnerabilities](#search_vulnerabilities)
  - [search_network_activity](#search_network_activity)
- [Query Tools (Paginated)](#query-tools-paginated)
  - [query_detection_events](#query_detection_events)
  - [query_sensors](#query_sensors)
  - [query_software_inventory](#query_software_inventory)
  - [query_vulnerability_data](#query_vulnerability_data)
- [Detail Tools](#detail-tools)
  - [get_endpoint_details](#get_endpoint_details)
  - [get_software_details](#get_software_details)
  - [get_vulnerability_details](#get_vulnerability_details)
- [Metrics & Posture Tools](#metrics--posture-tools)
  - [get_security_posture](#get_security_posture)
  - [get_remediation_metrics](#get_remediation_metrics)
  - [get_vulnerability_trends](#get_vulnerability_trends)
  - [get_tenant_settings](#get_tenant_settings)
- [Pagination Patterns](#pagination-patterns)
- [Response Size Notes](#response-size-notes)
- [Tool Availability](#tool-availability)
- [Recommended Server-Side Additions](#recommended-server-side-additions)

---

## Search Tools

### search_detections

**Parameters:** `category`, `highest_impact`, `platform`, `sort_by`, `limit`

**Response schema:**
```json
{
  "items": [
    {
      "name": "string",
      "highest_impact": "string",          // "Critical", "High", "Medium", "Low" (title case)
      "category": "string",               // "runtime_weakness", "exploit_impact", "remotely_exploitable"
      "subcategory": "string",            // OPTIONAL — e.g., "command_interpreter", "persistence"
      "platform": "string",              // "windows", "macos", "linux"
      "cve_likelihood": {
        "description": "string",
        "probability": "string"           // "high", "medium", "low" (lowercase strings, NOT numeric)
      },
      "first_seen": "string"             // ISO 8601 timestamp
    }
  ],
  "returned": "number",
  "total_count": "number"
}
```

**Fields present:** `name`, `highest_impact`, `category`, `subcategory` (optional), `platform`, `cve_likelihood.description`, `cve_likelihood.probability`, `first_seen`

**Fields NOT present (referenced by skills):**
- `software_count` — referenced by 5/6 skills
- `endpoint_count` — referenced by 5/6 skills
- `elevated_software_count` — referenced by runtime-detection-analysis

**Sort options:** `endpoint_count`, `software_count`, `highest_impact` (per tool definition). Since `endpoint_count` and `software_count` are not in the response, sorting by them may produce unexpected results.

---

### search_endpoints

**Parameters:** `hostname`, `platform`, `is_online`, `sort_by`, `limit`

**Response schema:**
```json
{
  "items": [
    {
      "hostname": "string",
      "ip_address": "string",
      "platform": "string",
      "os": "string",
      "domain": "string",
      "endpoint_type": "string",           // "workstation", "server"
      "is_online": "boolean",
      "grade": "string",
      "score": "number",
      "first_seen": "string",
      "last_seen": "string",
      "last_logged_on_user": "string",
      "present_software_count": "number",
      "unused_software_count": "number",
      "risk_count": "number",
      "cve_count": "number",
      "network_destination_count": "number",
      "executable_object_count": "number"
    }
  ],
  "matched": "number",
  "returned": "number",
  "total_count": "number"
}
```

**Fields present:** All expected fields are present. No mismatches identified.

---

### search_software

**Parameters:** `name`, `sort_by`, `limit`

**Response schema:**
```json
{
  "items": [
    {
      "name": "string",
      "publisher": "string",
      "platform": "string",
      "grade": "string",
      "score": "number",                  // -1 when ungraded
      "endpoint_count": "number",
      "unused_endpoint_count": "number",
      "cve_count": "number",
      "detection_count": "number",
      "elevated_detection_count": "number",
      "present_versions": "number",
      "has_high_risks": "boolean",
      "has_elevated_risk": "boolean",
      "has_runtime_weakness": "boolean",
      "has_remote_exploitability": "boolean",
      "makes_network_connection": "boolean",
      "network_destination_count": "number",
      "network_listener_count": "number"
    }
  ],
  "matched": "number",
  "returned": "number",
  "total_count": "number"
}
```

**Fields present:** All expected fields are present. No mismatches identified.

---

### search_vulnerabilities

**Parameters:** `severity`, `kev`, `exploit_maturity`, `has_remote_exploitability`, `sort_by`, `limit`

**Response schema:**
```json
{
  "items": [
    {
      "cve_id": "string",
      "name": "string",
      "severity": "string",
      "score": "number",
      "kev": "boolean",
      "platforms": ["string"],
      "first_seen": "string",
      "epss_score": "number",
      "exploit_maturity": "string",       // "poc", "functional", "unproven", etc.
      "has_remote_exploitability": "boolean",
      "endpoint_count": "number",
      "is_used": "boolean",
      "sla_due_date": "string"
    }
  ],
  "returned": "number",
  "total_count": "number"
}
```

**Fields present:** All expected fields are present. No mismatches identified.

---

### search_network_activity

**Parameters:** `software_name` (required), `limit`

**Response schema:**
```json
{
  "destination_count": "number",
  "destinations": [
    {
      "software_name": "string",
      "endpoint_hostname": "string",
      "destination": "string",            // IP address or hostname
      "activity": "string",              // e.g., "connection"
      "observation_count": "number",
      "is_internal": "boolean"
    }
  ],
  "listener_count": "number",
  "listeners": [
    {
      "software_name": "string",
      "endpoint_hostname": "string",
      "ip_address": "string",
      "port": "number"
    }
  ]
}
```

**Fields present:** Separate `destinations` and `listeners` arrays with counts. This is NOT a flat list — it has distinct structure for outbound connections vs port bindings.

---

## Query Tools (Paginated)

### query_detection_events

**Parameters:** `category`, `severity`, `platform`, `name`, `sort`, `limit`, `offset`

**Response schema:** (based on tool description; API returned 500 during audit)
```
Expected fields per item: detection ID, name, category, severity, software_count, asset_count, description
```

**Note:** This tool returned a 500 error during the audit. Schema documented from tool description. Unlike `search_detections`, this tool is expected to include `software_count` and `asset_count` per detection.

---

### query_sensors

**Parameters:** `hostname`, `os_family`, `importance`, `enabled`, `sort`, `limit`, `offset`

**Response schema:**
```json
{
  "count": "number",
  "items": [
    {
      "sensor_id": "string",
      "hostname": "string",
      "os_family": "string",
      "os_version": "string",
      "agent_version": "string",
      "endpoint_type": "string",
      "enabled": "boolean",
      "importance": "number",
      "first_seen": "string",
      "last_seen": "string",
      "grade": "string",
      "score": "number"
    }
  ],
  "offset": "number",
  "summary": "string",
  "total_count": "number"
}
```

**Fields present:** All expected fields are present. No mismatches identified.

---

### query_software_inventory

**Parameters:** `name`, `platform`, `sort`, `limit`, `offset`

**Response schema:**
```json
{
  "count": "number",
  "items": [
    {
      "software_id": "string",
      "software_name": "string",
      "platform": "string",
      "asset_count": "number",
      "version_count": "number",
      "cve_count": "number",
      "detection_count": "number"
    }
  ],
  "offset": "number",
  "summary": "string",
  "total_count": "number"
}
```

**Fields present:** All expected fields are present. Note: no `grade` or `score` field (unlike `search_software`).

---

### query_vulnerability_data

**Parameters:** `name`, `severity`, `kev`, `platform`, `sort`, `limit`, `offset`

**Response schema:**
```json
{
  "count": "number",
  "items": [
    {
      "id": "string",                     // CVE ID
      "severity": "string",
      "score": "number",
      "kev": "boolean",
      "platforms": ["string"],
      "asset_count": "number",
      "first_seen": "string"
    }
  ],
  "offset": "number",
  "summary": "string",
  "total_count": "number"
}
```

**Fields present:** Note the field is `id` not `cve_id` (different from `search_vulnerabilities`). Also uses `asset_count` not `endpoint_count`.

---

## Detail Tools

### get_endpoint_details

**Parameters:** `hostname` (required)

**Response schema:**
```json
{
  "endpoint": {
    "hostname": "string",
    "ip_address": "string",
    "platform": "string",
    "domain": "string",
    "endpoint_type": "string",
    "importance": "number",
    "is_online": "boolean",
    "grade": "string",
    "score": "number",
    "first_seen": "string",
    "last_seen": "string",
    "last_logged_on_user": "string",
    "present_software_count": "number",
    "unused_software_count": "number",
    "risk_count": "number",
    "cve_count": "number",
    "network_destination_count": "number",
    "executable_object_count": "number"
  },
  "installed_software": [
    {
      "name": "string",
      "publisher": "string",
      "used": "boolean",                  // OPTIONAL — may be absent
      "versions": ["string"],
      "grade": "string",
      "score": "number"                   // OPTIONAL — absent when grade is "--"
    }
  ],
  "network_activity": [
    {
      "software_name": "string",
      "destination": "string",
      "activity": "string",              // "connection"
      "observation_count": "number",
      "is_internal": "boolean"
    }
  ],
  "network_count": "number",
  "software_count": "number"
}
```

**Key observations:**
- `installed_software` does NOT have `cve_count` per software item. Only `name`, `publisher`, `used` (optional), `versions`, `grade`, `score` (optional).
- `network_activity` is a flat list of connections. No listener/port binding data. Only outbound connection records.
- `used` and `score` fields on installed_software are conditional/optional.
- Response can be very large: 175KB+ observed (1030 network_activity entries, 419 installed_software entries).

---

### get_software_details

**Parameters:** `software_name` (required)

**Response schema:**
```json
{
  "items": [
    {
      "software": {
        "name": "string",
        "publisher": "string",
        "platform": "string",
        "grade": "string",
        "score": "number",
        "endpoint_count": "number",
        "unused_endpoint_count": "number",
        "cve_count": "number",
        "detection_count": "number",
        "elevated_detection_count": "number",
        "present_versions": "number",
        "has_high_risks": "boolean",
        "has_elevated_risk": "boolean",
        "has_runtime_weakness": "boolean",
        "has_remote_exploitability": "boolean",
        "makes_network_connection": "boolean",
        "network_destination_count": "number",
        "network_listener_count": "number"
      },
      "assets": [
        {
          "hostname": "string",
          "ip_address": "string",
          "versions": ["string"]
        }
      ]
    }
  ],
  "returned": "number"
}
```

**Key observations:**
- Results are **grouped by platform**. Each `items[]` entry is one platform with `software` metadata and `assets` list.
- Software metadata is at `items[].software`, not at the top level.
- Per-endpoint data is at `items[].assets[]`.
- Response can be very large for widely-deployed software (295KB+ observed for "Python").

---

### get_vulnerability_details

**Parameters:** `cve_id` (required)

**Response schema:**
```json
{
  "cve_id": "string",
  "name": "string",
  "description": "string",
  "severity": "string",
  "score": "number",
  "epss_score": "number",
  "exploit_maturity": "string",
  "has_remote_exploitability": "boolean",
  "kev": "boolean",
  "kev_ransomware_campaign": "string | null",
  "platforms": ["string"],
  "published": "string",
  "is_used": "boolean",
  "sla_due_date": "string",
  "endpoint_count": "number",
  "impacted_software": [
    {
      "name": "string",
      "version": "string",
      "platform": "string",
      "has_remote_exploitability": "boolean"
    }
  ],
  "impacted_endpoints": [
    {
      "hostname": "string",
      "platform": "string",
      "first_seen": "string",
      "importance": "number"
    }
  ]
}
```

**Fields present:** All expected fields are present. No mismatches identified.

---

## Metrics & Posture Tools

### get_security_posture

**Parameters:** none

**Response schema:**
```json
{
  "active_assets": "number",
  "stale_assets": "number",
  "total_assets": "number",
  "stale_threshold_days": "number",
  "assets_by_platform": {
    "linux": "number",
    "macos": "number",
    "windows": "number"
  },
  "software_by_platform": {
    "linux": "number",
    "macos": "number",
    "windows": "number"
  },
  "total_software": "number",
  "total_detections": "number",
  "vulnerabilities_by_severity": {
    "critical": "number",
    "high": "number",
    "medium": "number",
    "low": "number"
  }
}
```

**Fields present:** All expected fields are present. No mismatches identified.

---

### get_remediation_metrics

**Parameters:** `severity`, `platform`, `start_time`, `end_time`

**Response schema:** Could not validate during audit — API returned `400: invalid tenant ID`.

**Expected fields (from tool description):** mean, median, P10, P90 days to remediate, KEV-specific metrics, SLA compliance data.

---

### get_vulnerability_trends

**Parameters:** `severity`, `platform`, `start_time`, `end_time`

**Response schema:** Could not validate during audit — API returned `400: invalid tenant ID`.

**Expected fields (from tool description):** daily delta (new vs resolved), distribution by age and severity, blindspot counts, preemptive CVE exposure.

---

### get_tenant_settings

**Parameters:** none

**Response schema:** Could not validate during audit — API returns placeholder: `"tenant settings retrieval will be available in a future update"`.

**Expected fields (from tool description):** SLA remediation policy, asset importance defaults, KEV override settings.

**Note:** This tool is registered and callable but returns a placeholder response. When implemented, it will be valuable for skills that reference SLA thresholds (`remediation-tracking`, `security-reporting`) and business impact tiers (`asset-risk-assessment`).

---

## Pagination Patterns

Two distinct pagination shapes exist:

### Search tools (`search_*`)
```json
{
  "items": [...],
  "returned": "number",
  "total_count": "number",
  "matched": "number"          // present in some (search_endpoints, search_software)
}
```
- No `offset` field in response
- `limit` parameter controls page size
- No built-in pagination cursor — use client-side offset if needed

### Query tools (`query_*`)
```json
{
  "count": "number",
  "items": [...],
  "offset": "number",
  "summary": "string",
  "total_count": "number"
}
```
- `offset` parameter for pagination (skip N results)
- `limit` parameter for page size (max 100)
- `sort` parameter with `-` prefix for descending (e.g., `-asset_count`)
- `summary` provides human-readable description (e.g., "Showing 1 of 149 sensors")

### Detail tools (`get_*_details`)
- Return a single object (not paginated)
- Can return very large responses (see Response Size Notes)

---

## Response Size Notes

| Tool | Observed Size | Cause | Recommendation |
|------|--------------|-------|----------------|
| `get_endpoint_details` | 175KB+ | 1030 network_activity entries, 419 installed_software entries | Use `search_network_activity` separately for network analysis |
| `get_software_details` | 295KB+ | Multiple platforms, many assets per platform | Filter by platform if possible; be aware of context window limits |
| `search_endpoints` | Generally small | Limited by `limit` parameter | Use `limit` to control |
| `search_software` | Generally small | Limited by `limit` parameter | Use `limit` to control |
| `query_*` tools | Controlled | Paginated with `limit` + `offset` | Use pagination for large datasets |

---

## Tool Availability

| Tool | Status | Notes |
|------|--------|-------|
| `search_detections` | Working | Missing fields vs tool description (see below) |
| `search_endpoints` | Working | |
| `search_software` | Working | |
| `search_vulnerabilities` | Working | |
| `search_network_activity` | Working | |
| `query_detection_events` | Error (500) | Internal server error during audit |
| `query_sensors` | Working | |
| `query_software_inventory` | Working | |
| `query_vulnerability_data` | Working | |
| `get_endpoint_details` | Working | Very large responses |
| `get_software_details` | Working | Very large responses |
| `get_vulnerability_details` | Working | |
| `get_security_posture` | Working | |
| `get_remediation_metrics` | Error (400) | Tenant ID issue during audit |
| `get_vulnerability_trends` | Error (400) | Tenant ID issue during audit |
| `get_tenant_settings` | Placeholder | Returns "will be available in a future update" |

---

## Recommended Server-Side Additions

| Tool | Missing Field | Why It Should Be Added | Skills Affected |
|------|--------------|----------------------|-----------------|
| `search_detections` | `software_count` | 5/6 skills need this to assess detection breadth without extra API calls | asset-risk-assessment, runtime-detection-analysis, cve-triage, software-risk-analysis, security-reporting |
| `search_detections` | `endpoint_count` | 5/6 skills need this to assess detection spread; `sort_by: endpoint_count` is a defined option but field isn't in response | asset-risk-assessment, runtime-detection-analysis, cve-triage, software-risk-analysis, security-reporting |
| `search_detections` | `elevated_software_count` | runtime-detection-analysis needs this to identify elevated-risk software per detection | runtime-detection-analysis |
| `installed_software` (in `get_endpoint_details`) | `cve_count` | asset-risk-assessment needs per-software CVE counts for risk ranking; currently must call `get_software_details` per package | asset-risk-assessment |
| `get_endpoint_details` | Network summary / top-N | Full `network_activity` list (1000+ entries, 175KB+) exceeds LLM context limits; a summary count + top-N external destinations would help | asset-risk-assessment |
| `query_software_inventory` | `grade`, `score` | Present in `search_software` but missing from query equivalent; inconsistent between search/query pairs | software-risk-analysis |

### Field Naming Inconsistencies

| Field | `search_*` tools | `query_*` tools |
|-------|-----------------|-----------------|
| CVE identifier | `cve_id` | `id` |
| Affected asset count | `endpoint_count` | `asset_count` |
| Software name | `name` | `software_name` |
| Impact level (detections) | `highest_impact` (title case: "Critical") | `severity` (lowercase: "critical") |

These inconsistencies require skills to handle both naming conventions depending on which tool is used.
