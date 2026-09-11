# Spektion — Claude Code Marketplace Plugin

Security posture management for Claude Code. Native MCP integration gives you conversational access to vulnerability, asset, software, runtime detection, remediation, and security-findings (secrets, AI security) data from Spektion.

## Quick Start

```bash
# Add the marketplace
/plugin marketplace add SpektionInc/marketplace

# Install the plugin
/plugin install spektion
```

## Setup

### 1. Get a Spektion API Key

1. Log into the [Spektion Console](https://app.spektion.com)
2. Navigate to **Settings > API Keys**
3. Create a new **Public API Key**
4. Copy the key

### 2. Configure Environment Variables

```bash
export SPEKTION_API_KEY="your-api-key-here"
export SPEKTION_MCP_URL="https://mcp.spektion.com/mcp"
```

Add these to your shell profile (`~/.zshrc`, `~/.bashrc`) or your project's `.env` file.

## What You Get

### 20 MCP Tools (Native Access)

Once installed, Claude can directly call these Spektion tools:

| Category | Tools |
|----------|-------|
| **Search** | `search_vulnerabilities`, `search_assets`, `search_software`, `search_detections`, `search_network_activity`, `search_secrets`, `search_ai_security_risks`, `search_executables`, `search_ai_sessions` |
| **Details** | `get_vulnerability_details`, `get_asset_details`, `get_software_details`, `get_detection_events`, `get_detection_controls` |
| **Analytics** | `get_security_posture`, `get_remediation_metrics`, `get_vulnerability_trends`, `get_tenant_settings` (required tenant SLA/settings authority at release), `count_ai_session_detections` |
| **Paginated Queries** | `query_sensors` |

### 5 Resources

| Resource | Description |
|----------|-------------|
| `spektion://platforms` | Active platform names in the environment (platform names only — no counts) |
| `spektion://software-categories` | Software category taxonomy with per-category software counts |
| `spektion://software-publishers` | Publisher list with per-publisher software counts |
| `spektion://detection-rules` | Detection rule availability metadata — query rules with `search_detections` |
| `spektion://sla-policy` | SLA remediation policy — tenant SLA remediation time matrix (default matrix when the tenant has not configured one) |

### 5 MCP Prompts

Prompts are reusable workflows the MCP server exposes; Claude chains the underlying tools to fulfill them:

| Prompt | Arguments | Purpose |
|--------|-----------|---------|
| `security_review` | `platform?`, `time_period?` | Full security posture review: posture, critical CVEs, riskiest endpoints, worst-graded software, detection activity, recommendations |
| `investigate_cve` | `cve_id` (required) | CVE impact investigation: severity, blast radius, business impact, SLA compliance, remediation priority |
| `endpoint_risk_assessment` | `hostname` (required) | Single-asset assessment: exposure risk, software risks, vulnerability exposure, network analysis, hardening recommendations |
| `vulnerability_report` | `time_period?`, `severity?` | Vulnerability management report: severity breakdown, remediation metrics, SLA compliance, top CVEs, trends |
| `software_risk_analysis` | `software_name?`, `grade?` | Software risk prioritization: riskiest products, deployment breadth, unused software, network exposure, blind spots |

### 7 Analyst Workflow Skills

Skills provide guided, multi-step workflows for common analyst tasks:

| Skill | Use Case |
|-------|----------|
| `cve-triage` | Investigate and prioritize CVEs with SSVC-style triage |
| `asset-risk-assessment` | Deep-dive endpoint risk analysis with hardening recommendations |
| `software-risk-analysis` | Rank software portfolio risk by CVE + runtime + network exposure |
| `remediation-tracking` | Track SLA compliance, remediation velocity, and blindspots |
| `runtime-detection-analysis` | Translate behavioral detections into actionable threat narratives |
| `security-reporting` | Generate executive and operational security reports |
| `ai-security-analysis` | Count AI detections by distinct sessions and investigate matching sessions and findings |

## Example Queries

**CVE Triage:**
> "Triage CVE-2025-21298 — is it in our environment and how urgent is it?"

**Asset Risk:**
> "Assess the risk on endpoint PROD-WEB-01"

**Software Risk:**
> "What are the top 10 riskiest software products in our environment?"

**Remediation:**
> "Are we meeting SLA on critical vulnerability remediation this quarter?"

**Runtime Detections:**
> "What critical runtime detections are active and do any correlate with known CVEs?"

**AI Security:**
> "Which AI detections fired on our Production servers in the last 30 days, and which sessions triggered them?"

**Secrets:**
> "What secret findings and credential types were recorded on PROD-WEB-01?"

**Reporting:**
> "Generate an executive security posture summary for leadership"

## Composable with Other Plugins

This plugin is designed to work standalone or combined with other marketplace plugins:

- **[MalloryAI](https://github.com/malloryai/marketplace)** — Adds threat actor attribution, active exploitation intel, and detection engineering context to every Spektion skill
- Additional integrations enrich results without creating dependencies

## Repository Structure

```
marketplace/
├── .claude-plugin/
│   └── marketplace.json
├── plugins/
│   └── spektion/
│       ├── .claude-plugin/
│       │   └── plugin.json
│       ├── .mcp.json
│       ├── contract/
│       │   └── mcp-contract.json
│       └── skills/
│           ├── cve-triage/
│           ├── asset-risk-assessment/
│           ├── software-risk-analysis/
│           ├── remediation-tracking/
│           ├── runtime-detection-analysis/
│           ├── security-reporting/
│           └── ai-security-analysis/
├── scripts/
│   ├── parity_check.py
│   ├── test_validation.py
│   └── validate_plugins.py
├── LICENSE
└── README.md
```

## Development

The plugin targets **1.1.0**, with 20 read-only tools and seven analyst skills.
The contract records separate provenance for the current tool registry/input
schemas (`source`) and the resource/prompt release requirements
(`release_surface_source`). The latter come from the API hardening candidate
that the existing PR already requires; this is a combined release contract,
not a claim that API master already implements every behavior.

At the reviewed API master revision, tenant settings and the SLA resource still
return placeholders, and three prompt bodies lack the required guidance. Use
the bundled skills for these workflows; never infer a tenant SLA policy from a
placeholder. The credentialed release gate continues to reject those responses.
Publish only after the target deployment combines the new tools with the API
hardening and passes live acceptance. See the [capability review](plugins/spektion/docs/mcp-capability-review-2026-09-11.md)
for the source revisions, tool boundaries, and remaining service dependencies.

AI detection prevalence uses distinct session counts with both denominators;
scanner findings are a separate population. Session drill-through preserves the
same recency and asset scope. Asset secret counts represent latest-scan findings,
not unique credentials, and zero does not establish that an asset was scanned.

### Refresh tool schemas

```bash
python3 scripts/refresh_contract.py --api ../spektionapi
python3 scripts/refresh_contract.py --api ../spektionapi --check
```

The exporter reads the Go registry and actual MCP adapter from a clean tracked
API checkout. It requires that checkout's Go dependencies. It refreshes tool
schemas and discovery fixtures, including array element types and MCP numeric
types. Resource/prompt requirements and synthetic response fixtures are retained
for explicit review; they are not recordings from the current deployment.

### Validate

```bash
python3 scripts/validate_plugins.py . --verbose
python3 -m unittest discover -s scripts -p 'test_*.py'
```

Before release, run credentialed acceptance against the seeded target tenant:

```bash
python3 plugins/spektion/scripts/contract_smoke.py --live
```

Or use the built-in Claude Code validator:

```bash
claude plugin validate .
```

### Adding a New Skill

1. Create a directory: `plugins/spektion/skills/<skill-name>/`
2. Add `SKILL.md` with YAML frontmatter (`name`, `description`)
3. Skill name must match: `^[a-z0-9]+(-[a-z0-9]+)*$` (1-64 chars)
4. Run validation to verify

## License

Apache-2.0
