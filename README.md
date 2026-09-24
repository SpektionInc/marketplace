# Spektion — Claude Code Marketplace Plugin

Security posture management for Claude Code. Native MCP integration gives you conversational access to vulnerability, asset, software, runtime detection, and remediation data from Spektion.

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

### 24 MCP Tools (Native Access)

Once installed, Claude can directly call these Spektion tools:

| Category | Tools |
|----------|-------|
| **Search** | `search_assets`, `search_vulnerabilities`, `search_software`, `search_detections`, `search_executables`, `search_secrets`, `count_secrets_by_detector`*, `search_network_activity` |
| **Details** | `get_asset_details`, `get_asset_executables`*, `get_executable_details`*, `get_vulnerability_details`, `get_software_details`, `get_detection_events`, `get_detection_controls` |
| **AI Security** | `search_ai_sessions`, `search_ai_security_risks`, `count_ai_session_detections`*, `get_ai_session_artifacts`* |
| **Analytics** | `get_security_posture`, `get_remediation_metrics`, `get_vulnerability_trends`, `get_tenant_settings` |
| **Sensors** | `query_sensors` |

\* Tools are served live by the MCP server, so the newest ones appear only on recent builds. `count_ai_session_detections` needs a build newer than 2026-09; `get_ai_session_artifacts` one from 2026-09-15; `count_secrets_by_detector` from 2026-09-17; and `get_asset_executables` and `get_executable_details` from 2026-09-24, when they were promoted from the chat-only surface. An older deployment simply lists fewer than 24 tools — nothing else changes, and the skills degrade to the tools that are present.

Most `search_*` tools accept asset-scope parameters (`asset_tags`, `asset_importance`, `asset_type`) to scope any question to a subset of the fleet — e.g. "critical CVEs on my production servers".

### 5 Resources

| Resource | Description |
|----------|-------------|
| `spektion://platforms` | Active platforms with endpoint counts |
| `spektion://software-categories` | Software category taxonomy |
| `spektion://software-publishers` | Publisher list |
| `spektion://detection-rules` | Detection rule index (use `search_detections` for queries) |
| `spektion://sla-policy` | SLA remediation policy *(returns a placeholder today — for per-CVE SLA compliance use the `sla_status` field on `search_vulnerabilities`)* |

### 6 Analyst Workflow Skills

Skills provide guided, multi-step workflows for common analyst tasks:

| Skill | Use Case |
|-------|----------|
| `cve-triage` | Investigate and prioritize CVEs with SSVC-style triage |
| `asset-risk-assessment` | Deep-dive endpoint risk analysis with hardening recommendations |
| `software-risk-analysis` | Rank software portfolio risk by CVE + runtime + network exposure |
| `remediation-tracking` | Track SLA compliance, remediation velocity, and blindspots |
| `runtime-detection-analysis` | Translate behavioral detections into actionable threat narratives |
| `security-reporting` | Generate executive and operational security reports |

## Example Queries

**CVE Triage:**
> "Triage CVE-2025-21298 — is it in our environment and how urgent is it?"

**Asset Risk:**
> "Assess the risk on asset PROD-WEB-01"

**Software Risk:**
> "What are the top 10 riskiest software products in our environment?"

**Remediation:**
> "Are we meeting SLA on critical vulnerability remediation this quarter?"

**Runtime Detections:**
> "What critical runtime detections are active and do any correlate with known CVEs?"

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
│       └── skills/
│           ├── cve-triage/
│           ├── asset-risk-assessment/
│           ├── software-risk-analysis/
│           ├── remediation-tracking/
│           ├── runtime-detection-analysis/
│           └── security-reporting/
├── scripts/
│   └── validate_plugins.py
├── LICENSE
└── README.md
```

## Development

### Validate

```bash
python3 scripts/validate_plugins.py . --verbose
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
