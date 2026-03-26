# SecOps Innovation — POC Toolkit

A local-first proof-of-concept toolkit for Security Operations, built to surface threat intelligence, track adversary behaviour, and generate Microsoft Sentinel detection rules — all without requiring a live Sentinel or Azure connection.

The toolkit is designed around three standalone CLI tools that share a common library of threat-intelligence primitives. Everything runs offline or against free public APIs (CISA, RSS, MITRE ATT&CK), with Azure OpenAI providing AI-assisted summarisation and rule generation.

## Tools

### Threat Digest

Generates a stakeholder-friendly weekly (or custom-window) summary of the current threat landscape by pulling live data from CISA's Known Exploited Vulnerabilities catalogue and security RSS feeds, then passing it through Azure OpenAI for structured summarisation.

```
python -m threat_digest
python -m threat_digest --days 14
python -m threat_digest --days 30 --output-dir custom/path
python -m threat_digest --no-llm   # feeds only; no LLM API key needed
```

**Requires:** `AZURE_OPENAI_ENDPOINT` and `AZURE_OPENAI_KEY` in `.env`, unless you pass `--no-llm`. Alternatively, configure Anthropic as a fallback option.

**Data sources:**
- CISA KEV JSON feed (free, no key)
- RSS: BleepingComputer, The Hacker News, Krebs on Security, CISA Alerts

**Output:** Rich terminal panel + `threat_digest/output/digest_YYYY-MM-DD.md`. In feed-only mode, the markdown file **starts with a copy-paste prompt** (“Please create a stakeholder digest webpage…”) so you can paste the entire file into Cursor Chat and ask the editor to produce the page—no API key required for that workflow.

### Actor Watch

Explores MITRE ATT&CK threat group profiles entirely offline. List all known groups or drill into a specific actor to see their full TTP breakdown, associated software, and tactic coverage.

```
python -m actor_watch                    # list all 170+ groups
python -m actor_watch "APT29"            # full profile
python -m actor_watch "Lazarus Group"
python -m actor_watch "Cozy Bear"        # aliases work too
```

**Requires:** No API key — fully offline using the ATT&CK Enterprise STIX bundle.

**Output:** Rich terminal table/panel + `output/actor_watch/<ActorName>.md`

### Detection Bot

Given any MITRE ATT&CK technique ID, uses Azure OpenAI to draft a production-style Microsoft Sentinel scheduled analytics rule in KQL, following the ScheduledRuleTemplate.yaml structure with complete YAML frontmatter metadata.

```
python -m detection_bot T1078
python -m detection_bot T1003.006
python -m detection_bot T1566.001 --severity High
python -m detection_bot T1021.002 --data-sources "DeviceNetworkEvents" "DeviceProcessEvents"
```

**Requires:** `AZURE_OPENAI_ENDPOINT` and `AZURE_OPENAI_KEY` in `.env` or Anthropic as fallback

**Output:** Rich syntax-highlighted terminal panel + `output/detection_bot/<TechniqueID>.kql` and `.md`

## Getting Started

### Prerequisites

- Python 3.12+
- Azure OpenAI access (for Threat Digest and Detection Bot) OR Anthropic API key as fallback
- Optional: VirusTotal API key (free) for enhanced IOC analysis
- Optional: GitHub token for security advisory management

### Installation

```bash
git clone <repo-url> && cd SecOps-Innovation
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt
```

### Configuration

Copy the sample environment file and fill in your keys:

```bash
cp .env.example .env
```

At minimum, set `AZURE_OPENAI_ENDPOINT` and `AZURE_OPENAI_KEY` or configure Anthropic (`ANTHROPIC_API_KEY`) as fallback. Actor Watch works without any keys.

### Azure OpenAI Integration

The project includes enhanced Azure OpenAI integration via `openai_client.py` for organizations using Azure OpenAI services. This provides:

- **Multi-model AI capabilities** with GPT-5 and other Azure OpenAI models
- **SecOps-specific methods** for threat intelligence analysis and security advisory generation
- **Integration with VirusTotal and GitHub APIs** for comprehensive security workflows
- **Fallback support** when multiple AI providers are configured

Example usage:
```python
from openai_client import SecOpsAIClient

client = SecOpsAIClient()
analysis = client.analyze_threat_intelligence(threat_data)
summary = client.generate_security_summary(raw_data, "executive")
```

The first run of any tool that uses MITRE data (Actor Watch, Detection Bot) will download the ATT&CK Enterprise STIX bundle (~25 MB) into `.cache/`. Subsequent runs use the cached copy.

### Troubleshooting: `SSL: CERTIFICATE_VERIFY_FAILED`

If Threat Digest or Detection Bot fails with *certificate verify failed: self-signed certificate in certificate chain*, a corporate TLS inspection proxy is usually intercepting HTTPS. Python does not trust that proxy’s CA by default.

**Preferred fix:** export your organisation’s root CA (or the proxy’s issuing CA) as a PEM file and set one of these in `.env` to that file path:

- `LLM_CA_BUNDLE` or `ANTHROPIC_CA_BUNDLE` (read first by this project), or
- `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, or `CURL_CA_BUNDLE` (common conventions)

Example (Windows):

```text
ANTHROPIC_CA_BUNDLE=C:\certs\company-root-ca.pem
```

**Last resort:** set `LLM_SSL_VERIFY_DISABLE=true` (or `ANTHROPIC_SSL_VERIFY_DISABLE=true`) to turn off TLS verification for LLM API calls only. This is insecure on untrusted networks; use only when you accept that risk on your corporate LAN.

### Troubleshooting: Anthropic “credit balance is too low”

Threat Digest and Detection Bot need Azure OpenAI access with proper endpoint and API key configuration. If you see authentication errors, verify your Azure OpenAI resource is properly configured and the API key is valid.

For Threat Digest only, you can still run without any AI usage:

```bash
python -m threat_digest --no-llm
```

That writes the same markdown file with CISA KEV and RSS headlines, without an AI-written summary.

## Project Structure

```
SecOps Innovation/
├── shared/                  # Common library modules
│   ├── llm.py               # LLM completions (Azure OpenAI primary, Anthropic fallback)
│   ├── feeds.py             # CISA KEV + RSS feed fetchers
│   ├── mitre_data.py        # ATT&CK Enterprise data loader and queries
│   └── output.py            # Dual output: Rich terminal + Markdown files
├── threat_digest/           # Threat Digest tool
│   ├── __main__.py          # CLI entry point
│   └── digest.py            # Feed aggregation + Claude summarisation
├── actor_watch/             # Actor Watch tool
│   ├── __main__.py          # CLI entry point
│   └── watch.py             # ATT&CK group queries and formatting
├── detection_bot/           # Detection Bot tool
│   ├── __main__.py          # CLI entry point
│   └── bot.py               # Technique lookup + Claude rule generation
├── output/                  # Centralized output directory
│   ├── threat_digest/       # Threat digest reports and stakeholder digests
│   ├── actor_watch/         # Actor profile reports
│   └── detection_bot/       # Generated KQL rules and documentation
├── openai_client.py         # Azure OpenAI integration for enhanced AI capabilities
├── .cache/                  # Auto-downloaded MITRE STIX data (gitignored)
├── .env                     # API keys and secrets (gitignored)
├── .env.example             # Template showing required variables
├── .cursorrules             # Cursor AI coding context
├── .gitignore
└── requirements.txt
```

All tools write their output to the centralized `output/` directory with organized subdirectories. These directories are created automatically on first run and are gitignored.

## KQL Rule Format

Detection Bot generates rules following the `ScheduledRuleTemplate.yaml` structure, ensuring consistency and production-readiness:

```yaml
id: 00000000-0000-0000-0000-000000000000
name: "[InitialAccess] Suspicious sign-in from Tor exit node"
description: |
  DO NOT EDIT IN PORTAL - MANAGED VIA GIT REPO.
  
  Detects sign-ins originating from known Tor exit nodes
  This behavior may indicate credential compromise or evasion attempts
  SOC analysts should verify legitimacy and check for additional suspicious activity

enabled: true
status: Available
severity: High

requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs

queryFrequency: PT1H
queryPeriod: PT2H

query: |
  SigninLogs
  | where TimeGenerated > ago(2h)
  | where IPAddress in (TorExitNodes)
  | project TimeGenerated, UserPrincipalName, IPAddress, Location

triggerOperator: gt
triggerThreshold: 0

tactics:
  - InitialAccess
relevantTechniques:
  - T1078

tags:
  - ManagedBy:Repository
  - Owner:SOC
  - Category:Identity
  - Version:1.0.0

entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: UserPrincipalName
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPAddress

alertDetailsOverride:
  alertDisplayNameFormat: "{{UserPrincipalName}} - Suspicious Tor sign-in"
  alertDescriptionFormat: "User {{UserPrincipalName}} signed in from Tor exit node {{IPAddress}}"

customDetails:
  SourceIP: IPAddress
  Location: Location

eventGroupingSettings:
  aggregationKind: SingleAlert

incidentConfiguration:
  createIncident: true
  groupingConfiguration:
    enabled: true
    reopenClosedIncident: false
    lookbackDuration: PT5H
    matchingMethod: AllEntities

suppressionEnabled: false
suppressionDuration: PT1H

version: 1.0.0
kind: Scheduled
```

## Architecture Decisions

- **No live Sentinel connection** — all tools use local files and public APIs so there are no cloud credentials required for the POC. The code is structured with isolated API modules in `shared/` so live connections (Azure SDK, Sentinel API) can be swapped in later without rewriting tool logic.
- **MITRE ATT&CK as the common language** — Actor Watch and Detection Bot both reference the Enterprise ATT&CK matrix via `mitreattack-python`, ensuring technique IDs, tactic names, and group metadata are consistent across the toolkit.
- **AI for generation, not for data** — Azure OpenAI (or Anthropic fallback) summarises and drafts, but the underlying data always comes from authoritative sources (CISA, MITRE, RSS feeds). This keeps outputs grounded and auditable.
- **Dual output** — every tool renders to the terminal with `rich` for immediate feedback and saves a Markdown file for sharing with stakeholders or pasting into Teams/email.

## Future Roadmap

- Connect to Sentinel API to pull live analytics rules and compare against ATT&CK coverage
- Add Microsoft Teams webhook notifications for new digests
- Scheduled runs via GitHub Actions or Azure Functions
- VirusTotal enrichment for IOCs mentioned in threat feeds
- Export Actor Watch profiles as ATT&CK Navigator layers for visual briefings
