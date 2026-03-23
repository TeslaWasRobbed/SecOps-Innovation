# SecOps Innovation — POC Toolkit

A local-first proof-of-concept toolkit for Security Operations, built to surface threat intelligence, track adversary behaviour, and generate Microsoft Sentinel detection rules — all without requiring a live Sentinel or Azure connection.

The toolkit is designed around three standalone CLI tools that share a common library of threat-intelligence primitives. Everything runs offline or against free public APIs (CISA, RSS, MITRE ATT&CK), with Anthropic Claude providing AI-assisted summarisation and rule generation.

## Tools

### Threat Digest

Generates a stakeholder-friendly weekly (or custom-window) summary of the current threat landscape by pulling live data from CISA's Known Exploited Vulnerabilities catalogue and security RSS feeds, then passing it through Claude for structured summarisation.

```
python -m threat_digest
python -m threat_digest --days 14
python -m threat_digest --days 30 --output-dir custom/path
```

**Requires:** `ANTHROPIC_API_KEY` in `.env`

**Data sources:**
- CISA KEV JSON feed (free, no key)
- RSS: BleepingComputer, The Hacker News, Krebs on Security, CISA Alerts

**Output:** Rich terminal panel + `threat_digest/output/digest_YYYY-MM-DD.md`

### Actor Watch

Explores MITRE ATT&CK threat group profiles entirely offline. List all known groups or drill into a specific actor to see their full TTP breakdown, associated software, and tactic coverage.

```
python -m actor_watch                    # list all 170+ groups
python -m actor_watch "APT29"            # full profile
python -m actor_watch "Lazarus Group"
python -m actor_watch "Cozy Bear"        # aliases work too
```

**Requires:** No API key — fully offline using the ATT&CK Enterprise STIX bundle.

**Output:** Rich terminal table/panel + `actor_watch/output/<ActorName>.md`

### Detection Bot

Given any MITRE ATT&CK technique ID, uses Claude to draft a production-style Microsoft Sentinel scheduled analytics rule in KQL, complete with YAML frontmatter metadata.

```
python -m detection_bot T1078
python -m detection_bot T1003.006
python -m detection_bot T1566.001 --severity High
python -m detection_bot T1021.002 --data-sources "DeviceNetworkEvents" "DeviceProcessEvents"
```

**Requires:** `ANTHROPIC_API_KEY` in `.env`

**Output:** Rich syntax-highlighted terminal panel + `detection_bot/output/<TechniqueID>.kql` and `.md`

## Getting Started

### Prerequisites

- Python 3.12+
- An Anthropic API key (for Threat Digest and Detection Bot)

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
cp .env.sample .env
```

At minimum, set `ANTHROPIC_API_KEY`. Actor Watch works without any keys.

The first run of any tool that uses MITRE data (Actor Watch, Detection Bot) will download the ATT&CK Enterprise STIX bundle (~25 MB) into `.cache/`. Subsequent runs use the cached copy.

## Project Structure

```
SecOps Innovation/
├── shared/                  # Common library modules
│   ├── llm.py               # Anthropic Claude client
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
├── .cache/                  # Auto-downloaded MITRE STIX data (gitignored)
├── .env                     # API keys and secrets (gitignored)
├── .env.sample              # Template showing required variables
├── .cursorrules             # Cursor AI coding context
├── .gitignore
└── requirements.txt
```

Each tool writes its output to its own `output/` subdirectory. These directories are created automatically on first run and are gitignored.

## KQL Rule Format

Detection Bot generates rules in the project's standard `.kql` format: YAML frontmatter between `---` markers followed by the KQL query body.

```yaml
---
name: "[InitialAccess] Suspicious sign-in from Tor exit node"
description: Detects sign-ins originating from known Tor exit nodes
severity: High
enabled: true
tactics:
  - InitialAccess
techniques:
  - T1078
entity_mappings:
  - Account
  - IPAddress
---
SigninLogs
| where TimeGenerated > ago(1h)
| where IPAddress in (TorExitNodes)
| project TimeGenerated, UserPrincipalName, IPAddress, Location
```

## Architecture Decisions

- **No live Sentinel connection** — all tools use local files and public APIs so there are no cloud credentials required for the POC. The code is structured with isolated API modules in `shared/` so live connections (Azure SDK, Sentinel API) can be swapped in later without rewriting tool logic.
- **MITRE ATT&CK as the common language** — Actor Watch and Detection Bot both reference the Enterprise ATT&CK matrix via `mitreattack-python`, ensuring technique IDs, tactic names, and group metadata are consistent across the toolkit.
- **Claude for generation, not for data** — Claude summarises and drafts, but the underlying data always comes from authoritative sources (CISA, MITRE, RSS feeds). This keeps outputs grounded and auditable.
- **Dual output** — every tool renders to the terminal with `rich` for immediate feedback and saves a Markdown file for sharing with stakeholders or pasting into Teams/email.

## Future Roadmap

- Connect to Sentinel API to pull live analytics rules and compare against ATT&CK coverage
- Add Microsoft Teams webhook notifications for new digests
- Scheduled runs via GitHub Actions or Azure Functions
- VirusTotal enrichment for IOCs mentioned in threat feeds
- Export Actor Watch profiles as ATT&CK Navigator layers for visual briefings
