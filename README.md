# 🛡️ SecOps Innovation Platform

**Threat Intelligence & Actor Monitoring Platform**

A focused cybersecurity intelligence platform featuring automated threat digests and an interactive threat actor database with a game-like character select interface.

## ✨ Features

- **📊 Threat Digest**: Automated intelligence reports combining CISA KEV and curated RSS feeds — generate on-demand or on a daily systemd timer
- **🔀 Executive / Tactical Toggle**: Every digest report has a one-click "Executive Briefing" vs "SecOps Tactical" view
- **🎯 Threat Actor Correlation**: Headlines are automatically matched against the full MITRE ATT&CK + Microsoft Threat Intel roster (100+ actors) and shown as chips on the digest
- **🎮 Actor Character Select**: Game-like interface for browsing threat actor profiles
- **📧 Header Analysis**: SPF/DKIM/DMARC verdicts, hop timeline, spoofing/lookalike-domain heuristics, and IOC extraction for suspicious emails
- **🔎 OSINT Lookup**: RDAP (free) + VirusTotal domain/IP/hash reputation lookups, self-throttled to the free-tier rate limit
- **📦 Breached Package Watchlist**: Tracks newly compromised NPM/Python packages surfaced in threat feeds
- **Sentinel Detection Drafts**: Generate disabled, review-first Microsoft Sentinel analytic rule YAML from digest items
- **📄 Multiple Formats**: HTML, PDF, and Markdown exports
- **⚡ Performance**: Smart caching, retry logic, and feed deduplication

## 🚀 Quick Start

For Azure Linux VM deployment, see [AZURE_VM_WEBAPP.md](AZURE_VM_WEBAPP.md).

Linux quick start:

```bash
chmod +x setup.sh generate_digest.sh start_workbench.sh cleanup_workspace.sh
./setup.sh
./generate_digest.sh --days 7
./start_workbench.sh --host 0.0.0.0 --port 8765 --no-open
```

See [SELF_SERVICE_SETUP.md](SELF_SERVICE_SETUP.md) for the full step-by-step guide.

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure Environment
Copy `.env.example` to `.env` and configure:
```bash
# Required
AZURE_OPENAI_KEY=your_key_here
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/

# Optional
ANTHROPIC_API_KEY=your_anthropic_key  # For Claude models
FEEDS_CACHE_ENABLED=true              # Enable caching for development
```

### 3. Generate Content
```bash
# Guided menu for non-technical users
python -m secops ui

# Browser workbench for digest review and detection drafts
python -m secops web

# Generate the latest threat digest and refresh the dashboard
python -m secops digest --days 7

# Open output/threat_digest/index.html for the latest report.
# The archive is output/threat_digest/history.html, and the latest report is also copied to output/threat_digest/latest.html.

# Refresh and view actor mentions across archived digests
python -m secops tracking --refresh

# List digest items and generate a Sentinel detection YAML draft
python -m secops detection --latest --list
python -m secops detection --latest --item 1

# Get specific actor intelligence
python -m secops actor "APT29" --recommendations

# Analyze suspicious email/message headers
python -m secops header --file suspicious_email.txt

# OSINT lookup for a domain, IP, or file hash
python -m secops osint 8.8.8.8
```

Script equivalents:

```bash
./generate_digest.sh --days 7
./generate_digest.sh --days 7 --no-llm
./start_workbench.sh --host 0.0.0.0 --port 8765 --no-open
./setup.sh
./cleanup_workspace.sh
```

## 🎮 Platform Commands

### Main Commands
```bash
python -m secops digest [--days 7] [--pdf]      # Generate threat digest
python -m secops actor [NAME] [OPTIONS]         # Actor intelligence
python -m secops tracking [--refresh]           # Actor mentions across digests
python -m secops detection [OPTIONS]            # Sentinel YAML detection drafts
python -m secops web [--port 8765]              # Local browser workbench (Digest, Header Analysis, OSINT tabs)
python -m secops header [--file PATH]           # Analyze raw email/message headers
python -m secops osint QUERY                    # RDAP + VirusTotal lookup for a domain/IP/hash
python -m secops ui                             # Guided command-line menu
```

### Detection Draft Options
```bash
python -m secops detection --latest --list          # Show digest items you can build detections from
python -m secops detection --latest --item 1        # Generate one disabled Sentinel YAML draft
python -m secops detection --title "Threat" --context "Details..."  # Manual rule request
python -m secops detection --index                 # Rebuild output/detections/index.html
```

Drafts are saved under `output/detections/drafts/YYYY-MM-DD/`. Open `output/detections/index.html` to review and copy YAML.

### Browser Workbench
```bash
python -m secops web
```

The workbench runs locally at `http://127.0.0.1:8765/` with three tabs:

- **Digest & Detections** — generate/refresh digests, select items, draft Sentinel YAML, review generated drafts.
- **Header Analysis** — paste raw headers or a full `.eml`; get SPF/DKIM/DMARC verdicts, a hop timeline, spoofing/lookalike-domain signals, and clickable extracted IOCs.
- **OSINT Lookup** — RDAP (free) + VirusTotal lookups for a domain, IP, or file hash.

On an Azure Linux VM, run `./start_workbench.sh --host 0.0.0.0 --port 8765 --no-open` behind your chosen network/auth controls, and install `secops-digest.timer.example` for unattended daily briefings. See [AZURE_VM_WEBAPP.md](AZURE_VM_WEBAPP.md).

### Actor Intelligence Options
```bash
python -m secops actor "APT29" --recommendations  # Get detailed profile
python -m secops actor "FIN7" --timeline         # Show activity timeline
python -m secops actor --search "lazarus"        # Search for actors
```

## 🏗️ Platform Architecture

### Threat Digest (`threat_digest/`)
- **Multi-source Intelligence**: CISA KEV + curated RSS feeds
- **LLM Summarization**: AI-powered analysis and structuring
- **Executive / Tactical Toggle**: One-click view switch on every generated report
- **Actor Correlation**: Headlines are auto-matched against `shared/actor_correlation.py`'s full actor roster and shown as chips
- **Interactive Reports**: Charts, progress bars, and mobile-optimized UI
- **Character Select Interface**: Game-like actor database navigation
- **Export Options**: HTML, PDF, and JSON formats
- **Automated Scheduling**: `secops-digest.timer.example` (systemd) generates a fresh daily briefing unattended

### Actor Watch (`actor_watch/`)
- **Unified Intelligence**: MITRE ATT&CK + Microsoft threat data (100+ actors)
- **Activity Tracking**: Real-time monitoring from security feeds, scanned against the full actor roster (`shared/actor_tracking.py`)
- **Timeline Analysis**: Historical activity patterns
- **Defensive Recommendations**: Actionable security guidance

### Detection Drafts (`detection/`)
- **Analyst Selection**: Choose a threat item from the latest generated digest
- **Template-Guided Output**: Uses `Templates/AnalyticRuleGuide` and `company_profile.yaml`
- **Review First**: Rules default to `enabled: false` and are saved for copy/paste review
- **Browser Workbench**: Local web UI with tabs for digest/detections, header analysis, and OSINT lookups

### Analyst Tooling (`analysis/`)
- **Header Analysis** (`analysis/email_header.py`): SPF/DKIM/DMARC parsing, Received-header hop timeline, From/Reply-To/Return-Path spoofing heuristics, lookalike-domain detection against `known_domains`, IOC extraction, heuristic risk score
- **OSINT Lookup** (`analysis/osint.py`): RDAP domain/IP lookups (free, no key) and VirusTotal domain/IP/hash reputation (needs `VIRUSTOTAL_API_KEY`), with built-in free-tier rate limiting
- Available via the web workbench tabs, or `secops header` / `secops osint` on the CLI

### Enhanced Features
- **Caching Layer**: Smart feed caching with configurable TTL
- **Error Handling**: Comprehensive retry logic and graceful degradation
- **Mobile Optimization**: Touch-friendly interfaces and responsive design

## 📁 Output Structure

```
SecOps Innovation/
├── output/
│   ├── threat_digest/
│   │   ├── index.html              # Latest digest report
│   │   ├── history.html            # Archived digest list
│   │   ├── latest.html             # Copy of the latest generated digest
│   │   ├── digest_2026-04-10.html  # Archived dated digest
│   │   ├── digest_2026-04-10.pdf
│   │   └── digest_2026-04-10.md
│   ├── actor_watch/
│   │   ├── APT29.md
│   │   ├── FIN7_timeline.md
│   │   └── Storm_1175.md
│   └── detections/
│       ├── index.html              # Detection draft review page
│       └── drafts/
│           └── 2026-04-10/
│               └── valid_example-rule.yaml
└── company_profile.yaml         # Organization configuration
```

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AZURE_OPENAI_KEY` | Azure OpenAI API key | Required |
| `AZURE_OPENAI_ENDPOINT` | Azure OpenAI endpoint URL | Required |
| `AZURE_OPENAI_DEPLOYMENT` | Deployment name | gpt-5 |
| `ANTHROPIC_API_KEY` | Anthropic API key for Claude | Optional |
| `FEEDS_CACHE_ENABLED` | Enable feed caching | false |
| `DIGEST_MAX_COMPLETION_TOKENS` | Max tokens for digest | 4000 |
| `VIRUSTOTAL_API_KEY` | Enables VirusTotal in the OSINT Lookup tool (RDAP works without it) | Optional |
| `DIGEST_SCHEDULE_DAYS` | Look-back window for the automated daily briefing (systemd timer) | 1 |
| `DIGEST_SCHEDULE_PDF` | Also render a PDF on every scheduled daily run | 0 |

### Company Profile (`company_profile.yaml`)
```yaml
company_name: "Your Organization"
industry: "Technology"
size: "Enterprise"
regions: ["North America", "Europe"]
threat_priorities:
  - "Ransomware"
  - "Supply Chain"
  - "Cloud Security"
known_domains: # your real sending domains — used by Header Analysis to flag lookalikes
  - "yourcompany.com"
```

## 🎯 Use Cases

### Security Operations Center (SOC)
- **Daily Briefings**: Automated threat intelligence digests
- **Actor Tracking**: Monitor specific threat groups targeting your industry
- **Incident Response**: Quick access to actor TTPs and defensive measures

### Threat Intelligence Teams
- **Research Platform**: Unified view of MITRE ATT&CK and Microsoft intelligence
- **Timeline Analysis**: Track threat actor campaigns over time
- **Report Generation**: Professional HTML and PDF reports for stakeholders

### Executive Reporting
- **Strategic Overview**: High-level threat landscape summaries
- **Risk Assessment**: Industry-specific threat actor targeting
- **Compliance**: Structured intelligence for regulatory requirements

## 🔧 Advanced Features

### PDF Export
```bash
pip install weasyprint
python launch.py digest --pdf
```

### Custom Feeds
Modify `shared/feeds.py` to add organization-specific threat intelligence sources.

### API Integration
The platform can be extended with custom APIs for:
- SIEM integration
- Ticketing system updates
- Custom data sources

## 🚦 Getting Started Workflow

1. **Configure**: Edit `.env` and `company_profile.yaml`
2. **Generate Digest**: `python -m secops digest --pdf`
3. **Review Dashboard**: Open `output/threat_digest/index.html`; previous dated reports remain in `output/threat_digest/history.html`
4. **Generate Detection Draft**: `python -m secops detection --latest --list`, then `python -m secops detection --latest --item <number>`
5. **Review YAML**: Open `output/detections/index.html` and copy/paste the draft after analyst review
6. **Get Specific Intelligence**: `python -m secops actor "APT29" --recommendations`
7. **Triage a Suspicious Email**: `python -m secops header --file suspicious_email.txt`, then follow up on flagged IOCs with `python -m secops osint <indicator>`
8. **Automate**: install `secops-digest.timer.example` on your VM for unattended daily briefings (see [AZURE_VM_WEBAPP.md](AZURE_VM_WEBAPP.md))

## 📊 Platform Statistics

The platform provides:
- **Total Threat Actors Tracked**: 100+ from MITRE ATT&CK and Microsoft
- **Intelligence Sources**: CISA KEV, 10+ curated RSS feeds
- **Export Formats**: HTML, PDF, Markdown, JSON
- **Interactive Interface**: Game-like character select for threat actors

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Test thoroughly: `python -m secops digest`
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**🛡️ SecOps Innovation Platform** - *Empowering security teams with actionable threat intelligence*
