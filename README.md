# 🛡️ SecOps Innovation Platform

**Threat Intelligence & Actor Monitoring Platform**

A focused cybersecurity intelligence platform featuring automated threat digests and an interactive threat actor database with a game-like character select interface.

## ✨ Features

- **📊 Threat Digest**: Automated intelligence reports combining CISA KEV and curated RSS feeds
- **🎮 Actor Character Select**: Game-like interface for browsing threat actor profiles
- **🎯 Actor Intelligence**: Comprehensive threat actor profiles with TTPs and defensive recommendations
- **📄 Multiple Formats**: HTML, PDF, and Markdown exports
- **⚡ Performance**: Smart caching, retry logic, and feed deduplication

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure Environment
Copy `.env.example` to `.env` and configure:
```bash
# Required
AZURE_OPENAI_API_KEY=your_key_here
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/

# Optional
ANTHROPIC_API_KEY=your_anthropic_key  # For Claude models
FEEDS_CACHE_ENABLED=true              # Enable caching for development
```

### 3. Generate Content
```bash
# Generate threat digest with character select
python -m secops digest --days 7

# Get specific actor intelligence
python -m secops actor "APT29" --recommendations
```

## 🎮 Platform Commands

### Main Commands
```bash
python -m secops digest [--days 7] [--pdf]      # Generate threat digest
python -m secops actor [NAME] [OPTIONS]         # Actor intelligence
```

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
- **Interactive Reports**: Charts, progress bars, and mobile-optimized UI
- **Character Select Interface**: Game-like actor database navigation
- **Export Options**: HTML, PDF, and JSON formats

### Actor Watch (`actor_watch/`)
- **Unified Intelligence**: MITRE ATT&CK + Microsoft threat data
- **Activity Tracking**: Real-time monitoring from security feeds
- **Timeline Analysis**: Historical activity patterns
- **Defensive Recommendations**: Actionable security guidance

### Enhanced Features
- **Caching Layer**: Smart feed caching with configurable TTL
- **Error Handling**: Comprehensive retry logic and graceful degradation
- **Mobile Optimization**: Touch-friendly interfaces and responsive design

## 📁 Output Structure

```
SecOps Innovation/
├── output/
│   ├── threat_digest/
│   │   ├── digest_2026-04-10.html  # Main digest with character select
│   │   ├── digest_2026-04-10.pdf
│   │   └── digest_2026-04-10.json
│   └── actor_watch/
│       ├── APT29.md
│       ├── FIN7_timeline.md
│       └── Storm_1175.md
└── company_profile.yaml         # Organization configuration
```

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AZURE_OPENAI_API_KEY` | Azure OpenAI API key | Required |
| `AZURE_OPENAI_ENDPOINT` | Azure OpenAI endpoint URL | Required |
| `AZURE_OPENAI_DEPLOYMENT_NAME` | Deployment name | gpt-4 |
| `ANTHROPIC_API_KEY` | Anthropic API key for Claude | Optional |
| `FEEDS_CACHE_ENABLED` | Enable feed caching | false |
| `DIGEST_MAX_COMPLETION_TOKENS` | Max tokens for digest | 4000 |

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
3. **Explore Actors**: Open the HTML digest and click the second navigation dot
4. **Get Specific Intelligence**: `python -m secops actor "APT29" --recommendations`

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