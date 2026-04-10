# 🛡️ SecOps Innovation Platform

**Advanced Threat Intelligence & Actor Monitoring Platform**

A comprehensive cybersecurity intelligence platform that combines MITRE ATT&CK framework with Microsoft threat intelligence, automated threat digests, and real-time actor monitoring.

## ✨ Features

- **🏠 Dynamic Homepage**: Central hub with navigation to all platform features
- **📊 Threat Digest**: Automated intelligence reports combining CISA KEV and curated RSS feeds
- **🎯 Actor Watch**: Comprehensive threat actor profiles with TTPs and defensive recommendations
- **📈 Live Dashboard**: Real-time monitoring of threat actor activity
- **🔄 Auto-Updates**: Homepage automatically updates when new content is generated
- **📱 Mobile Responsive**: Optimized for all devices with touch-friendly interfaces
- **📄 Multiple Formats**: HTML, PDF, and Markdown exports
- **⚡ Performance**: Smart caching, retry logic, and feed deduplication

## 🚀 Quick Start

### 1. Initialize Platform
```bash
# Install dependencies
pip install -r requirements.txt

# Initialize the complete platform
python launch.py init --open
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

### 3. Start Using the Platform
```bash
# Start web server
python launch.py serve

# Generate threat digest
python launch.py digest --pdf

# Get actor intelligence
python launch.py actor "APT29" --recommendations

# Open monitoring dashboard
python launch.py dashboard --open
```

## 🎮 Platform Commands

### Main Commands
```bash
python launch.py init [--open]           # Initialize platform
python launch.py serve [--port 8000]     # Start web server
python launch.py digest [--days 7] [--pdf] # Generate threat digest
python launch.py actor [NAME] [OPTIONS]  # Actor intelligence
python launch.py dashboard [--open]      # Generate monitoring dashboard
```

### Actor Intelligence Options
```bash
python launch.py actor "APT29" --recommendations  # Get detailed profile
python launch.py actor "FIN7" --timeline         # Show activity timeline
python launch.py actor --search "lazarus"        # Search for actors
```

## 🏗️ Platform Architecture

### Homepage System (`homepage/`)
- **Dynamic Content Scanning**: Automatically discovers threat digests and actor profiles
- **Interactive Navigation**: Pills/cards for easy navigation between sections
- **Real-time Stats**: Live metrics on tracked actors and generated content
- **Auto-refresh**: Updates every 5 minutes with new content

### Threat Digest (`threat_digest/`)
- **Multi-source Intelligence**: CISA KEV + curated RSS feeds
- **LLM Summarization**: AI-powered analysis and structuring
- **Interactive Reports**: Charts, progress bars, and mobile-optimized UI
- **Export Options**: HTML, PDF, and JSON formats

### Actor Watch (`actor_watch/`)
- **Unified Intelligence**: MITRE ATT&CK + Microsoft threat data
- **Activity Tracking**: Real-time monitoring from security feeds
- **Timeline Analysis**: Historical activity patterns
- **Defensive Recommendations**: Actionable security guidance

### Enhanced Features
- **Auto-Update System**: Homepage refreshes when new content is generated
- **Caching Layer**: Smart feed caching with configurable TTL
- **Error Handling**: Comprehensive retry logic and graceful degradation
- **Mobile Optimization**: Touch-friendly interfaces and responsive design

## 📁 Output Structure

```
SecOps Innovation/
├── index.html                    # Main homepage
├── output/
│   ├── threat_digest/
│   │   ├── digest_2026-04-10.html
│   │   ├── digest_2026-04-10.pdf
│   │   └── digest_2026-04-10.json
│   └── actor_watch/
│       ├── APT29.md
│       ├── FIN7_timeline.md
│       └── dashboard.html
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

1. **Initialize**: `python launch.py init --open`
2. **Configure**: Edit `.env` and `company_profile.yaml`
3. **Generate Content**: 
   - `python launch.py digest --pdf`
   - `python launch.py actor "APT29" --recommendations`
4. **Monitor**: `python launch.py dashboard --open`
5. **Serve**: `python launch.py serve` for web access

## 📊 Platform Statistics

After initialization, your homepage will show:
- **Total Threat Actors Tracked**: 100+ from MITRE ATT&CK and Microsoft
- **Intelligence Sources**: CISA KEV, 10+ curated RSS feeds
- **Export Formats**: HTML, PDF, Markdown, JSON
- **Update Frequency**: Real-time with auto-refresh

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Test thoroughly: `python launch.py init && python launch.py serve`
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**🛡️ SecOps Innovation Platform** - *Empowering security teams with actionable threat intelligence*