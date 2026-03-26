# 🚀 SecOps Innovation - Quick Start Guide

## What This Project Does

This is a **cybersecurity toolkit** with 3 main tools that help security teams:

1. **📊 Threat Digest** - Creates weekly security reports from live threat feeds
2. **🕵️ Actor Watch** - Looks up detailed profiles of cyber threat groups (APTs)
3. **🛡️ Detection Bot** - Generates security detection rules for Microsoft Sentinel

## 🏃‍♂️ Quick Setup (5 minutes)

### Step 1: Install Python Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Configure API Keys (Required for AI Features)
```bash
# Copy the example file
copy .env.example .env

# Edit .env and add your API keys:
# - AZURE_OPENAI_ENDPOINT (required for AI features)
# - AZURE_OPENAI_KEY (required for AI features)
# - VIRUSTOTAL_API_KEY (optional, free from virustotal.com)
# - GITHUB_TOKEN (optional, for GitHub integration)
```

### Step 3: You're Ready! 🎉

## 🎯 How to Use Each Tool

### 1. 📊 Threat Digest - Get Weekly Security Reports

**What it does:** Pulls the latest vulnerabilities and security news, then creates an executive-friendly report.

```bash
# Generate this week's threat report
python -m threat_digest

# Get last 30 days of threats
python -m threat_digest --days 30

# Skip AI analysis (no API key needed)
python -m threat_digest --no-llm
```

**Output:** Creates reports in `output/threat_digest/` including stakeholder-friendly HTML pages.

### 2. 🕵️ Actor Watch - Research Threat Groups

**What it does:** Shows detailed profiles of cyber threat groups using MITRE ATT&CK data.

```bash
# List all known threat groups
python -m actor_watch

# Get detailed profile of a specific group
python -m actor_watch "APT29"
python -m actor_watch "Lazarus Group"
python -m actor_watch "FIN7"
```

**Output:** Creates detailed reports in `output/actor_watch/` with tactics, techniques, and tools used.

### 3. 🛡️ Detection Bot - Generate Security Rules

**What it does:** Creates Microsoft Sentinel detection rules for specific attack techniques.

```bash
# Generate rule for a technique
python -m detection_bot T1078          # Valid Accounts
python -m detection_bot T1003.006      # DCSync
python -m detection_bot T1566.001      # Spearphishing

# Customize the rule
python -m detection_bot T1078 --severity High
```

**Output:** Creates KQL detection rules in `output/detection_bot/`.

## 📁 Where to Find Your Results

All outputs go to the `output/` folder:

```
output/
├── threat_digest/           # Security reports and stakeholder digests
├── actor_watch/            # Threat group profiles  
└── detection_bot/          # Generated security rules
```

## 🔧 Troubleshooting

### "No API Key" Errors
- **For basic use:** Most tools work without API keys
- **For AI features:** Add `AZURE_OPENAI_ENDPOINT` and `AZURE_OPENAI_KEY` to your `.env` file
- **Alternative:** Use Anthropic by setting `ANTHROPIC_API_KEY` (fallback option)

### SSL Certificate Errors
If you're behind a corporate firewall:
```bash
# In your .env file, add:
LLM_SSL_VERIFY_DISABLE=true
```

### Need Help?
- Check the detailed `README.md` for advanced usage
- All tools have `--help` options: `python -m threat_digest --help`

## 💡 Common Use Cases

### Weekly Security Briefing
```bash
# Generate this week's threat digest
python -m threat_digest

# Open the HTML file in output/threat_digest/stakeholder_digests/
# Share with executives and stakeholders
```

### Threat Intelligence Research
```bash
# Research a specific threat group
python -m actor_watch "APT28"

# Generate detection rules for their common techniques
python -m detection_bot T1078
python -m detection_bot T1003
```

### Building Detection Coverage
```bash
# Generate rules for common attack techniques
python -m detection_bot T1566.001  # Phishing
python -m detection_bot T1055      # Process Injection  
python -m detection_bot T1021.001  # RDP
```

---

**🎯 That's it!** You now have a powerful cybersecurity toolkit for threat intelligence, research, and detection rule generation. Start with `python -m threat_digest` to see it in action!