# 🎯 Storm-1175 Demo Script for Manager

## **Quick 5-Minute Demo Commands**

### **1. Initialize Platform (30 seconds)**
```bash
python launch.py init --open
```
*"This initializes our complete threat intelligence platform and opens the homepage"*

### **2. Generate Storm-1175 Profile (1 minute)**
```bash
python launch.py actor "Storm-1175" --recommendations
```
*"Here we're pulling comprehensive intelligence on Storm-1175, a financially motivated ransomware group"*

### **3. Show Activity Timeline (1 minute)**
```bash
python launch.py actor "Storm-1175" --timeline --days 30
```
*"This shows recent activity and mentions of Storm-1175 in security feeds over the last 30 days"*

### **4. Generate Current Threat Digest (2 minutes)**
```bash
python launch.py digest --pdf --days 7
```
*"This creates our weekly threat intelligence digest with PDF export for stakeholders"*

### **5. Open Live Dashboard (30 seconds)**
```bash
python launch.py dashboard --open
```
*"And here's our live monitoring dashboard showing all tracked threat actors"*

---

## **Demo Talking Points**

### **🛡️ Platform Overview**
- **"This is our SecOps Innovation Platform - a comprehensive threat intelligence system"**
- **"It combines MITRE ATT&CK with Microsoft threat intelligence"**
- **"Everything runs locally with beautiful, stakeholder-ready reports"**

### **🎯 Storm-1175 Specifics**
- **"Storm-1175 is a financially motivated ransomware group active since 2022"**
- **"They use BlackCat/ALPHV ransomware with double extortion tactics"**
- **"Primary targets: Healthcare, manufacturing, education, government"**
- **"Known for sophisticated attack chains and living-off-the-land techniques"**

### **📊 Key Features to Highlight**
- **"Interactive HTML reports"** - Click through the Storm-1175 profile
- **"Real-time activity tracking"** - Show timeline of recent mentions
- **"PDF exports"** - Professional reports for executives
- **"Mobile responsive"** - Access from anywhere
- **"Auto-updating homepage"** - Central hub for all intelligence

### **💼 Business Value**
- **"Reduces threat research time from hours to minutes"**
- **"Professional reports ready for stakeholder presentations"**
- **"Comprehensive coverage of 100+ threat actors"**
- **"Real-time monitoring of threat landscape"**

---

## **If Manager Asks Questions:**

### **"How current is this data?"**
*"The platform pulls from live CISA feeds, security RSS feeds, and the latest MITRE ATT&CK data. Storm-1175 intelligence includes activity through Q1 2024."*

### **"Can we customize this for our industry?"**
*"Absolutely - we can configure company profiles to focus on specific sectors, regions, and threat priorities relevant to our organization."*

### **"What about integration with our existing tools?"**
*"The platform generates JSON, HTML, and PDF outputs that can integrate with SIEMs, ticketing systems, or be embedded in security dashboards."*

### **"How much maintenance does this require?"**
*"Minimal - it's designed to be self-contained. We can run it on a small VM and set up automated daily reports."*

---

## **Demo Flow (5 minutes total)**

1. **[30s]** Open homepage → "Here's our threat intelligence hub"
2. **[60s]** Generate Storm-1175 profile → "Watch it pull comprehensive intelligence"
3. **[60s]** Show timeline → "Recent activity and threat landscape"
4. **[120s]** Generate digest → "Weekly stakeholder report with PDF"
5. **[30s]** Open dashboard → "Live monitoring of all threats"

**Closing:** *"This gives us enterprise-grade threat intelligence capabilities with minimal overhead and maximum insight."*