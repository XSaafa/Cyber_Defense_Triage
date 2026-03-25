# 🛡️ Cyber-Defense Triage System

**AI-powered security incident triage with external threat intelligence integration**

A comprehensive cybersecurity triage platform with MCP server integration, web dashboard, and CLI tools. Provides instant alert analysis, log classification, IOC scanning with real-time threat intelligence, CVE lookups, and incident response playbooks.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org)

---

## 🎯 Features

### **1. Alert Triage**
- Instant severity classification (Critical/High/Medium/Low)
- MITRE ATT&CK technique mapping
- SLA-based response timelines
- First responder action steps

### **2. Log Classification**
- Pattern matching for 12+ attack types
- Detects: SQL injection, XSS, RCE, brute force, Log4Shell, Shellshock, path traversal, CSRF, malware droppers
- Forensic analysis guidance
- Multi-pattern detection

### **3. IOC Scanner with Threat Intelligence**
- **Supported IOC types:** IP, domain, hash, URL, email
- **External enrichment from:**
  - VirusTotal (file/IP/domain/URL reputation)
  - AbuseIPDB (IP abuse scores & geolocation)
  - AlienVault OTX (threat pulses & tags)
  - Emerging Threats (compromised IP blocklist)
  - MITRE ATT&CK (latest techniques)
  - **NVD (CVE vulnerability data)** ⭐ NEW
- Auto-defanging for safe sharing
- Validation tool recommendations

### **4. CVE Vulnerability Lookup** ⭐ NEW
- Look up any CVE from National Vulnerability Database
- CVSS scores and severity ratings
- CWE (Common Weakness Enumeration)
- Exploitability and impact metrics
- References and patch information

### **5. Incident Response Playbooks**
- **8 comprehensive playbooks:** Ransomware, Phishing, Brute Force, Data Exfiltration, Lateral Movement, DDoS, Insider Threat, Web Defacement
- Step-by-step SOC procedures
- IOC hunting checklists
- Evidence preservation guides
- Escalation criteria

### **6. Incident Timeline Tracker**
- Chronological incident tracking
- localStorage persistence
- Severity-based filtering
- Export-ready documentation

---

## 🚀 Quick Start

### **Prerequisites**
- Node.js 18+ ([Download](https://nodejs.org))
- Optional: API keys for external threat intelligence (free tiers available)

### **Installation**

```bash
# Clone the repository
git clone <your-repo-url>
cd cyber-triage-system

# Install dependencies
npm install

# Test MCP server
node server.js
# Should output: "Cyber-Defense Triage MCP server running on stdio"
```

---

## 🔧 Usage

### **1. MCP Server (Windsurf/Cursor/Claude Desktop)**

#### **Windsurf Setup**
1. Open Windsurf Settings
2. Search for "MCP"
3. Click the gear icon to edit MCP configuration
4. Add this JSON:

```json
{
  "mcpServers": {
    "cyber-triage": {
      "command": "node",
      "args": [
        "C:/Users/YOUR_USERNAME/path/to/cyber-triage-system/server.js"
      ],
      "env": {}
    }
  }
}
```

5. Save and restart Windsurf
6. Use in Cascade chat:

```
Use cyber-triage to triage this alert: ransomware detected on DESKTOP-01
Use cyber-triage to classify this log: Failed password for root from 45.33.32.156
Use cyber-triage to get the playbook for phishing
Use cyber-triage to scan this ip IOC: 185.220.101.47
Use cyber-triage to check CVE-2021-44228
```

#### **Available MCP Tools**
- `triage_alert` - Analyze security alerts
- `classify_log` - Classify log entries
- `get_playbook` - Get incident response playbooks
- `scan_ioc` - Scan indicators of compromise with threat intelligence
- `check_cve` - Look up CVE vulnerabilities ⭐ NEW

---

### **2. Web Dashboard**

```bash
# Start the dashboard
npm run dashboard

# Open browser to http://localhost:5173
```

**Dashboard Features:**
- Alert Triage panel
- Log Classifier
- Playbook Viewer
- IOC Scanner with API key management
- Incident Timeline tracker

**Configure API Keys in Dashboard:**
1. Go to IOC Scanner panel
2. Click "🔑 API Keys" button
3. Enter your API keys (VirusTotal, AbuseIPDB)
4. Click Save

---

### **3. CLI Tool**

```bash
# Triage an alert
npm run cli triage "ransomware detected on server"

# Classify a log
npm run cli log "Failed password for admin from 192.168.1.100"

# View a playbook
npm run cli playbook ransomware

# Scan an IOC
npm run cli ioc ip 185.220.101.47
```

---

## 🌐 External Threat Intelligence Setup

The system works **offline by default** using local knowledge bases. For enhanced IOC analysis with real-time threat intelligence:

### **Supported APIs**

| API | Type | Key Required | Free Tier | Purpose |
|-----|------|--------------|-----------|---------|
| **VirusTotal** | Multi-IOC | Yes | 500/day | File/IP/domain/URL reputation |
| **AbuseIPDB** | IP | Yes | 1000/day | IP abuse scores & geolocation |
| **AlienVault OTX** | Multi-IOC | Yes | Unlimited | Threat pulses & tags |
| **Emerging Threats** | IP | No | Unlimited | Compromised IP blocklist |
| **MITRE ATT&CK** | Techniques | No | Unlimited | Latest attack techniques |
| **NVD** | CVE | Optional | 5 req/30s (50 with key) | CVE vulnerability data |

### **Get Free API Keys**

1. **VirusTotal:** https://www.virustotal.com/ (Sign up → Profile → API Key)
2. **AbuseIPDB:** https://www.abuseipdb.com/ (Register → Account → API)
3. **AlienVault OTX:** https://otx.alienvault.com/ (Settings → API Integration)
4. **NVD:** https://nvd.nist.gov/developers/request-an-api-key (Optional, increases rate limit)

### **Configuration**

#### **For MCP Server:**

```bash
# Copy example file
cp .env.example .env

# Edit .env and add your keys
notepad .env  # Windows
nano .env     # Linux/Mac
```

Example `.env`:
```env
VIRUSTOTAL_API_KEY=your_actual_key_here
ABUSEIPDB_API_KEY=your_actual_key_here
OTX_API_KEY=your_actual_key_here
NVD_API_KEY=your_actual_key_here
```

Restart Windsurf after adding keys.

#### **For Dashboard:**

1. Start dashboard: `npm run dashboard`
2. Go to IOC Scanner panel
3. Click "🔑 API Keys"
4. Enter keys and save (stored in browser localStorage)

---

## 📁 Project Structure

```
cyber-triage-system/
├── server.js                    # MCP server (5 tools)
├── package.json                 # Dependencies
├── .env.example                 # API key template
├── knowledge-base/              # Offline threat intelligence
│   ├── severity-rules.json      # Severity levels & SLAs
│   ├── log-patterns.json        # Attack pattern detection
│   ├── playbooks.json           # Incident response procedures
│   └── mitre-map.json           # MITRE ATT&CK mappings
├── lib/
│   └── threatIntelligence.js    # External API integrations
├── cli/
│   └── triage-cli.js            # Command-line interface
├── dashboard/                   # React web application
│   └── src/
│       ├── components/          # UI components
│       └── lib/
│           ├── triageEngine.js  # Core triage logic
│           └── threatIntelAPI.js # Browser threat intel
├── tests/                       # Vitest test suite
└── docs/
    ├── THREAT_INTEL_SETUP.md    # Detailed API setup guide
    ├── SETUP_GUIDE.md           # MCP configuration guide
    └── HOW_TO_USE_IN_CASCADE.md # Cascade usage examples
```

---

## 🧪 Testing

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Lint code
npm run lint

# Fix lint issues
npm run lint:fix
```

---

## 📖 Documentation

- **[THREAT_INTEL_SETUP.md](THREAT_INTEL_SETUP.md)** - Complete guide to external API integration
- **[SETUP_GUIDE.md](SETUP_GUIDE.md)** - Step-by-step MCP configuration for Windsurf
- **[HOW_TO_USE_IN_CASCADE.md](HOW_TO_USE_IN_CASCADE.md)** - Example prompts for Cascade

---

## 💡 Example Usage

### **Triage a Ransomware Alert**
```
Use cyber-triage to triage this alert: ransomware encrypting files on FILESERVER-01
```

**Response includes:**
- 🔴 CRITICAL severity
- MITRE ATT&CK: T1486 (Data Encrypted for Impact)
- Immediate isolation steps
- Evidence preservation checklist
- Ransomware response playbook excerpt

---

### **Scan a Suspicious IP with Threat Intelligence**
```
Use cyber-triage to scan this ip IOC: 185.220.101.47
```

**Response includes:**
- Overall reputation (Malicious/Suspicious/Clean)
- AbuseIPDB abuse score (0-100)
- VirusTotal detections
- Emerging Threats listing
- Country, ISP, geolocation
- Recommended blocking actions

---

### **Look Up a CVE Vulnerability**
```
Use cyber-triage to check CVE-2021-44228
```

**Response includes:**
- CVSS score and severity (9.8 - CRITICAL)
- Description (Log4Shell RCE vulnerability)
- CWE classification
- Exploitability and impact scores
- Patch references
- Severity assessment and recommendations

---

## 🔒 Security & Privacy

- **Offline-first:** Works without internet or API keys
- **No data collection:** All processing is local
- **API keys:** Stored locally (`.env` for server, localStorage for browser)
- **Rate limiting:** Respects free tier limits with intelligent caching
- **Caching:** 1-hour TTL to minimize API calls

---

## 🛠️ Advanced Features

### **MITRE ATT&CK Auto-Update**

Update your local MITRE mappings with the latest techniques:

```bash
node -e "import('./lib/threatIntelligence.js').then(m => m.updateMitreKnowledgeBase().then(console.log))"
```

### **Cache Management**

```javascript
import { getCacheStats, clearCache } from './lib/threatIntelligence.js';

// View cache stats
console.log(getCacheStats());

// Clear cache
clearCache();
```

---

## 🤝 Contributing

Contributions welcome! To extend the system:

### **Add a New Attack Pattern**

Edit `knowledge-base/log-patterns.json`:

```json
{
  "new_attack": {
    "pattern": "your_regex_pattern",
    "patternFlags": "i",
    "keywords": ["keyword1", "keyword2"],
    "severity": "high",
    "type": "Attack Type",
    "description": "What this attack does",
    "action": "What to do when detected"
  }
}
```

### **Add a New Playbook**

Edit `knowledge-base/playbooks.json`:

```json
{
  "newincident": {
    "name": "New Incident Response",
    "steps": ["Step 1", "Step 2", "..."],
    "iocs_to_look_for": ["IOC 1", "IOC 2"],
    "escalation_criteria": ["When to escalate"],
    "evidence_checklist": ["What to preserve"]
  }
}
```

---

## 📊 Tech Stack

- **Backend:** Node.js, MCP SDK, Zod
- **Frontend:** React, Vite, TailwindCSS
- **Testing:** Vitest
- **Linting:** ESLint
- **APIs:** VirusTotal, AbuseIPDB, AlienVault OTX, NVD, MITRE ATT&CK

---

## 📝 License

MIT License - See LICENSE file for details

---

## 🙏 Acknowledgments

- **MITRE ATT&CK** for the attack framework
- **NVD/NIST** for CVE data
- **VirusTotal, AbuseIPDB, AlienVault** for threat intelligence
- **Emerging Threats** for IP blocklists
- **MCP SDK** for IDE integration

---

## 📧 Support

For issues, questions, or feature requests, please open an issue on GitHub.

---

## 🎯 Roadmap

- [ ] Add more external threat feeds (Shodan, Censys)
- [ ] Machine learning-based anomaly detection
- [ ] SIEM integration (Splunk, Elastic)
- [ ] Automated playbook execution
- [ ] Multi-language support
- [ ] Mobile app for on-call analysts

---

**Built for SOC analysts, by security professionals** 🛡️
