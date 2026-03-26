// Extracted tool logic — pure async functions usable by both MCP server and the AI agent
import { readFileSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'
import { enrichIOC, checkNVD } from './threatIntelligence.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

const SEVERITY_MATRIX = JSON.parse(readFileSync(join(__dirname, '..', 'knowledge-base', 'severity-rules.json'), 'utf-8'))
const PLAYBOOKS = JSON.parse(readFileSync(join(__dirname, '..', 'knowledge-base', 'playbooks.json'), 'utf-8'))
const LOG_PATTERNS_RAW = JSON.parse(readFileSync(join(__dirname, '..', 'knowledge-base', 'log-patterns.json'), 'utf-8'))
const MITRE_MAP = JSON.parse(readFileSync(join(__dirname, '..', 'knowledge-base', 'mitre-map.json'), 'utf-8'))

const LOG_PATTERNS = {}
for (const [key, pattern] of Object.entries(LOG_PATTERNS_RAW)) {
  LOG_PATTERNS[key] = {
    ...pattern,
    pattern: new RegExp(pattern.pattern, pattern.patternFlags || 'i')
  }
}

// ─── Tool: triage_alert ───────────────────────────────────────────────────────

export async function triageAlert({ alert_description, source_system, affected_asset }) {
  const desc = alert_description.toLowerCase()

  let severity = 'low'
  let alertType = 'Unknown'
  let mitreEntry = null

  if (/ransomware|encrypting|ransom|cryptolocker/i.test(desc)) {
    severity = 'critical'; alertType = 'Ransomware'
    mitreEntry = MITRE_MAP['ransomware']
  } else if (/exfil|data.*transfer|upload.*external|mega\.nz|pastebin/i.test(desc)) {
    severity = 'critical'; alertType = 'Data Exfiltration'
    mitreEntry = MITRE_MAP['data exfiltration']
  } else if (/rce|remote.*execut|reverse.*shell|webshell|cmd\.exe.*from/i.test(desc)) {
    severity = 'critical'; alertType = 'Remote Code Execution'
  } else if (/lateral.*mov|pass.*hash|pass.*ticket|kerberoast|psexec/i.test(desc)) {
    severity = 'high'; alertType = 'Lateral Movement'
    mitreEntry = MITRE_MAP['lateral movement']
  } else if (/privilege.*escal|privesc|sudo|runas.*admin/i.test(desc)) {
    severity = 'high'; alertType = 'Privilege Escalation'
    mitreEntry = MITRE_MAP['privilege escalation']
  } else if (/phish|spearphish|malicious.*email|credential.*harvest/i.test(desc)) {
    severity = 'high'; alertType = 'Phishing'
    mitreEntry = MITRE_MAP['phishing']
  } else if (/sql.*inject|union.*select|xp_cmdshell/i.test(desc)) {
    severity = 'high'; alertType = 'SQL Injection'
    mitreEntry = MITRE_MAP['sql injection']
  } else if (/brute.*force|password.*spray|multiple.*failed.*login|login.*attempt/i.test(desc)) {
    severity = 'medium'; alertType = 'Brute Force'
    mitreEntry = MITRE_MAP['brute force']
  } else if (/persist|scheduled.*task|registry.*run|cron.*added/i.test(desc)) {
    severity = 'high'; alertType = 'Persistence Mechanism'
    mitreEntry = MITRE_MAP['persistence']
  } else if (/scan|port.*scan|nmap|discovery/i.test(desc)) {
    severity = 'low'; alertType = 'Reconnaissance / Scanning'
  } else if (/anomal|unusual|suspicious/i.test(desc)) {
    severity = 'medium'; alertType = 'Suspicious Activity'
  }

  const sev = SEVERITY_MATRIX[severity]
  const playbook = PLAYBOOKS[alertType.toLowerCase().replace(/\s+/g, '')] ||
                   PLAYBOOKS[alertType === 'Brute Force' ? 'bruteforce' : 'phishing']

  const assetInfo = affected_asset ? `\n**Affected Asset:** ${affected_asset}` : ''
  const sourceInfo = source_system ? `\n**Alert Source:** ${source_system}` : ''

  let response = `## ${sev.color} ${sev.label} — ${alertType}\n`
  response += `${sourceInfo}${assetInfo}\n\n`
  response += `**SLA:** ${sev.sla}\n`
  response += `**What this means:** ${sev.description}\n\n`

  if (mitreEntry) {
    response += `### MITRE ATT&CK Mapping\n`
    response += `- **Tactic:** ${mitreEntry.tactic}\n`
    response += `- **Technique:** ${mitreEntry.technique}\n`
    response += `- **Sub-technique:** ${mitreEntry.subtechnique}\n\n`
  }

  response += `### Immediate First Responder Actions\n`
  if (severity === 'critical') {
    response += `⚠️ **DO NOT delay. Execute these steps NOW:**\n`
    response += `1. Notify your incident commander / security lead immediately\n`
    response += `2. If ransomware or active exfil — ISOLATE the system from network NOW\n`
    response += `3. Preserve evidence: RAM dump, running processes, network connections\n`
    response += `4. Open an incident ticket and start a timeline log\n\n`
  } else if (severity === 'high') {
    response += `1. Verify the alert is not a false positive (check 2 corroborating logs)\n`
    response += `2. Identify all affected assets in your SIEM\n`
    response += `3. Notify your team lead and begin containment\n`
    response += `4. Start preserving logs — they may rotate\n\n`
  } else if (severity === 'medium') {
    response += `1. Investigate the alert context — is this a known pattern?\n`
    response += `2. Correlate with other alerts from the same source/asset\n`
    response += `3. Monitor for escalation indicators\n\n`
  } else {
    response += `1. Log and monitor — no immediate action required\n`
    response += `2. Review during normal business hours\n\n`
  }

  if (playbook) {
    response += `### Response Playbook: ${playbook.name}\n`
    playbook.steps.slice(0, 4).forEach((step, i) => {
      response += `${i + 1}. ${step}\n`
    })
    response += `\n_Use get_playbook("${alertType.toLowerCase()}") for the full playbook._\n\n`
  }

  response += `### Quick Questions to Answer Now\n`
  response += `- Was the action successful or just attempted?\n`
  response += `- What user/process triggered this?\n`
  response += `- Has this asset been involved in other alerts recently?\n`
  response += `- Is this asset internet-facing or internal?\n`

  return response
}

// ─── Tool: classify_log ───────────────────────────────────────────────────────

export async function classifyLog({ log_entry, log_type }) {
  const matches = []

  for (const [key, pattern] of Object.entries(LOG_PATTERNS)) {
    if (pattern.pattern.test(log_entry)) {
      matches.push({ key, ...pattern })
    }
  }

  let response = `## Log Analysis Result\n`
  if (log_type) response += `**Log Type:** ${log_type}\n`
  response += `\`\`\`\n${log_entry.slice(0, 300)}${log_entry.length > 300 ? '...' : ''}\n\`\`\`\n\n`

  if (matches.length === 0) {
    const hasIp = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(log_entry)
    const hasError = /error|fail|denied|blocked|reject/i.test(log_entry)
    const hasSuccess = /accept|success|granted|authenticated/i.test(log_entry)

    response += `### Classification: No Known Attack Pattern Detected\n\n`
    response += `This log entry does not match known attack signatures.\n\n`

    if (hasIp && hasError) {
      response += `**Note:** Contains an IP address and error/denial — consider correlating this IP against threat intel feeds.\n`
    }
    if (hasSuccess) {
      response += `**Note:** Log indicates a successful action. If unexpected, investigate the user/source.\n`
    }
    response += `\n**Recommendation:** Log for baseline, monitor for pattern recurrence.\n`
  } else {
    const topMatch = matches.reduce((a, b) => {
      const order = ['critical', 'high', 'medium', 'low']
      return order.indexOf(a.severity) <= order.indexOf(b.severity) ? a : b
    })

    const sev = SEVERITY_MATRIX[topMatch.severity]
    response += `### ${sev.color} ${sev.label} — ${topMatch.type}\n\n`
    response += `**What this log indicates:** ${topMatch.description}\n\n`
    response += `**Immediate action:** ${topMatch.action}\n\n`

    if (matches.length > 1) {
      response += `**Additional patterns detected:**\n`
      matches.slice(1).forEach(m => {
        response += `- ${m.type}: ${m.description}\n`
      })
      response += `\n`
    }

    response += `### Forensic Analysis Tips\n`
    response += `- Extract the source IP and look it up on AbuseIPDB or VirusTotal\n`
    response += `- Check if this pattern appears in other log sources in the same time window\n`
    response += `- Look for what happened BEFORE and AFTER this log entry (context window ±5 min)\n`
    response += `- Preserve this log entry and its neighbors before log rotation\n`
  }

  return response
}

// ─── Tool: get_playbook ───────────────────────────────────────────────────────

export async function getPlaybook({ incident_type, include_iocs = true }) {
  const playbook = PLAYBOOKS[incident_type]
  if (!playbook) {
    return `No playbook found for: ${incident_type}`
  }

  let response = `## Incident Response Playbook: ${playbook.name}\n\n`
  response += `> This is a first-responder triage playbook. Escalate to your IR team for full forensic investigation.\n\n`

  response += `### Response Steps (Follow in Order)\n\n`
  playbook.steps.forEach((step, i) => {
    const phase = step.split(':')[0]
    const detail = step.split(':').slice(1).join(':').trim()
    response += `**Step ${i + 1} — ${phase}**\n${detail}\n\n`
  })

  if (include_iocs && playbook.iocs_to_look_for) {
    response += `### IOCs to Hunt For\n`
    playbook.iocs_to_look_for.forEach(ioc => {
      response += `- ${ioc}\n`
    })
    response += `\n`
  }

  response += `### Escalation Criteria\n`
  response += `Escalate to senior IR analyst / management if:\n`
  response += `- Confirmed data exfiltration of PII or sensitive records\n`
  response += `- Attack has spread to 3+ systems\n`
  response += `- Critical infrastructure or domain controllers are affected\n`
  response += `- Regulatory notification may be required (GDPR, HIPAA, PCI-DSS)\n\n`

  response += `### Evidence Preservation Checklist\n`
  response += `- [ ] RAM capture (use WinPmem or LiME)\n`
  response += `- [ ] Disk image (write-blocked)\n`
  response += `- [ ] Network flow logs\n`
  response += `- [ ] Authentication logs (past 7 days)\n`
  response += `- [ ] Timeline documented with UTC timestamps\n`

  return response
}

// ─── Tool: scan_ioc ──────────────────────────────────────────────────────────

export async function scanIOC({ ioc_value, ioc_type }) {
  const validations = {
    ip: {
      tools: ['AbuseIPDB (abuseipdb.com)', 'VirusTotal (virustotal.com)', 'Shodan (shodan.io)', 'IPVoid', 'AlienVault OTX'],
      checks: [
        'Is this IP in known threat intel feeds?',
        'Is it a Tor exit node or VPN/proxy?',
        'What ports/services does Shodan show?',
        'Has it appeared in breach datasets?',
        'Is it in the same /24 as known malicious IPs?',
      ],
      response: [
        'Block at perimeter firewall (ingress and egress)',
        'Search SIEM for all connections to/from this IP (past 30 days)',
        'Check DNS logs for any internal hosts resolving to this IP',
        'Add to threat intel blocklist',
      ],
    },
    domain: {
      tools: ['VirusTotal', 'URLVoid', 'Cisco Talos Intelligence', 'WHOIS / DomainTools', 'AlienVault OTX', 'urlscan.io'],
      checks: [
        'When was the domain registered? (New domains = higher risk)',
        'Does the WHOIS show privacy-protected registration?',
        'Is it a lookalike of a legitimate domain? (typosquatting check)',
        'What IP does it resolve to — is that IP also malicious?',
        'Does it appear in phishing or malware databases?',
      ],
      response: [
        'Block at DNS resolver and web proxy',
        'Search proxy/firewall logs for all requests to this domain',
        'Check email gateway for emails linking to or from this domain',
        'Report to domain registrar if it\'s impersonating a legitimate brand',
      ],
    },
    hash: {
      tools: ['VirusTotal', 'MalwareBazaar (bazaar.abuse.ch)', 'Hybrid Analysis', 'Any.run sandbox', 'CAPE Sandbox'],
      checks: [
        'What AV/EDR vendors detect this hash?',
        'Is this a known malware family? (Get YARA rules if available)',
        'What is the file\'s behavior in a sandbox?',
        'Are there other samples with similar code (import hash, fuzzy hash)?',
        'Is this a known-good file that may have been tampered?',
      ],
      response: [
        'Quarantine all files with this hash across endpoints',
        'Run EDR hunt for this hash organization-wide',
        'Review process trees for this executable — what did it spawn?',
        'Check for persistence: startup folders, registry, scheduled tasks',
      ],
    },
    url: {
      tools: ['VirusTotal URL scanner', 'URLScan.io', 'Google Safe Browsing', 'PhishTank', 'CheckPhish.ai'],
      checks: [
        'Does the URL host a known phishing page or malware download?',
        'What does the page content look like? (urlscan.io screenshot)',
        'Is the SSL certificate legitimate or self-signed?',
        'Is the landing page impersonating a known brand?',
        'What is the hosting IP\'s reputation?',
      ],
      response: [
        'Block at web proxy and email gateway',
        'Search proxy logs for any user who visited this URL',
        'If visited: check that user\'s machine for download artifacts',
        'Submit to phishing takedown services if impersonating a brand',
      ],
    },
    email: {
      tools: ['MXToolbox Email Header Analyzer', 'Email Header Analyzer', 'PhishTool', 'VirusTotal'],
      checks: [
        'Does the from address match the Reply-To header?',
        'Did it pass SPF, DKIM, and DMARC checks?',
        'What is the sending mail server\'s reputation?',
        'Does the subject or body contain urgency language?',
        'Are any links or attachments malicious?',
      ],
      response: [
        'Quarantine email from all mailboxes (use email gateway admin tools)',
        'Reset credentials of any user who clicked links',
        'Block sending domain in email gateway',
        'Report to anti-phishing organizations (APWG, Google, Microsoft)',
      ],
    },
  }

  const v = validations[ioc_type]
  let response = `## IOC Analysis: ${ioc_type.toUpperCase()}\n`
  response += `**IOC:** \`${ioc_value}\`\n\n`

  try {
    const enrichment = await enrichIOC(ioc_value, ioc_type)
    if (enrichment.overallReputation !== 'unknown') {
      response += `### External Threat Intelligence\n`
      response += `**Overall Reputation:** ${enrichment.overallReputation.toUpperCase()}\n\n`
      enrichment.sources.forEach(source => {
        if (source.available && source.reputation) {
          response += `**${source.source}:**\n`
          if (source.source === 'AbuseIPDB' && source.abuseScore !== undefined) {
            response += `  - Abuse Score: ${source.abuseScore}/100\n`
            response += `  - Total Reports: ${source.totalReports}\n`
            response += `  - Country: ${source.country || 'Unknown'}\n`
          } else if (source.source === 'VirusTotal') {
            response += `  - Detection Ratio: ${source.detectionRatio}\n`
            response += `  - Malicious: ${source.malicious}, Suspicious: ${source.suspicious}\n`
          } else if (source.source === 'AlienVault OTX') {
            response += `  - Pulse Count: ${source.pulseCount}\n`
          }
          response += `\n`
        }
      })
    }
  } catch {
    response += `_Note: External threat intelligence unavailable_\n\n`
  }

  response += `### Recommended Validation Tools\n`
  v.tools.forEach(tool => { response += `- ${tool}\n` })

  response += `\n### What to Check\n`
  v.checks.forEach((check, i) => { response += `${i + 1}. ${check}\n` })

  response += `\n### Response Actions\n`
  v.response.forEach((action, i) => { response += `${i + 1}. ${action}\n` })

  const defanged = ioc_value
    .replace(/\./g, '[.]')
    .replace(/http/g, 'hxxp')
    .replace(/@/g, '[at]')
  response += `\n### Defanged IOC (safe to share)\n\`${defanged}\`\n`

  return response
}

// ─── Tool: check_cve ─────────────────────────────────────────────────────────

export async function checkCVE({ cve_id }) {
  const nvdData = await checkNVD(cve_id)

  let response = `## CVE Vulnerability Lookup\n\n`

  if (!nvdData.available) {
    response += `**CVE ID:** ${cve_id}\n`
    response += `**Status:** ${nvdData.message || nvdData.error}\n`
    return response
  }

  if (!nvdData.found) {
    response += `**CVE ID:** ${cve_id}\n`
    response += `**Status:** Not found in NVD database\n`
    return response
  }

  response += `**CVE ID:** ${nvdData.cveId}\n`
  response += `**CVSS Score:** ${nvdData.cvssScore || 'N/A'} (${nvdData.severity})\n`
  response += `**Published:** ${new Date(nvdData.published).toLocaleDateString()}\n\n`
  response += `### Description\n${nvdData.description}\n\n`

  if (nvdData.cvssVector) {
    response += `### CVSS Vector\n\`${nvdData.cvssVector}\`\n\n`
  }

  response += `### Weakness (CWE)\n${nvdData.weaknesses}\n\n`

  const score = nvdData.cvssScore || 0
  response += `### Severity Assessment\n`
  if (score >= 9.0) response += `🔴 CRITICAL — Immediate patching required.\n`
  else if (score >= 7.0) response += `🟠 HIGH — Patch as soon as possible.\n`
  else if (score >= 4.0) response += `🟡 MEDIUM — Schedule patching in maintenance window.\n`
  else if (score > 0) response += `🟢 LOW — Monitor and patch when convenient.\n`

  return response
}

// ─── Tool definitions for Groq API (OpenAI-compatible format) ────────────────

export const TOOL_DEFINITIONS = [
  {
    type: 'function',
    function: {
      name: 'triage_alert',
      description: 'Triage a security alert. Returns severity classification, MITRE ATT&CK mapping, immediate actions, and relevant playbook steps.',
      parameters: {
        type: 'object',
        properties: {
          alert_description: { type: 'string', description: 'The alert text or description from your SIEM, EDR, or security tool' },
          source_system: { type: 'string', description: 'e.g. Windows Defender, Splunk, CrowdStrike, firewall' },
          affected_asset: { type: 'string', description: 'Hostname, IP, or system name that triggered the alert' }
        },
        required: ['alert_description']
      }
    }
  },
  {
    type: 'function',
    function: {
      name: 'classify_log',
      description: 'Classify a raw log line or snippet. Detects attack patterns, assigns severity, explains what the log indicates.',
      parameters: {
        type: 'object',
        properties: {
          log_entry: { type: 'string', description: 'Raw log line or multi-line log block to analyze' },
          log_type: { type: 'string', description: 'Type: syslog, windows_event, web_server, firewall, auth, etc.' }
        },
        required: ['log_entry']
      }
    }
  },
  {
    type: 'function',
    function: {
      name: 'get_playbook',
      description: 'Get a full step-by-step incident response playbook for a specific attack type.',
      parameters: {
        type: 'object',
        properties: {
          incident_type: {
            type: 'string',
            enum: ['ransomware', 'phishing', 'bruteforce', 'dataexfil', 'lateral', 'ddos', 'insiderthreat', 'webdefacement'],
            description: 'Type of incident'
          },
          include_iocs: { type: 'boolean', description: 'Include IOC hunting tips' }
        },
        required: ['incident_type']
      }
    }
  },
  {
    type: 'function',
    function: {
      name: 'scan_ioc',
      description: 'Analyze an IOC (IP, domain, file hash, URL, email). Returns threat assessment and response actions.',
      parameters: {
        type: 'object',
        properties: {
          ioc_value: { type: 'string', description: 'The IOC to analyze: IP address, domain, SHA256 hash, URL, or email' },
          ioc_type: { type: 'string', enum: ['ip', 'domain', 'hash', 'url', 'email'], description: 'Type of IOC' }
        },
        required: ['ioc_value', 'ioc_type']
      }
    }
  },
  {
    type: 'function',
    function: {
      name: 'check_cve',
      description: 'Look up CVE details from NVD. Returns CVSS score, severity, description, and remediation guidance.',
      parameters: {
        type: 'object',
        properties: {
          cve_id: { type: 'string', description: 'CVE identifier e.g. CVE-2021-44228' }
        },
        required: ['cve_id']
      }
    }
  }
]

// ─── Tool dispatcher ─────────────────────────────────────────────────────────

export async function executeTool(name, input) {
  switch (name) {
    case 'triage_alert':  return triageAlert(input)
    case 'classify_log':  return classifyLog(input)
    case 'get_playbook':  return getPlaybook(input)
    case 'scan_ioc':      return scanIOC(input)
    case 'check_cve':     return checkCVE(input)
    default: return `Unknown tool: ${name}`
  }
}
