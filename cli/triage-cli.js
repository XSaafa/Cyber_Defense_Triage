#!/usr/bin/env node

import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const SEVERITY_MATRIX = JSON.parse(readFileSync(join(__dirname, "..", "knowledge-base", "severity-rules.json"), "utf-8"));
const PLAYBOOKS = JSON.parse(readFileSync(join(__dirname, "..", "knowledge-base", "playbooks.json"), "utf-8"));
const LOG_PATTERNS_RAW = JSON.parse(readFileSync(join(__dirname, "..", "knowledge-base", "log-patterns.json"), "utf-8"));
const MITRE_MAP = JSON.parse(readFileSync(join(__dirname, "..", "knowledge-base", "mitre-map.json"), "utf-8"));

const LOG_PATTERNS = {};
for (const [key, pattern] of Object.entries(LOG_PATTERNS_RAW)) {
  LOG_PATTERNS[key] = {
    ...pattern,
    pattern: new RegExp(pattern.pattern, pattern.patternFlags || 'i')
  };
}

const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  orange: '\x1b[38;5;208m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m'
};

function colorize(text, color) {
  return `${colors[color]}${text}${colors.reset}`;
}

function getSeverityColor(severity) {
  const colorMap = {
    critical: 'red',
    high: 'orange',
    medium: 'yellow',
    low: 'green'
  };
  return colorMap[severity] || 'reset';
}

function triageAlert(description) {
  const desc = description.toLowerCase();
  let severity = "low";
  let alertType = "Unknown";
  let mitreEntry = null;

  if (/ransomware|encrypting|ransom|cryptolocker/i.test(desc)) {
    severity = "critical"; alertType = "Ransomware";
    mitreEntry = MITRE_MAP["ransomware"];
  } else if (/exfil|data.*transfer|upload.*external|mega\.nz|pastebin/i.test(desc)) {
    severity = "critical"; alertType = "Data Exfiltration";
    mitreEntry = MITRE_MAP["data exfiltration"];
  } else if (/rce|remote.*execut|reverse.*shell|webshell|cmd\.exe.*from/i.test(desc)) {
    severity = "critical"; alertType = "Remote Code Execution";
  } else if (/lateral.*mov|pass.*hash|pass.*ticket|kerberoast|psexec/i.test(desc)) {
    severity = "high"; alertType = "Lateral Movement";
    mitreEntry = MITRE_MAP["lateral movement"];
  } else if (/privilege.*escal|privesc|sudo|runas.*admin/i.test(desc)) {
    severity = "high"; alertType = "Privilege Escalation";
    mitreEntry = MITRE_MAP["privilege escalation"];
  } else if (/phish|spearphish|malicious.*email|credential.*harvest/i.test(desc)) {
    severity = "high"; alertType = "Phishing";
    mitreEntry = MITRE_MAP["phishing"];
  } else if (/sql.*inject|union.*select|xp_cmdshell/i.test(desc)) {
    severity = "high"; alertType = "SQL Injection";
    mitreEntry = MITRE_MAP["sql injection"];
  } else if (/brute.*force|password.*spray|multiple.*failed.*login|login.*attempt/i.test(desc)) {
    severity = "medium"; alertType = "Brute Force";
    mitreEntry = MITRE_MAP["brute force"];
  } else if (/persist|scheduled.*task|registry.*run|cron.*added/i.test(desc)) {
    severity = "high"; alertType = "Persistence Mechanism";
    mitreEntry = MITRE_MAP["persistence"];
  }

  const sev = SEVERITY_MATRIX[severity];
  
  console.log('\n' + colorize('═══════════════════════════════════════════════════════════════════', getSeverityColor(severity)));
  console.log(colorize(`  ${sev.color} ${sev.label} — ${alertType}`, getSeverityColor(severity)));
  console.log(colorize('═══════════════════════════════════════════════════════════════════', getSeverityColor(severity)));
  
  console.log(`\n${colorize('Alert:', 'bright')} ${description}`);
  console.log(`${colorize('Severity:', 'bright')} ${sev.label}`);
  console.log(`${colorize('SLA:', 'bright')} ${sev.sla}`);
  console.log(`${colorize('Description:', 'bright')} ${sev.description}`);
  
  if (mitreEntry) {
    console.log(`\n${colorize('MITRE ATT&CK:', 'cyan')}`);
    console.log(`  Tactic: ${mitreEntry.tactic}`);
    console.log(`  Technique: ${mitreEntry.technique}`);
    console.log(`  Sub-technique: ${mitreEntry.subtechnique}`);
  }
  
  console.log(`\n${colorize('Immediate Actions:', 'bright')}`);
  if (severity === "critical") {
    console.log(colorize('  ⚠️  DO NOT DELAY - EXECUTE NOW:', 'red'));
    console.log('  1. Notify incident commander immediately');
    console.log('  2. ISOLATE affected system from network');
    console.log('  3. Preserve evidence (RAM dump, processes)');
    console.log('  4. Open incident ticket and start timeline');
  } else if (severity === "high") {
    console.log('  1. Verify alert is not false positive');
    console.log('  2. Identify all affected assets');
    console.log('  3. Notify team lead and begin containment');
    console.log('  4. Preserve logs before rotation');
  } else if (severity === "medium") {
    console.log('  1. Investigate alert context');
    console.log('  2. Correlate with other alerts');
    console.log('  3. Monitor for escalation');
  } else {
    console.log('  1. Log and monitor');
    console.log('  2. Review during business hours');
  }
  
  console.log('');
}

function classifyLog(logEntry) {
  const matches = [];
  
  for (const [key, pattern] of Object.entries(LOG_PATTERNS)) {
    if (pattern.pattern.test(logEntry)) {
      matches.push({ key, ...pattern });
    }
  }
  
  console.log('\n' + colorize('═══════════════════════════════════════════════════════════════════', 'cyan'));
  console.log(colorize('  LOG CLASSIFICATION RESULT', 'cyan'));
  console.log(colorize('═══════════════════════════════════════════════════════════════════', 'cyan'));
  
  console.log(`\n${colorize('Log Entry:', 'bright')}`);
  console.log(colorize(`  ${logEntry.slice(0, 200)}${logEntry.length > 200 ? '...' : ''}`, 'gray'));
  
  if (matches.length === 0) {
    console.log(`\n${colorize('Result:', 'green')} No known attack pattern detected`);
    console.log('Recommendation: Log for baseline, monitor for recurrence');
  } else {
    const topMatch = matches.reduce((a, b) => {
      const order = ["critical", "high", "medium", "low"];
      return order.indexOf(a.severity) <= order.indexOf(b.severity) ? a : b;
    });
    
    const sev = SEVERITY_MATRIX[topMatch.severity];
    const color = getSeverityColor(topMatch.severity);
    
    console.log(`\n${colorize('Detection:', color)} ${sev.color} ${sev.label} — ${topMatch.type}`);
    console.log(`${colorize('Description:', 'bright')} ${topMatch.description}`);
    console.log(`${colorize('Action:', 'bright')} ${topMatch.action}`);
    
    if (matches.length > 1) {
      console.log(`\n${colorize('Additional Patterns:', 'yellow')}`);
      matches.slice(1).forEach(m => {
        console.log(`  - ${m.type}: ${m.description}`);
      });
    }
  }
  
  console.log('');
}

function showPlaybook(type) {
  const playbook = PLAYBOOKS[type];
  
  if (!playbook) {
    console.log(colorize(`\n❌ No playbook found for: ${type}`, 'red'));
    console.log(colorize('Available playbooks:', 'cyan'));
    Object.keys(PLAYBOOKS).forEach(key => {
      console.log(`  - ${key}`);
    });
    return;
  }
  
  console.log('\n' + colorize('═══════════════════════════════════════════════════════════════════', 'cyan'));
  console.log(colorize(`  ${playbook.name.toUpperCase()}`, 'cyan'));
  console.log(colorize('═══════════════════════════════════════════════════════════════════', 'cyan'));
  
  console.log(`\n${colorize('Response Steps:', 'bright')}`);
  playbook.steps.forEach((step, i) => {
    const phase = step.split(":")[0];
    const detail = step.split(":").slice(1).join(":").trim();
    console.log(`\n${colorize(`Step ${i + 1} — ${phase}`, 'cyan')}`);
    console.log(`  ${detail}`);
  });
  
  if (playbook.iocs_to_look_for) {
    console.log(`\n${colorize('IOCs to Hunt For:', 'yellow')}`);
    playbook.iocs_to_look_for.forEach(ioc => {
      console.log(`  • ${ioc}`);
    });
  }
  
  console.log('');
}

function scanIoc(value, type) {
  const validations = {
    ip: {
      tools: ["AbuseIPDB", "VirusTotal", "Shodan", "IPVoid", "AlienVault OTX"],
      checks: [
        "Is this IP in known threat intel feeds?",
        "Is it a Tor exit node or VPN/proxy?",
        "What ports/services does Shodan show?",
        "Has it appeared in breach datasets?"
      ],
      response: [
        "Block at perimeter firewall",
        "Search SIEM for all connections to/from this IP",
        "Check DNS logs",
        "Add to threat intel blocklist"
      ]
    },
    domain: {
      tools: ["VirusTotal", "URLVoid", "WHOIS", "AlienVault OTX", "urlscan.io"],
      checks: [
        "When was the domain registered?",
        "Is WHOIS privacy-protected?",
        "Is it a lookalike domain?",
        "Does it appear in phishing databases?"
      ],
      response: [
        "Block at DNS resolver and web proxy",
        "Search proxy logs for requests",
        "Check email gateway",
        "Report to registrar if impersonating"
      ]
    },
    hash: {
      tools: ["VirusTotal", "MalwareBazaar", "Hybrid Analysis", "Any.run", "CAPE Sandbox"],
      checks: [
        "What AV vendors detect this?",
        "Is this a known malware family?",
        "What is the sandbox behavior?",
        "Are there similar samples?"
      ],
      response: [
        "Quarantine all files with this hash",
        "Run EDR hunt organization-wide",
        "Review process trees",
        "Check for persistence mechanisms"
      ]
    },
    url: {
      tools: ["VirusTotal", "URLScan.io", "Google Safe Browsing", "PhishTank"],
      checks: [
        "Does it host phishing/malware?",
        "What does the page look like?",
        "Is the SSL cert legitimate?",
        "Is it impersonating a brand?"
      ],
      response: [
        "Block at web proxy and email gateway",
        "Search proxy logs for visitors",
        "Check visitor machines for artifacts",
        "Submit to takedown services"
      ]
    },
    email: {
      tools: ["MXToolbox", "Email Header Analyzer", "PhishTool", "VirusTotal"],
      checks: [
        "Does from match Reply-To?",
        "Did it pass SPF/DKIM/DMARC?",
        "What is sender reputation?",
        "Are links/attachments malicious?"
      ],
      response: [
        "Quarantine from all mailboxes",
        "Reset credentials of clickers",
        "Block sending domain",
        "Report to anti-phishing orgs"
      ]
    }
  };
  
  const v = validations[type];
  if (!v) {
    console.log(colorize(`\n❌ Invalid IOC type: ${type}`, 'red'));
    console.log(colorize('Valid types: ip, domain, hash, url, email', 'cyan'));
    return;
  }
  
  const defanged = value
    .replace(/\./g, "[.]")
    .replace(/http/g, "hxxp")
    .replace(/@/g, "[@]");
  
  console.log('\n' + colorize('═══════════════════════════════════════════════════════════════════', 'cyan'));
  console.log(colorize(`  IOC ANALYSIS: ${type.toUpperCase()}`, 'cyan'));
  console.log(colorize('═══════════════════════════════════════════════════════════════════', 'cyan'));
  
  console.log(`\n${colorize('IOC:', 'bright')} ${value}`);
  console.log(`${colorize('Defanged:', 'yellow')} ${defanged}`);
  
  console.log(`\n${colorize('Validation Tools:', 'cyan')}`);
  v.tools.forEach(tool => console.log(`  • ${tool}`));
  
  console.log(`\n${colorize('What to Check:', 'cyan')}`);
  v.checks.forEach((check, i) => console.log(`  ${i + 1}. ${check}`));
  
  console.log(`\n${colorize('Response Actions:', 'cyan')}`);
  v.response.forEach((action, i) => console.log(`  ${i + 1}. ${action}`));
  
  console.log('');
}

function showHelp() {
  console.log(colorize('\n╔═══════════════════════════════════════════════════════════════════╗', 'cyan'));
  console.log(colorize('║         CYBER-DEFENSE TRIAGE CLI — First Responder Tool          ║', 'cyan'));
  console.log(colorize('╚═══════════════════════════════════════════════════════════════════╝', 'cyan'));
  
  console.log(`\n${colorize('Usage:', 'bright')}`);
  console.log('  node cli/triage-cli.js <command> [arguments]\n');
  
  console.log(colorize('Commands:', 'cyan'));
  console.log('  triage <description>        Triage a security alert');
  console.log('  log <log_entry>             Classify a log entry');
  console.log('  playbook <type>             Show incident response playbook');
  console.log('  ioc <value> <type>          Analyze an IOC\n');
  
  console.log(colorize('Examples:', 'yellow'));
  console.log('  node cli/triage-cli.js triage "ransomware encrypting files"');
  console.log('  node cli/triage-cli.js log "Failed password for root from 45.33.32.156"');
  console.log('  node cli/triage-cli.js playbook ransomware');
  console.log('  node cli/triage-cli.js ioc 185.220.101.47 ip\n');
  
  console.log(colorize('Available Playbooks:', 'cyan'));
  console.log('  ransomware, phishing, bruteforce, dataexfil, lateral,');
  console.log('  ddos, insiderthreat, webdefacement\n');
  
  console.log(colorize('IOC Types:', 'cyan'));
  console.log('  ip, domain, hash, url, email\n');
}

const args = process.argv.slice(2);

if (args.length === 0) {
  showHelp();
  process.exit(0);
}

const command = args[0];

switch (command) {
  case 'triage':
    if (args.length < 2) {
      console.log(colorize('❌ Missing alert description', 'red'));
      console.log('Usage: node cli/triage-cli.js triage "alert description"');
      process.exit(1);
    }
    triageAlert(args.slice(1).join(' '));
    break;
    
  case 'log':
    if (args.length < 2) {
      console.log(colorize('❌ Missing log entry', 'red'));
      console.log('Usage: node cli/triage-cli.js log "log entry"');
      process.exit(1);
    }
    classifyLog(args.slice(1).join(' '));
    break;
    
  case 'playbook':
    if (args.length < 2) {
      console.log(colorize('❌ Missing playbook type', 'red'));
      console.log('Usage: node cli/triage-cli.js playbook <type>');
      console.log('Available: ransomware, phishing, bruteforce, dataexfil, lateral, ddos, insiderthreat, webdefacement');
      process.exit(1);
    }
    showPlaybook(args[1]);
    break;
    
  case 'ioc':
    if (args.length < 3) {
      console.log(colorize('❌ Missing IOC value or type', 'red'));
      console.log('Usage: node cli/triage-cli.js ioc <value> <type>');
      console.log('Types: ip, domain, hash, url, email');
      process.exit(1);
    }
    scanIoc(args[1], args[2]);
    break;
    
  default:
    console.log(colorize(`❌ Unknown command: ${command}`, 'red'));
    showHelp();
    process.exit(1);
}
