import severityRules from '../../../knowledge-base/severity-rules.json';
import playbooks from '../../../knowledge-base/playbooks.json';
import logPatterns from '../../../knowledge-base/log-patterns.json';
import mitreMap from '../../../knowledge-base/mitre-map.json';

export function triageAlert(alertDescription, sourceSystem = null, affectedAsset = null) {
  const desc = alertDescription.toLowerCase();

  let severity = "low";
  let alertType = "Unknown";
  let mitreEntry = null;

  if (/ransomware|encrypting|ransom|cryptolocker/i.test(desc)) {
    severity = "critical";
    alertType = "Ransomware";
    mitreEntry = mitreMap["ransomware"];
  } else if (/exfil|data.*transfer|upload.*external|mega\.nz|pastebin/i.test(desc)) {
    severity = "critical";
    alertType = "Data Exfiltration";
    mitreEntry = mitreMap["data exfiltration"];
  } else if (/rce|remote.*execut|reverse.*shell|webshell|cmd\.exe.*from/i.test(desc)) {
    severity = "critical";
    alertType = "Remote Code Execution";
  } else if (/lateral.*mov|pass.*hash|pass.*ticket|kerberoast|psexec/i.test(desc)) {
    severity = "high";
    alertType = "Lateral Movement";
    mitreEntry = mitreMap["lateral movement"];
  } else if (/privilege.*escal|privesc|sudo|runas.*admin/i.test(desc)) {
    severity = "high";
    alertType = "Privilege Escalation";
    mitreEntry = mitreMap["privilege escalation"];
  } else if (/phish|spearphish|malicious.*email|credential.*harvest/i.test(desc)) {
    severity = "high";
    alertType = "Phishing";
    mitreEntry = mitreMap["phishing"];
  } else if (/sql.*inject|union.*select|xp_cmdshell/i.test(desc)) {
    severity = "high";
    alertType = "SQL Injection";
    mitreEntry = mitreMap["sql injection"];
  } else if (/brute.*force|password.*spray|multiple.*failed.*login|login.*attempt/i.test(desc)) {
    severity = "medium";
    alertType = "Brute Force";
    mitreEntry = mitreMap["brute force"];
  } else if (/persist|scheduled.*task|registry.*run|cron.*added/i.test(desc)) {
    severity = "high";
    alertType = "Persistence Mechanism";
    mitreEntry = mitreMap["persistence"];
  } else if (/scan|port.*scan|nmap|discovery/i.test(desc)) {
    severity = "low";
    alertType = "Reconnaissance / Scanning";
  } else if (/anomal|unusual|suspicious/i.test(desc)) {
    severity = "medium";
    alertType = "Suspicious Activity";
  }

  const sev = severityRules[severity];
  const playbookKey = alertType.toLowerCase().replace(/\s+/g, "");
  const playbook = playbooks[playbookKey] || playbooks[alertType === "Brute Force" ? "bruteforce" : "phishing"];

  return {
    severity,
    severityInfo: sev,
    alertType,
    mitreEntry,
    playbook,
    sourceSystem,
    affectedAsset
  };
}

export function classifyLog(logEntry, logType = null) {
  const matches = [];

  for (const [key, pattern] of Object.entries(logPatterns)) {
    const regex = new RegExp(pattern.pattern, pattern.patternFlags || 'i');
    if (regex.test(logEntry)) {
      matches.push({ key, ...pattern });
    }
  }

  const hasIp = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(logEntry);
  const hasError = /error|fail|denied|blocked|reject/i.test(logEntry);
  const hasSuccess = /accept|success|granted|authenticated/i.test(logEntry);

  let topMatch = null;
  if (matches.length > 0) {
    topMatch = matches.reduce((a, b) => {
      const order = ["critical", "high", "medium", "low"];
      return order.indexOf(a.severity) <= order.indexOf(b.severity) ? a : b;
    });
  }

  return {
    matches,
    topMatch,
    logType,
    hasIp,
    hasError,
    hasSuccess,
    severityInfo: topMatch ? severityRules[topMatch.severity] : null
  };
}

export function getPlaybook(incidentType, includeIocs = true) {
  const playbook = playbooks[incidentType];
  if (!playbook) {
    return null;
  }

  return {
    ...playbook,
    includeIocs
  };
}

export function scanIoc(iocValue, iocType) {
  const validations = {
    ip: {
      tools: ["AbuseIPDB (abuseipdb.com)", "VirusTotal (virustotal.com)", "Shodan (shodan.io)", "IPVoid", "AlienVault OTX"],
      checks: [
        "Is this IP in known threat intel feeds?",
        "Is it a Tor exit node or VPN/proxy?",
        "What ports/services does Shodan show?",
        "Has it appeared in breach datasets?",
        "Is it in the same /24 as known malicious IPs?"
      ],
      response: [
        "Block at perimeter firewall (ingress and egress)",
        "Search SIEM for all connections to/from this IP (past 30 days)",
        "Check DNS logs for any internal hosts resolving to this IP",
        "Add to threat intel blocklist"
      ]
    },
    domain: {
      tools: ["VirusTotal", "URLVoid", "Cisco Talos Intelligence", "WHOIS / DomainTools", "AlienVault OTX", "urlscan.io"],
      checks: [
        "When was the domain registered? (New domains = higher risk)",
        "Does the WHOIS show privacy-protected registration?",
        "Is it a lookalike of a legitimate domain? (typosquatting check)",
        "What IP does it resolve to — is that IP also malicious?",
        "Does it appear in phishing or malware databases?"
      ],
      response: [
        "Block at DNS resolver and web proxy",
        "Search proxy/firewall logs for all requests to this domain",
        "Check email gateway for emails linking to or from this domain",
        "Report to domain registrar if it's impersonating a legitimate brand"
      ]
    },
    hash: {
      tools: ["VirusTotal", "MalwareBazaar (bazaar.abuse.ch)", "Hybrid Analysis", "Any.run sandbox", "CAPE Sandbox"],
      checks: [
        "What AV/EDR vendors detect this hash?",
        "Is this a known malware family? (Get YARA rules if available)",
        "What is the file's behavior in a sandbox?",
        "Are there other samples with similar code (import hash, fuzzy hash)?",
        "Is this a known-good file that may have been tampered?"
      ],
      response: [
        "Quarantine all files with this hash across endpoints",
        "Run EDR hunt for this hash organization-wide",
        "Review process trees for this executable — what did it spawn?",
        "Check for persistence: startup folders, registry, scheduled tasks"
      ]
    },
    url: {
      tools: ["VirusTotal URL scanner", "URLScan.io", "Google Safe Browsing", "PhishTank", "CheckPhish.ai"],
      checks: [
        "Does the URL host a known phishing page or malware download?",
        "What does the page content look like? (urlscan.io screenshot)",
        "Is the SSL certificate legitimate or self-signed?",
        "Is the landing page impersonating a known brand?",
        "What is the hosting IP's reputation?"
      ],
      response: [
        "Block at web proxy and email gateway",
        "Search proxy logs for any user who visited this URL",
        "If visited: check that user's machine for download artifacts",
        "Submit to phishing takedown services if impersonating a brand"
      ]
    },
    email: {
      tools: ["MXToolbox Email Header Analyzer", "Email Header Analyzer (mha.azurewebsites.net)", "PhishTool", "VirusTotal"],
      checks: [
        "Does the from address match the Reply-To header?",
        "Did it pass SPF, DKIM, and DMARC checks?",
        "What is the sending mail server's reputation?",
        "Does the subject or body contain urgency language?",
        "Are any links or attachments malicious?"
      ],
      response: [
        "Quarantine email from all mailboxes (use email gateway admin tools)",
        "Reset credentials of any user who clicked links",
        "Block sending domain in email gateway",
        "Report to anti-phishing organizations (APWG, Google, Microsoft)"
      ]
    }
  };

  const v = validations[iocType];
  if (!v) {
    return null;
  }

  const defanged = iocValue
    .replace(/\./g, "[.]")
    .replace(/http/g, "hxxp")
    .replace(/@/g, "[@]");

  return {
    iocValue,
    iocType,
    tools: v.tools,
    checks: v.checks,
    response: v.response,
    defanged
  };
}

export { severityRules, playbooks, logPatterns, mitreMap };
