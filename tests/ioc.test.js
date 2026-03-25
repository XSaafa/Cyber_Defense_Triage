import { describe, it, expect } from 'vitest'

function scanIoc(iocValue, iocType) {
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
  }

  const v = validations[iocType]
  if (!v) return null

  const defanged = iocValue
    .replace(/\./g, "[.]")
    .replace(/http/g, "hxxp")
    .replace(/@/g, "[@]")

  return {
    iocValue,
    iocType,
    tools: v.tools,
    checks: v.checks,
    response: v.response,
    defanged
  }
}

describe('IOC Scanner Tests', () => {
  it('should return correct tools list for IP', () => {
    const result = scanIoc('185.220.101.47', 'ip')
    expect(result).toBeDefined()
    expect(result.tools).toContain('AbuseIPDB')
    expect(result.tools).toContain('VirusTotal')
    expect(result.tools.length).toBeGreaterThan(3)
  })

  it('should return WHOIS check for domain', () => {
    const result = scanIoc('malicious-site.com', 'domain')
    expect(result).toBeDefined()
    expect(result.tools).toContain('WHOIS')
    expect(result.checks.some(c => c.includes('domain registered'))).toBe(true)
  })

  it('should return sandbox tools for hash', () => {
    const result = scanIoc('a1b2c3d4e5f6', 'hash')
    expect(result).toBeDefined()
    expect(result.tools).toContain('Hybrid Analysis')
    expect(result.tools).toContain('Any.run')
    expect(result.response.some(r => r.includes('Quarantine'))).toBe(true)
  })

  it('should defang IOC correctly', () => {
    const result1 = scanIoc('192.168.1.1', 'ip')
    expect(result1.defanged).toBe('192[.]168[.]1[.]1')

    const result2 = scanIoc('http://evil.com', 'url')
    expect(result2.defanged).toBe('hxxp://evil[.]com')

    const result3 = scanIoc('attacker@evil.com', 'email')
    expect(result3.defanged).toBe('attacker[@]evil[.]com')
  })

  it('should return null for invalid IOC type', () => {
    const result = scanIoc('test', 'invalid_type')
    expect(result).toBeNull()
  })

  it('should include response actions for all IOC types', () => {
    const types = ['ip', 'domain', 'hash', 'url', 'email']
    
    types.forEach(type => {
      const result = scanIoc('test-value', type)
      expect(result.response).toBeDefined()
      expect(result.response.length).toBeGreaterThan(0)
    })
  })

  it('should include validation checks for all IOC types', () => {
    const types = ['ip', 'domain', 'hash', 'url', 'email']
    
    types.forEach(type => {
      const result = scanIoc('test-value', type)
      expect(result.checks).toBeDefined()
      expect(result.checks.length).toBeGreaterThan(0)
    })
  })

  it('should preserve original IOC value', () => {
    const originalValue = '192.168.1.100'
    const result = scanIoc(originalValue, 'ip')
    expect(result.iocValue).toBe(originalValue)
  })
})
