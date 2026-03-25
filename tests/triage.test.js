import { describe, it, expect } from 'vitest'
import { readFileSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

const MITRE_MAP = JSON.parse(readFileSync(join(__dirname, '..', 'knowledge-base', 'mitre-map.json'), 'utf-8'))

function triageAlert(alertDescription) {
  const desc = alertDescription.toLowerCase()
  let severity = "low"
  let alertType = "Unknown"
  let mitreEntry = null

  if (/ransomware|encrypting|ransom|cryptolocker/i.test(desc)) {
    severity = "critical"
    alertType = "Ransomware"
    mitreEntry = MITRE_MAP["ransomware"]
  } else if (/exfil|data.*transfer|upload.*external|mega\.nz|pastebin/i.test(desc)) {
    severity = "critical"
    alertType = "Data Exfiltration"
    mitreEntry = MITRE_MAP["data exfiltration"]
  } else if (/rce|remote.*execut|reverse.*shell|webshell|cmd\.exe.*from/i.test(desc)) {
    severity = "critical"
    alertType = "Remote Code Execution"
  } else if (/lateral.*mov|pass.*hash|pass.*ticket|kerberoast|psexec/i.test(desc)) {
    severity = "high"
    alertType = "Lateral Movement"
    mitreEntry = MITRE_MAP["lateral movement"]
  } else if (/privilege.*escal|privesc|sudo|runas.*admin/i.test(desc)) {
    severity = "high"
    alertType = "Privilege Escalation"
    mitreEntry = MITRE_MAP["privilege escalation"]
  } else if (/phish|spearphish|malicious.*email|credential.*harvest/i.test(desc)) {
    severity = "high"
    alertType = "Phishing"
    mitreEntry = MITRE_MAP["phishing"]
  } else if (/sql.*inject|union.*select|xp_cmdshell/i.test(desc)) {
    severity = "high"
    alertType = "SQL Injection"
    mitreEntry = MITRE_MAP["sql injection"]
  } else if (/brute.*force|password.*spray|multiple.*failed.*login|login.*attempt/i.test(desc)) {
    severity = "medium"
    alertType = "Brute Force"
    mitreEntry = MITRE_MAP["brute force"]
  } else if (/persist|scheduled.*task|registry.*run|cron.*added/i.test(desc)) {
    severity = "high"
    alertType = "Persistence Mechanism"
    mitreEntry = MITRE_MAP["persistence"]
  }

  return { severity, alertType, mitreEntry }
}

describe('Triage Alert Tests', () => {
  it('should classify ransomware as critical', () => {
    const result = triageAlert('ransomware encrypting files on DESKTOP-01')
    expect(result.severity).toBe('critical')
    expect(result.alertType).toBe('Ransomware')
    expect(result.mitreEntry).toBeDefined()
    expect(result.mitreEntry.technique).toBe('T1486')
  })

  it('should classify brute force as medium', () => {
    const result = triageAlert('multiple failed login attempts detected')
    expect(result.severity).toBe('medium')
    expect(result.alertType).toBe('Brute Force')
    expect(result.mitreEntry).toBeDefined()
    expect(result.mitreEntry.tactic).toBe('Credential Access')
  })

  it('should classify SQL injection as high', () => {
    const result = triageAlert('SQL injection attempt with union select detected')
    expect(result.severity).toBe('high')
    expect(result.alertType).toBe('SQL Injection')
    expect(result.mitreEntry).toBeDefined()
  })

  it('should classify unknown alerts as low', () => {
    const result = triageAlert('some random alert text that matches nothing')
    expect(result.severity).toBe('low')
    expect(result.alertType).toBe('Unknown')
  })

  it('should classify lateral movement as high', () => {
    const result = triageAlert('lateral movement detected via PsExec')
    expect(result.severity).toBe('high')
    expect(result.alertType).toBe('Lateral Movement')
    expect(result.mitreEntry).toBeDefined()
    expect(result.mitreEntry.technique).toBe('T1021')
  })

  it('should handle case-insensitive matching', () => {
    const result1 = triageAlert('RANSOMWARE DETECTED')
    const result2 = triageAlert('ransomware detected')
    expect(result1.severity).toBe(result2.severity)
    expect(result1.alertType).toBe(result2.alertType)
  })

  it('should classify data exfiltration as critical', () => {
    const result = triageAlert('data exfiltration to mega.nz detected')
    expect(result.severity).toBe('critical')
    expect(result.alertType).toBe('Data Exfiltration')
  })

  it('should classify privilege escalation as high', () => {
    const result = triageAlert('privilege escalation attempt using sudo')
    expect(result.severity).toBe('high')
    expect(result.alertType).toBe('Privilege Escalation')
  })
})
