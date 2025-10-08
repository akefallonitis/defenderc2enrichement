# Microsoft Defender for Endpoint - Device Compromise Investigation Playbook

## Overview
This playbook provides step-by-step manual investigation procedures for analysts investigating potential device compromises detected by Microsoft Defender for Endpoint (MDE).

## Prerequisites
- Access to Microsoft 365 Defender portal
- MDE license and device onboarding
- Appropriate permissions (Security Reader minimum)

---

## Investigation Steps

### 1. Initial Assessment
**Objective:** Quickly determine the severity and scope of the potential compromise.

#### Actions:
1. **Navigate to Device Details**
   - Open Microsoft 365 Defender portal
   - Go to Devices → Search for affected device
   - Review device overview page

2. **Check Device Risk Score**
   - Review current risk score (Low/Medium/High)
   - Check exposure level
   - Note risk score trend (increasing/decreasing)

3. **Review Device Compliance Status**
   - Verify device is compliant with organizational policies
   - Check for security configuration issues
   - Review missing security updates

4. **Validate Device Ownership and Criticality**
   - Confirm device owner/primary user
   - Determine device criticality (executive, server, workstation)
   - Check if device handles sensitive data

#### Decision Point:
- **High risk score + Critical device** = Proceed immediately to full investigation
- **Low risk score + Non-critical device** = Continue standard investigation flow
- **Device offline/not reporting** = Note in case file, attempt to locate device

---

### 2. Alert Analysis
**Objective:** Understand all security alerts associated with this device.

#### Actions:
1. **Review All Alerts (Last 30 Days)**
   - Navigate to Device → Alerts tab
   - Sort by severity and date
   - Document all High and Critical alerts

2. **Categorize Alerts by MITRE ATT&CK Techniques**
   - Identify primary tactics:
     - Initial Access
     - Execution
     - Persistence
     - Privilege Escalation
     - Defense Evasion
     - Credential Access
     - Discovery
     - Lateral Movement
     - Collection
     - Exfiltration
     - Command and Control
     - Impact

3. **Identify Alert Clustering Patterns**
   - Look for multiple alerts within short timeframes
   - Identify common indicators across alerts
   - Note if alerts follow typical attack chain patterns

4. **Check Alert Status**
   - Review which alerts are still active
   - Check if any alerts were auto-resolved
   - Identify alerts requiring analyst attention

#### Key Indicators:
- ✗ Multiple alerts across different MITRE techniques
- ✗ Alerts progressing through kill chain (Initial Access → Execution → C2)
- ✗ Alerts involving credential theft or privilege escalation
- ✓ Single isolated alert with no follow-up activity

---

### 3. Process Investigation
**Objective:** Analyze suspicious process execution and identify malicious behavior.

#### Actions:
1. **Analyze Suspicious Process Execution Timeline**
   - Navigate to Device → Timeline
   - Filter for Process events
   - Identify processes launched around alert timestamps
   - Note unusual process names or paths

2. **Check Process Tree and Parent-Child Relationships**
   - Select suspicious process → View process tree
   - Verify parent process legitimacy
   - Look for unusual parent-child relationships:
     - ✗ Office apps spawning cmd.exe/powershell.exe
     - ✗ Browser spawning suspicious executables
     - ✗ Services spawning user-mode applications

3. **Validate Process Signatures and Reputation**
   - Check process file signature
   - Review file prevalence (global/organizational)
   - Verify file path legitimacy
   - Check process command line arguments

4. **Investigate Process Behavior**
   - Network connections initiated
   - Files created/modified
   - Registry modifications
   - Scheduled tasks created
   - Services installed

#### Red Flags:
- ✗ Unsigned or suspicious signatures
- ✗ Very low prevalence (<100 globally)
- ✗ Execution from unusual paths (Temp, AppData, Downloads)
- ✗ Obfuscated or encoded command lines
- ✗ Living-off-the-land binaries (LOLBins) abuse

---

### 4. Network Analysis
**Objective:** Identify suspicious network communications and potential C2 connections.

#### Actions:
1. **Review Outbound Connections and Destinations**
   - Navigate to Device → Network connections
   - Filter by time period around alerts
   - Document all external IP addresses contacted
   - Note unusual ports (not 80, 443, 53, 22, 3389)

2. **Check for C2 Communication Patterns**
   - Look for:
     - Regular beaconing (connections at fixed intervals)
     - Connections to newly registered domains
     - Connections to infrastructure in unexpected countries
     - Use of uncommon protocols
     - High-volume data transfers

3. **Analyze DNS Queries and Responses**
   - Review DNS query log
   - Look for:
     - Domain generation algorithm (DGA) patterns
     - DNS tunneling indicators (unusual TXT queries)
     - Recently registered domains
     - Typosquatting domains

4. **Cross-reference with Threat Intelligence**
   - Check IPs/domains against:
     - Microsoft Threat Intelligence
     - Known C2 infrastructure lists
     - Organizational threat feeds

#### Investigation Queries:
```kusto
// Recent network connections from device
DeviceNetworkEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess"
| summarize ConnectionCount = count() by RemoteIP, RemotePort, RemoteUrl
| order by ConnectionCount desc

// DNS queries to suspicious domains
DeviceNetworkEvents
| where DeviceName == "<DEVICE_NAME>"
| where ActionType == "DnsQueryResponse"
| where Timestamp > ago(7d)
| where DomainName has_any ("bit.ly", "tinyurl", "t.co") or DomainName matches regex @"[a-z]{20,}"
| project Timestamp, DomainName, RemoteIP
```

---

### 5. File Analysis
**Objective:** Examine files created, modified, or executed during the incident.

#### Actions:
1. **Examine Recently Created/Modified Files**
   - Navigate to Device → Timeline
   - Filter for File events
   - Focus on:
     - Executable files (.exe, .dll, .sys)
     - Script files (.ps1, .vbs, .js, .bat)
     - Office documents with macros
     - Compressed archives

2. **Check File Reputation and Signatures**
   - For each suspicious file:
     - Calculate/retrieve file hash (SHA256)
     - Check MDE file page (Files → Search)
     - Review global prevalence
     - Verify digital signature
     - Check signing certificate validity

3. **Analyze File Prevalence Globally**
   - Files seen on <10 devices globally = High suspicion
   - Files seen only in your org = Medium suspicion
   - Files seen >1000 devices globally = Lower suspicion (but verify legitimacy)

4. **Submit Files for Deep Analysis** (if needed)
   - Use MDE's "Deep Analysis" feature
   - Submit to Microsoft for automated sandbox analysis
   - Review detonation results

#### File Investigation Queries:
```kusto
// Recently created executable files
DeviceFileEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where FileName endswith ".exe" or FileName endswith ".dll"
| project Timestamp, FileName, FolderPath, SHA256, InitiatingProcessFileName
| order by Timestamp desc

// Files with low prevalence
DeviceFileEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp > ago(7d)
| join kind=inner (
    DeviceFileCertificateInfo
    | where GlobalPrevalence < 10
) on SHA256
| project Timestamp, FileName, FolderPath, SHA256, GlobalPrevalence
```

---

### 6. Lateral Movement Assessment
**Objective:** Determine if the compromise has spread to other devices.

#### Actions:
1. **Check for Remote Logons FROM This Device**
   - Review authentication events
   - Look for:
     - Remote Desktop connections initiated
     - PowerShell remoting sessions
     - WMI connections to other hosts
     - SMB connections with administrative shares

2. **Review Network Shares Accessed**
   - Check file access events
   - Identify accessed network shares
   - Note if admin shares (C$, ADMIN$) were accessed

3. **Analyze Privilege Escalation Attempts**
   - Look for:
     - UAC bypass attempts
     - Token manipulation
     - Process injection
     - Credential dumping (LSASS access)
     - Pass-the-hash/ticket indicators

4. **Identify Compromised Credentials**
   - Check if any credentials were exposed
   - Review user accounts logged on during incident
   - Identify accounts that may need password reset

#### Lateral Movement Queries:
```kusto
// Outbound remote connections from device
DeviceNetworkEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp > ago(7d)
| where RemotePort in (3389, 5985, 5986, 22, 445)
| where InitiatingProcessFileName in~ ("mstsc.exe", "powershell.exe", "psexec.exe", "winrs.exe")
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessCommandLine

// Logon events for users on this device
DeviceLogonEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp > ago(7d)
| summarize LogonCount = count() by AccountName, LogonType
| order by LogonCount desc
```

---

### 7. Documentation & Response
**Objective:** Document findings and recommend appropriate response actions.

#### Actions:
1. **Document Findings and IOCs**
   - Create incident case file with:
     - Timeline of events
     - All identified IOCs (IPs, domains, file hashes, process names)
     - MITRE ATT&CK techniques observed
     - Affected user accounts
     - Potential data exposure

2. **Recommend Containment Actions**
   - Based on investigation, recommend:
     
     **High Severity (Confirmed compromise):**
     - [ ] Isolate device from network immediately
     - [ ] Block identified IOCs across organization
     - [ ] Reset credentials for affected accounts
     - [ ] Initiate full malware remediation
     
     **Medium Severity (Suspicious activity):**
     - [ ] Restrict device network access
     - [ ] Monitor device for additional activity
     - [ ] Run full antivirus scan
     - [ ] Review and strengthen endpoint controls
     
     **Low Severity (False positive/Resolved):**
     - [ ] Document investigation results
     - [ ] Update detection rules to reduce false positives
     - [ ] Close incident

3. **Create Timeline of Events**
   - Chronological sequence of attack
   - Initial compromise vector
   - Lateral movement path (if applicable)
   - Actions taken by attacker
   - Data accessed or exfiltrated

4. **Escalate if Needed**
   - Escalate to Tier 2/3 if:
     - Advanced persistent threat (APT) indicators
     - Widespread compromise suspected
     - Critical data systems affected
     - Unknown malware/techniques observed

---

## Investigation Checklist

Use this checklist to ensure all investigation steps are completed:

- [ ] Device risk score and exposure level reviewed
- [ ] Device compliance status validated
- [ ] All alerts in last 30 days reviewed and categorized
- [ ] Alert clustering and patterns identified
- [ ] Suspicious processes identified and analyzed
- [ ] Process tree and parent-child relationships examined
- [ ] Process signatures and reputations verified
- [ ] Network connections and destinations reviewed
- [ ] C2 communication patterns analyzed
- [ ] DNS queries examined for anomalies
- [ ] Recently created/modified files investigated
- [ ] File reputations and signatures checked
- [ ] File prevalence globally analyzed
- [ ] Remote logons from device reviewed
- [ ] Network shares accessed documented
- [ ] Privilege escalation attempts identified
- [ ] Findings and IOCs documented
- [ ] Containment actions recommended
- [ ] Timeline of events created
- [ ] Case escalated (if required)

---

## Common Attack Patterns

### Pattern 1: Phishing → Malware Execution
1. User receives phishing email with malicious attachment
2. User opens attachment (Office doc with macro)
3. Macro downloads and executes malware
4. Malware establishes persistence
5. C2 communication initiated

**Key Indicators:**
- Office process spawning PowerShell/cmd.exe
- Downloads from suspicious domains
- Files created in Temp/AppData
- Scheduled tasks or registry run keys created

### Pattern 2: Credential Theft → Lateral Movement
1. Attacker gains initial access (phishing, exploit)
2. Credential dumping from LSASS
3. Use of stolen credentials on other systems
4. Privilege escalation to Domain Admin
5. Widespread compromise

**Key Indicators:**
- LSASS process access
- Pass-the-hash authentication
- Multiple failed logon attempts
- Remote logons to multiple devices

### Pattern 3: Living-off-the-Land (LOLBin) Attack
1. Attacker uses legitimate Windows tools
2. PowerShell for reconnaissance and execution
3. WMI for persistence and lateral movement
4. BITSAdmin for data exfiltration
5. Minimal custom malware = harder detection

**Key Indicators:**
- Unusual PowerShell command lines (encoded, obfuscated)
- WMI events creating processes
- BITSAdmin transferring data
- Native Windows tools in unusual contexts

---

## Additional Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Microsoft 365 Defender Documentation](https://docs.microsoft.com/defender-365)
- [MDE Advanced Hunting Schema](https://docs.microsoft.com/defender-endpoint/advanced-hunting-schema-reference)
- [Threat Analytics](https://security.microsoft.com/threatanalytics3) in Microsoft 365 Defender

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2024 | Initial playbook creation |

---

*This playbook should be adapted to your organization's specific requirements, tools, and procedures.*
