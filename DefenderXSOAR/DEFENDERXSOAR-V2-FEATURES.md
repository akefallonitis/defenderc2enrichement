# DefenderXSOAR V2 - Enhanced Features Documentation

## Overview

DefenderXSOAR V2 represents a major enhancement to the original solution, incorporating advanced SOAR capabilities, official Microsoft entity schemas, cross-product correlation, and comprehensive enrichment modules.

---

## 🆕 New Features

### 1. Official Microsoft Entity Types

DefenderXSOAR V2 now supports **all official Microsoft Sentinel entity types** with proper schemas:

#### Enhanced Entity Support:
- ✅ **Account** - UPN, ObjectGUID, SID, AADUserId, NTDomain, DnsDomain
- ✅ **Host** - Hostname, NetBiosName, AzureID, OMSAgentID, OSVersion
- ✅ **Mailbox** - DisplayName, Alias, MailboxGuid, PrimarySmtpAddress
- ✅ **Registry** - RegistryKey, RegistryHive, RegistryValueName, RegistryValueData
- ✅ **DNS** - DomainName, DnsServerIP, QueryType, QueryResult
- ✅ **IP** - IPv4/IPv6 with geolocation data
- ✅ **File** - Enhanced with FileHash (SHA1/SHA256/MD5), FileName, FilePath
- ✅ **Process** - ProcessID, ProcessName, CommandLine, ParentProcess
- ✅ **URL** - Full URL string, Host portion, Domain
- ✅ **CloudApplication** - ApplicationID, ResourceID, AppDisplayName
- ✅ **User** - Extended with additional identity properties
- ✅ **Device** - Enhanced device information
- ✅ **MailMessage** - Complete email message metadata
- ✅ **AzureResource** - Azure resource identifiers and metadata

**Module:** `Modules/Common/EntityNormalizer.psm1`

---

### 2. Cross-Product Correlation Engine

Advanced correlation engine that detects multi-product attack scenarios:

#### Correlation Scenarios:
- **Email → Endpoint:** Phishing email leads to malware execution
- **Identity → Multiple Endpoints:** Compromised account lateral movement
- **Cloud → Identity:** Unusual cloud access patterns + risky sign-ins
- **Endpoint → Network:** Device compromise + C2 communications
- **Identity → Email → Cloud:** Full kill-chain correlation

#### Features:
- Time-based correlation (events within configurable time windows)
- Entity-based correlation (shared accounts, IPs, files)
- Behavioral correlation (deviation from baselines)
- IOC correlation (shared threat indicators)
- Risk scoring based on correlation patterns

**Module:** `Modules/Common/CrossCorrelationEngine.psm1`

**Configuration:**
```json
{
  "Correlation": {
    "Enabled": true,
    "TimeWindowMinutes": 60,
    "ScenarioWeights": {
      "EmailToEndpoint": 20,
      "IdentityToEndpoint": 25,
      "CloudToIdentity": 20,
      "EndpointToNetwork": 30,
      "FullKillChain": 50
    }
  }
}
```

---

### 3. Advanced Enrichment Modules

Four new enrichment modules provide comprehensive threat intelligence and context:

#### A. Threat Intelligence Enrichment
Integrates with multiple threat intelligence sources:
- Microsoft Threat Intelligence API
- VirusTotal (placeholder for integration)
- AlienVault OTX (placeholder for integration)
- Custom threat feeds

**Capabilities:**
- IP address reputation lookup
- File hash reputation checking
- URL/Domain reputation analysis
- Confidence scoring
- Multi-source aggregation

**Module:** `Modules/Enrichment/ThreatIntelEnrichment.psm1`

#### B. GeoLocation Enrichment
Provides geographic context for IP addresses:
- Country, city, region identification
- ISP and organization lookup
- Proxy/VPN/Tor detection
- Impossible travel detection
- High-risk country flagging

**Module:** `Modules/Enrichment/GeoLocationEnrichment.psm1`

#### C. Reputation Enrichment
Reputation scoring for various entity types:
- File reputation based on prevalence
- IP reputation from multiple sources
- Domain age and reputation
- Cloud app risk scoring
- Low reputation detection

**Module:** `Modules/Enrichment/ReputationEnrichment.psm1`

#### D. Behavior Analytics
Behavioral analysis and anomaly detection:
- User behavior patterns
- Account authentication patterns
- Host activity patterns
- Device configuration changes
- Baseline deviation detection

**Module:** `Modules/Enrichment/BehaviorAnalytics.psm1`

**Configuration:**
```json
{
  "Enrichment": {
    "ThreatIntelligence": {
      "Enabled": true,
      "Sources": ["MicrosoftThreatIntelligence", "VirusTotal", "AlienVaultOTX"]
    },
    "GeoLocation": {
      "Enabled": true,
      "HighRiskCountries": ["NK", "IR", "SY", "CU", "SD"],
      "DetectImpossibleTravel": true
    },
    "Reputation": {
      "Enabled": true,
      "LowReputationThreshold": 30
    },
    "BehaviorAnalytics": {
      "Enabled": true,
      "BaselinePeriodDays": 30,
      "AnomalyThreshold": 2.0
    }
  }
}
```

---

### 4. Manual Investigation Playbooks

Step-by-step manual investigation procedures for security analysts:

#### Available Playbooks:
- **MDE Investigation Playbook** - Complete device compromise investigation guide
  - Initial assessment steps
  - Alert analysis procedures
  - Process investigation workflow
  - Network analysis guidelines
  - File analysis procedures
  - Lateral movement assessment
  - Documentation and response templates

**Location:** `Documentation/AnalystPlaybooks/`

#### Key Features:
- ✅ Actionable step-by-step procedures
- ✅ Decision points and branching logic
- ✅ Investigation queries included
- ✅ Common attack pattern descriptions
- ✅ Investigation checklists
- ✅ Best practices and tips

**Future Playbooks:**
- EntraID Investigation Playbook
- MDO Investigation Playbook
- MCAS Investigation Playbook
- MDI Investigation Playbook
- MDC Investigation Playbook

---

### 5. Automatic Trigger Mechanisms

Multiple activation scenarios for automated and manual analysis:

#### A. Sentinel Webhook Trigger
Azure Function webhook for automatic incident enrichment:
- Triggers on Sentinel incident creation
- Severity-based filtering
- Automatic entity extraction
- Real-time enrichment

**Script:** `Triggers/SentinelWebhook.ps1`

**Deployment:**
```powershell
# Deploy as Azure Function
# Configure Sentinel automation rule to call webhook
```

#### B. Defender Polling Trigger
Continuous monitoring of Microsoft 365 Defender alerts:
- Polls every 5 minutes (configurable)
- High-priority alert detection
- Automatic enrichment
- Alert deduplication
- Multi-tenant support

**Script:** `Triggers/DefenderPolling.ps1`

**Usage:**
```powershell
# Run continuously
.\Triggers\DefenderPolling.ps1 -ConfigPath "..\Config\DefenderXSOAR.json" -PollingIntervalMinutes 5

# Run once
.\Triggers\DefenderPolling.ps1 -ConfigPath "..\Config\DefenderXSOAR.json" -RunOnce
```

#### C. Manual Analysis Function
Flexible function for on-demand analysis:

**Script:** `Functions/Invoke-DefenderXSOARAnalysis.ps1`

**Usage Examples:**
```powershell
# Analyze a single IP address
Invoke-DefenderXSOARAnalysis -EntityType 'IP' -EntityValue '1.2.3.4' -TenantId $tenantId

# Analyze a user
Invoke-DefenderXSOARAnalysis -EntityType 'User' -EntityValue 'user@domain.com' -TenantId $tenantId

# Analyze multiple entities
$entities = @(
    @{ Type = 'User'; UserPrincipalName = 'user@domain.com' },
    @{ Type = 'Device'; HostName = 'DESKTOP-001' },
    @{ Type = 'IP'; Address = '192.168.1.100' }
)
Invoke-DefenderXSOARAnalysis -Entities $entities -TenantId $tenantId

# Analyze with specific products only
Invoke-DefenderXSOARAnalysis -EntityType 'User' -EntityValue 'user@domain.com' -TenantId $tenantId -Products @('EntraID', 'MDO')

# Output formats
Invoke-DefenderXSOARAnalysis ... -OutputFormat JSON
Invoke-DefenderXSOARAnalysis ... -OutputFormat Summary    # Default
Invoke-DefenderXSOARAnalysis ... -OutputFormat Full
```

**Configuration:**
```json
{
  "Triggers": {
    "SentinelWebhook": {
      "Enabled": true,
      "MinimumSeverity": "Medium"
    },
    "DefenderPolling": {
      "Enabled": false,
      "IntervalMinutes": 5,
      "MinimumSeverity": "Medium"
    },
    "ScheduledAnalysis": {
      "Enabled": false,
      "CronSchedule": "0 */6 * * *"
    }
  }
}
```

---

### 6. Enhanced Data Output

Multiple custom Log Analytics tables for comprehensive data management:

#### Custom Tables:

**A. DefenderXSOAR_CL** (Main enrichment data)
- TimeGenerated
- IncidentId
- Product
- RiskScore
- Severity
- EntitiesCount
- RelatedAlertsCount
- ThreatIntelCount
- WatchlistMatches
- UEBAInsights
- Recommendations
- EnrichmentData (JSON)

**B. DefenderXSOAR_Entities_CL** (Entity details)
- TimeGenerated
- IncidentId
- EntityType
- EntityValue (JSON)
- Source
- CorrelationId
- RawData (JSON)

**C. DefenderXSOAR_Correlations_CL** (Cross-product correlations)
- TimeGenerated
- IncidentId
- CorrelationType
- Description
- RiskScore
- Severity
- Details (JSON)

**D. DefenderXSOAR_Decisions_CL** (Incident decisions)
- TimeGenerated
- IncidentId
- Action
- Priority
- Confidence
- Reasoning
- AutomatedAction
- DecisionFactors (JSON)

**E. DefenderXSOAR_Playbooks_CL** (Playbook results)
- TimeGenerated
- IncidentId
- Product
- PlaybookName
- ExecutionStatus
- ResultCount
- QueryExecuted
- Results (JSON)

**Module:** `Modules/Common/DataTableManager.psm1`

**Benefits:**
- ✅ Granular data for workbooks
- ✅ Advanced KQL queries
- ✅ Historical analysis
- ✅ Trend identification
- ✅ Performance metrics

---

## 🚀 Getting Started with V2 Features

### Prerequisites
- DefenderXSOAR base installation completed
- PowerShell 7.0 or later
- Azure permissions for custom tables
- Microsoft Defender product licenses

### Configuration

1. **Update Configuration File:**
```powershell
# Edit Config/DefenderXSOAR.json
# Enable new features:
- Enrichment modules
- Correlation engine
- Trigger mechanisms
```

2. **Deploy Custom Tables:**
```powershell
# Custom tables will be created automatically on first use
# Or pre-create using Azure CLI/PowerShell
```

3. **Configure Triggers:**
```powershell
# For Sentinel Webhook:
Deploy-DefenderXSOAR.ps1 -IncludeWebhook

# For Defender Polling:
# Run DefenderPolling.ps1 as scheduled task or service
```

### Usage Examples

#### Example 1: Full Enrichment with All Features
```powershell
.\Functions\Start-DefenderXSOAROrchestration.ps1 `
    -ConfigPath ".\Config\DefenderXSOAR.json" `
    -IncidentId "12345" `
    -IncidentArmId "/subscriptions/.../incidents/12345" `
    -Entities $entities `
    -TenantId "tenant-guid" `
    -Products @('MDE', 'MDC', 'MCAS', 'MDI', 'MDO', 'EntraID')
```

This will:
- Enrich with all 6 products
- Run threat intelligence lookups
- Perform geolocation analysis
- Check reputation scores
- Analyze behavior patterns
- Execute cross-product correlation
- Send data to 5 custom tables
- Add incident comments

#### Example 2: Quick IP Investigation
```powershell
.\Functions\Invoke-DefenderXSOARAnalysis.ps1 `
    -EntityType 'IP' `
    -EntityValue '203.0.113.42' `
    -TenantId $tenantId `
    -Products @('MDE', 'MDC') `
    -OutputFormat Summary
```

#### Example 3: Continuous Monitoring
```powershell
# Start Defender polling service
.\Triggers\DefenderPolling.ps1 `
    -ConfigPath ".\Config\DefenderXSOAR.json" `
    -PollingIntervalMinutes 5 `
    -MinimumSeverity High
```

---

## 📊 Workbook Queries

### Query 1: High-Risk Correlations
```kusto
DefenderXSOAR_Correlations_CL
| where TimeGenerated > ago(7d)
| where RiskScore > 70
| summarize Count = count() by CorrelationType, Severity
| order by Count desc
```

### Query 2: Entity Risk Timeline
```kusto
DefenderXSOAR_Entities_CL
| where TimeGenerated > ago(30d)
| extend EntityDetails = parse_json(EntityValue)
| extend RiskScore = toint(EntityDetails.RiskScore)
| summarize AvgRisk = avg(RiskScore) by bin(TimeGenerated, 1d), EntityType
| render timechart
```

### Query 3: Threat Intelligence Matches
```kusto
DefenderXSOAR_CL
| where TimeGenerated > ago(7d)
| where ThreatIntelCount > 0
| project TimeGenerated, IncidentId, ThreatIntelCount, Severity, RiskScore
| order by RiskScore desc
```

### Query 4: Decision Analytics
```kusto
DefenderXSOAR_Decisions_CL
| where TimeGenerated > ago(7d)
| summarize Count = count() by Action, Priority
| render columnchart
```

---

## 🔧 Advanced Configuration

### Enrichment Tuning
```json
{
  "Enrichment": {
    "ThreatIntelligence": {
      "Enabled": true,
      "CacheDuration": 3600,
      "MaxConcurrentLookups": 10
    },
    "GeoLocation": {
      "Enabled": true,
      "CacheDuration": 7200,
      "HighRiskCountries": ["NK", "IR", "SY", "CU", "SD"],
      "DetectImpossibleTravel": true,
      "ImpossibleTravelThreshold": {
        "DistanceKm": 1000,
        "TimeHours": 2
      }
    }
  }
}
```

### Correlation Tuning
```json
{
  "Correlation": {
    "Enabled": true,
    "TimeWindowMinutes": 60,
    "MaxEventsPerCorrelation": 100,
    "ScenarioWeights": {
      "EmailToEndpoint": 20,
      "IdentityToEndpoint": 25,
      "CloudToIdentity": 20,
      "EndpointToNetwork": 30,
      "FullKillChain": 50
    }
  }
}
```

---

## 🎓 Training Materials

### For Security Analysts
- Review manual investigation playbooks in `Documentation/AnalystPlaybooks/`
- Practice with `Invoke-DefenderXSOARAnalysis.ps1` on test incidents
- Understand correlation scenarios and their implications

### For Security Engineers
- Study enrichment module architecture
- Customize correlation weights for your environment
- Integrate additional threat intelligence sources
- Develop custom playbooks

### For Administrators
- Deploy and configure trigger mechanisms
- Set up custom Log Analytics tables
- Configure workbooks for reporting
- Manage multi-tenant configurations

---

## 📈 Performance Considerations

### Optimization Tips:
1. **Enable caching** for threat intelligence lookups
2. **Adjust correlation time windows** based on your needs
3. **Configure polling intervals** appropriately
4. **Use severity filtering** to reduce noise
5. **Monitor Log Analytics ingestion** costs

### Resource Requirements:
- **Memory:** 2-4 GB for typical workloads
- **CPU:** 2+ cores recommended for parallel enrichment
- **Network:** Outbound HTTPS to Microsoft APIs
- **Storage:** Minimal (logs only)

---

## 🐛 Troubleshooting

### Common Issues:

**Issue:** Enrichment modules not loading
```powershell
# Solution: Verify module paths
Import-Module .\Modules\Enrichment\ThreatIntelEnrichment.psm1 -Verbose
```

**Issue:** Correlation engine finding no correlations
```powershell
# Solution: Check time window configuration
# Increase TimeWindowMinutes in config
```

**Issue:** Custom tables not appearing in Log Analytics
```powershell
# Solution: Wait 5-10 minutes for first ingestion
# Verify WorkspaceId and SharedKey are correct
```

---

## 🔄 Migration from V1

### Breaking Changes:
- None - V2 is fully backward compatible

### Recommended Steps:
1. Update configuration file with new sections
2. Test enrichment modules individually
3. Enable correlation engine
4. Configure triggers as needed
5. Deploy custom tables
6. Update workbooks to use new tables

---

## 📝 License

MIT License - See LICENSE file for details

---

## 👥 Contributors

- **akefallonitis** - Original author
- DefenderXSOAR Community

---

## 📞 Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Review documentation in `Documentation/` directory
- Check IMPLEMENTATION-SUMMARY.md for architecture details

---

*DefenderXSOAR V2 - Enterprise-grade Security Orchestration, Automation & Response*
