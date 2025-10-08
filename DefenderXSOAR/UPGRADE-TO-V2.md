# Upgrading to DefenderXSOAR V2

## Overview

DefenderXSOAR V2 introduces significant enhancements while maintaining full backward compatibility with V1. This guide will help you upgrade and take advantage of the new features.

---

## ✨ What's New in V2

### Major Enhancements

1. **Official Microsoft Entity Support** (13 entity types)
   - Account, Host, Mailbox, Registry, DNS entities added
   - Full compliance with Microsoft Sentinel entity schemas

2. **Cross-Product Correlation Engine**
   - Detects multi-stage attacks across products
   - 5 correlation scenarios (Email→Endpoint, Identity→Endpoint, etc.)
   - Automatic risk scoring based on correlations

3. **Advanced Enrichment Modules** (4 new modules)
   - Threat Intelligence Enrichment
   - GeoLocation Enrichment with impossible travel detection
   - Reputation Enrichment
   - Behavior Analytics

4. **Manual Investigation Playbooks**
   - Step-by-step analyst procedures
   - Complete investigation workflows
   - Decision trees and checklists

5. **Automatic Trigger Mechanisms**
   - Sentinel webhook for automatic incident enrichment
   - Defender alert polling service
   - Flexible on-demand analysis function

6. **Enhanced Data Output**
   - 5 custom Log Analytics tables (instead of 1)
   - Granular data for workbooks and queries
   - Better historical analysis

---

## 🔄 Backward Compatibility

**Good news:** V2 is fully backward compatible with V1!

- Existing configurations work without changes
- All V1 features remain functional
- New features are opt-in via configuration
- No breaking changes to existing code

---

## 📋 Upgrade Checklist

### Step 1: Backup Current Configuration
```powershell
# Backup your existing config
Copy-Item ".\Config\DefenderXSOAR.json" ".\Config\DefenderXSOAR.json.backup"
```

### Step 2: Update Configuration File

Add new sections to your `DefenderXSOAR.json`:

```json
{
  "Enrichment": {
    "ThreatIntelligence": {
      "Enabled": true,
      "Sources": ["MicrosoftThreatIntelligence"]
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
  },
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
  },
  "Triggers": {
    "SentinelWebhook": {
      "Enabled": true,
      "MinimumSeverity": "Medium"
    },
    "DefenderPolling": {
      "Enabled": false,
      "IntervalMinutes": 5,
      "MinimumSeverity": "Medium"
    }
  }
}
```

### Step 3: Test Core Functionality

Test that existing functionality still works:

```powershell
# Test with a simple entity
.\Functions\Invoke-DefenderXSOARAnalysis.ps1 `
    -EntityType 'User' `
    -EntityValue 'testuser@yourdomain.com' `
    -TenantId 'your-tenant-id' `
    -OutputFormat Summary
```

### Step 4: Enable New Features Gradually

Start with enrichment modules:

```json
{
  "Enrichment": {
    "ThreatIntelligence": { "Enabled": true },
    "GeoLocation": { "Enabled": true },
    "Reputation": { "Enabled": false },     // Enable later
    "BehaviorAnalytics": { "Enabled": false } // Enable later
  }
}
```

Then enable correlation:

```json
{
  "Correlation": { "Enabled": true }
}
```

### Step 5: Verify Custom Tables

After running enrichment, verify new tables appear in Log Analytics:

```kusto
// Check if new tables exist
search in (DefenderXSOAR_CL, DefenderXSOAR_Entities_CL, 
           DefenderXSOAR_Correlations_CL, DefenderXSOAR_Decisions_CL,
           DefenderXSOAR_Playbooks_CL)
| where TimeGenerated > ago(1d)
| summarize Count = count() by $table
```

### Step 6: Configure Triggers (Optional)

#### Option A: Sentinel Webhook
```powershell
# Deploy Azure Function webhook
# See Triggers/SentinelWebhook.ps1 for deployment instructions
```

#### Option B: Defender Polling
```powershell
# Run as scheduled task or service
.\Triggers\DefenderPolling.ps1 `
    -ConfigPath ".\Config\DefenderXSOAR.json" `
    -PollingIntervalMinutes 5 `
    -MinimumSeverity High
```

---

## 🧪 Testing V2 Features

### Test 1: Entity Enrichment
```powershell
# Test new entity types
.\Functions\Invoke-DefenderXSOARAnalysis.ps1 `
    -EntityType 'Host' `
    -EntityValue 'WORKSTATION01' `
    -TenantId $tenantId
```

### Test 2: Correlation Engine
```powershell
# Test with incident that has multiple product alerts
.\Functions\Start-DefenderXSOAROrchestration.ps1 `
    -ConfigPath ".\Config\DefenderXSOAR.json" `
    -IncidentId "TEST-001" `
    -Entities $multiProductEntities `
    -TenantId $tenantId
```

### Test 3: Enrichment Modules
```powershell
# Test with external IP addresses
$entities = @(
    @{ Type = 'IP'; Address = '203.0.113.42' }
)
.\Functions\Invoke-DefenderXSOARAnalysis.ps1 `
    -Entities $entities `
    -TenantId $tenantId `
    -OutputFormat Full
```

### Test 4: Custom Tables
```kusto
// Query correlation data
DefenderXSOAR_Correlations_CL
| where TimeGenerated > ago(1h)
| project TimeGenerated, IncidentId, CorrelationType, RiskScore, Severity
```

---

## 📊 Recommended Workbooks

### Workbook 1: V2 Enhanced Dashboard
Create a new workbook with these queries:

**Correlation Overview:**
```kusto
DefenderXSOAR_Correlations_CL
| where TimeGenerated > ago(7d)
| summarize Count = count() by CorrelationType
| render columnchart
```

**Entity Risk Distribution:**
```kusto
DefenderXSOAR_Entities_CL
| where TimeGenerated > ago(7d)
| extend EntityDetails = parse_json(EntityValue)
| summarize Count = count() by EntityType
| render piechart
```

**Decision Analytics:**
```kusto
DefenderXSOAR_Decisions_CL
| where TimeGenerated > ago(7d)
| summarize Count = count() by Action, Priority
| render columnchart
```

---

## ⚙️ Configuration Reference

### Minimal V2 Configuration
```json
{
  "Enrichment": {
    "ThreatIntelligence": { "Enabled": true }
  },
  "Correlation": {
    "Enabled": true,
    "TimeWindowMinutes": 60
  }
}
```

### Recommended V2 Configuration
```json
{
  "Enrichment": {
    "ThreatIntelligence": { 
      "Enabled": true,
      "Sources": ["MicrosoftThreatIntelligence"]
    },
    "GeoLocation": { 
      "Enabled": true,
      "DetectImpossibleTravel": true 
    },
    "Reputation": { 
      "Enabled": true 
    },
    "BehaviorAnalytics": { 
      "Enabled": true,
      "BaselinePeriodDays": 30 
    }
  },
  "Correlation": {
    "Enabled": true,
    "TimeWindowMinutes": 60
  },
  "Triggers": {
    "SentinelWebhook": {
      "Enabled": true,
      "MinimumSeverity": "Medium"
    }
  }
}
```

### Production V2 Configuration
Use recommended configuration plus:
- Adjust time windows based on your environment
- Configure high-risk countries for your organization
- Set baseline periods based on user patterns
- Configure triggers based on your workflow

---

## 🔍 Monitoring V2

### Key Metrics to Monitor

1. **Enrichment Success Rate**
```kusto
DefenderXSOAR_CL
| where TimeGenerated > ago(24h)
| summarize Total = count(), 
            Successful = countif(RiskScore > 0)
| extend SuccessRate = (Successful * 100.0 / Total)
```

2. **Correlation Detection Rate**
```kusto
DefenderXSOAR_Correlations_CL
| where TimeGenerated > ago(7d)
| summarize CorrelationsPerDay = count() by bin(TimeGenerated, 1d)
| render timechart
```

3. **Average Processing Time**
```kusto
DefenderXSOAR_CL
| where TimeGenerated > ago(24h)
| extend ProcessingTime = datetime_diff('second', TimeGenerated, todatetime(EnrichmentData.Timestamp))
| summarize AvgProcessingTime = avg(ProcessingTime)
```

---

## 🚨 Troubleshooting

### Issue: Enrichment modules not running
**Symptoms:** No threat intel or geolocation data
**Solution:**
```powershell
# Verify modules are loaded
Get-Module -Name *Enrichment*

# Re-import if needed
Import-Module .\Modules\Enrichment\ThreatIntelEnrichment.psm1 -Force
```

### Issue: Correlation engine not finding correlations
**Symptoms:** Empty correlation results
**Solution:**
- Increase time window: `"TimeWindowMinutes": 120`
- Verify multiple products have data
- Check alert timestamps are within window

### Issue: Custom tables not appearing
**Symptoms:** Tables missing in Log Analytics
**Solution:**
- Wait 5-10 minutes after first ingestion
- Verify WorkspaceId and SharedKey are correct
- Check for ingestion errors in Azure portal

### Issue: High memory usage
**Symptoms:** PowerShell consuming excessive memory
**Solution:**
- Reduce concurrent enrichment lookups
- Disable unused enrichment modules
- Process entities in smaller batches

---

## 📚 Additional Resources

- **V2 Features Documentation:** `DEFENDERXSOAR-V2-FEATURES.md`
- **Implementation Summary:** `IMPLEMENTATION-SUMMARY.md`
- **Quick Start Guide:** `QUICKSTART.md`
- **Analyst Playbooks:** `Documentation/AnalystPlaybooks/`

---

## 🎯 Next Steps

After successful upgrade:

1. **Review Manual Investigation Playbooks**
   - Read `Documentation/AnalystPlaybooks/MDE-Investigation-Playbook.md`
   - Adapt procedures to your organization

2. **Customize Correlation Weights**
   - Adjust based on your threat landscape
   - Monitor correlation accuracy

3. **Deploy Triggers**
   - Choose webhook or polling based on needs
   - Configure severity thresholds

4. **Create Custom Workbooks**
   - Use provided queries as templates
   - Build dashboards for your team

5. **Train Security Analysts**
   - Share investigation playbooks
   - Demonstrate new analysis functions
   - Explain correlation scenarios

---

## 💡 Tips for Success

1. **Start Small:** Enable one enrichment module at a time
2. **Monitor Logs:** Watch for errors during initial runs
3. **Adjust Thresholds:** Fine-tune risk scores for your environment
4. **Document Customizations:** Keep track of your configuration changes
5. **Provide Feedback:** Report issues and suggest improvements

---

## 📞 Support

If you encounter issues:
1. Check this upgrade guide
2. Review V2 features documentation
3. Search existing GitHub issues
4. Open a new issue with details

---

*Thank you for using DefenderXSOAR V2! We hope these enhancements improve your security operations.*
