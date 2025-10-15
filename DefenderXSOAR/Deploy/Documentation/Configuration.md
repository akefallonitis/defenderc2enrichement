# DefenderXSOAR Configuration Guide

Complete guide for configuring DefenderXSOAR after deployment.

## Table of Contents

- [Overview](#overview)
- [Configuration File Structure](#configuration-file-structure)
- [Tenant Configuration](#tenant-configuration)
- [Product Configuration](#product-configuration)
- [Risk Scoring Configuration](#risk-scoring-configuration)
- [Trigger Configuration](#trigger-configuration)
- [Advanced Configuration](#advanced-configuration)

## Overview

DefenderXSOAR configuration is stored in Azure Key Vault as a JSON secret named `DefenderXSOAR-Configuration`.

### Configuration Methods

1. **Key Vault Secret** (Recommended) - Secure, centralized
2. **Environment Variables** - For development/testing
3. **Configuration File** - For local testing

## Configuration File Structure

```json
{
  "Version": "1.0.0",
  "Description": "DefenderXSOAR Configuration",
  "Tenants": [],
  "Products": {},
  "RiskScoring": {},
  "IncidentDecisions": {},
  "Triggers": {},
  "Enrichment": {},
  "Correlation": {},
  "Logging": {}
}
```

## Tenant Configuration

### Single Tenant Setup

```json
{
  "Tenants": [
    {
      "TenantName": "Production",
      "TenantId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      "ClientId": "11111111-2222-3333-4444-555555555555",
      "ClientSecret": "your-client-secret-here",
      "SubscriptionId": "sub-id-here",
      "MCASUrl": "https://contoso.portal.cloudappsecurity.com",
      "MCASToken": "your-mcas-token",
      "Enabled": true
    }
  ]
}
```

### Multi-Tenant MSSP Setup

```json
{
  "Tenants": [
    {
      "TenantName": "MSSP-Management",
      "TenantId": "mssp-tenant-id",
      "ClientId": "multi-tenant-app-id",
      "ClientSecret": "multi-tenant-secret",
      "SubscriptionId": "mssp-subscription-id",
      "MCASUrl": "https://mssp.portal.cloudappsecurity.com",
      "MCASToken": "mssp-mcas-token",
      "Enabled": true,
      "IsManagement": true
    },
    {
      "TenantName": "Customer-A",
      "TenantId": "customer-a-tenant-id",
      "ClientId": "multi-tenant-app-id",
      "ClientSecret": "multi-tenant-secret",
      "SubscriptionId": "customer-a-subscription-id",
      "MCASUrl": "https://customera.portal.cloudappsecurity.com",
      "MCASToken": "customer-a-mcas-token",
      "Enabled": true,
      "IsManagement": false
    },
    {
      "TenantName": "Customer-B",
      "TenantId": "customer-b-tenant-id",
      "ClientId": "multi-tenant-app-id",
      "ClientSecret": "multi-tenant-secret",
      "SubscriptionId": "customer-b-subscription-id",
      "MCASUrl": "https://customerb.portal.cloudappsecurity.com",
      "MCASToken": "customer-b-mcas-token",
      "Enabled": true,
      "IsManagement": false
    }
  ]
}
```

### Tenant Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| TenantName | Yes | Friendly name for the tenant |
| TenantId | Yes | Azure AD Tenant ID |
| ClientId | Yes | Application (Client) ID |
| ClientSecret | Yes | Application Client Secret |
| SubscriptionId | Yes | Azure Subscription ID |
| MCASUrl | No | Microsoft Defender for Cloud Apps portal URL |
| MCASToken | No | MCAS API token |
| Enabled | Yes | Enable/disable tenant processing |
| IsManagement | No | Mark as MSSP management tenant |

## Product Configuration

Enable or disable individual Defender products:

```json
{
  "Products": {
    "MDE": {
      "Enabled": true,
      "Priority": 1,
      "MinimumRiskScore": 20
    },
    "MDC": {
      "Enabled": true,
      "Priority": 2,
      "MinimumRiskScore": 20
    },
    "MCAS": {
      "Enabled": true,
      "Priority": 3,
      "MinimumRiskScore": 20
    },
    "MDI": {
      "Enabled": true,
      "Priority": 4,
      "MinimumRiskScore": 20
    },
    "MDO": {
      "Enabled": true,
      "Priority": 5,
      "MinimumRiskScore": 20
    },
    "EntraID": {
      "Enabled": true,
      "Priority": 6,
      "MinimumRiskScore": 20
    }
  }
}
```

### Product Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| Enabled | Enable/disable product | `true` |
| Priority | Processing priority (1-6) | Varies |
| MinimumRiskScore | Minimum score to include in analysis | `20` |

## Risk Scoring Configuration

### Unified Risk Scoring (New)

DefenderXSOAR now includes a unified risk scoring engine that combines Microsoft native scores, STAT-like analytics, and custom scoring into a comprehensive risk assessment.

```json
{
  "UnifiedRiskScoring": {
    "Enabled": true,
    "ScoringWeights": {
      "Microsoft": 0.35,
      "STAT": 0.35,
      "Custom": 0.30
    },
    "DynamicWeightAdjustment": {
      "Enabled": true
    },
    "ConfidenceThresholds": {
      "High": 0.8,
      "Medium": 0.6,
      "Low": 0.4
    },
    "ContextualAdjustments": {
      "AfterHoursBoost": 1.15,
      "CriticalAssetBoost": 1.25
    }
  }
}
```

#### Unified Scoring Components

- **Microsoft Native (35%)**: Combines Defender for Endpoint, Cloud, Identity Protection, Secure Score, and Sentinel severity
- **STAT Analytics (35%)**: ML-like behavioral patterns, attack chains, temporal analysis, and anomaly detection
- **Custom Scoring (30%)**: Existing weighted scoring and cross-product correlations

#### Configuration Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| Enabled | Enable unified risk scoring | `true` |
| Microsoft | Weight for Microsoft native scores | `0.35` |
| STAT | Weight for STAT analytics | `0.35` |
| Custom | Weight for custom scoring | `0.30` |
| DynamicWeightAdjustment | Adjust weights based on confidence | `true` |
| AfterHoursBoost | Multiplier for after-hours incidents | `1.15` |
| CriticalAssetBoost | Multiplier for critical asset incidents | `1.25` |

#### Output Format

The unified risk scorer provides:
- **FinalScore**: Unified risk score (0-100)
- **Severity**: Critical, High, Medium, Low, Informational
- **Confidence**: Score confidence (0-1)
- **ComponentScores**: Breakdown by Microsoft, STAT, and Custom
- **Explainability**: Detailed breakdown of scoring factors
- **Recommendations**: Actionable recommendations based on risk

### Traditional Risk Scoring

Configure traditional risk scoring thresholds and weights (used when UnifiedRiskScoring is disabled):

```json
{
  "RiskScoring": {
    "Thresholds": {
      "Critical": 80,
      "High": 60,
      "Medium": 40,
      "Low": 20
    },
    "Weights": {
      "MDE": 1.2,
      "MDC": 1.0,
      "MCAS": 1.1,
      "MDI": 1.3,
      "MDO": 1.0,
      "EntraID": 1.2
    },
    "DecayFactorDays": 30,
    "BaselineRequired": true
  }
}
```

### Risk Scoring Algorithm

Risk score calculation:

```
RiskScore = Σ(ProductScore × Weight) / TotalWeight
FinalScore = RiskScore × TimeDecayFactor
```

Where:
- `ProductScore`: Individual product risk score (0-100)
- `Weight`: Product weight multiplier
- `TimeDecayFactor`: Time-based decay (1.0 for new, decreases over time)

### Customizing Weights

Adjust weights based on your environment:

```json
{
  "Weights": {
    "MDE": 1.5,      // Increase if endpoint security is critical
    "MDC": 0.8,      // Decrease if cloud security is less critical
    "MCAS": 1.2,     // Increase for SaaS-heavy environments
    "MDI": 1.5,      // Increase for identity-focused threats
    "MDO": 1.0,      // Standard weight
    "EntraID": 1.3   // Increase for identity compromise concerns
  }
}
```

## Incident Decisions Configuration

Configure automatic incident actions:

```json
{
  "IncidentDecisions": {
    "AutoEscalate": {
      "Enabled": true,
      "MinimumRiskScore": 80,
      "RequiredThreatIntelCount": 3,
      "RequiredProducts": 2
    },
    "AutoClose": {
      "Enabled": false,
      "MaximumRiskScore": 10,
      "RequireNoThreatIntel": true
    },
    "AutoMerge": {
      "Enabled": true,
      "SimilarityThreshold": 0.8,
      "TimeWindowHours": 24
    },
    "AutoAssign": {
      "Enabled": false,
      "RuleBasedAssignment": true,
      "DefaultAssignee": "soc-team@contoso.com"
    }
  }
}
```

### Auto-Escalation Rules

Escalate incidents automatically when:
- Risk score ≥ `MinimumRiskScore`
- Threat intel matches ≥ `RequiredThreatIntelCount`
- Detections from ≥ `RequiredProducts` products

### Auto-Close Rules

Close incidents automatically when:
- Risk score ≤ `MaximumRiskScore`
- No threat intelligence matches
- No high-confidence detections

## Trigger Configuration

Configure automatic triggering mechanisms:

```json
{
  "Triggers": {
    "SentinelWebhook": {
      "Enabled": true,
      "MinimumSeverity": "Medium"
    },
    "DefenderPolling": {
      "Enabled": false,
      "IntervalMinutes": 15,
      "MinimumSeverity": "High"
    },
    "ScheduledAnalysis": {
      "Enabled": false,
      "CronSchedule": "0 */6 * * *",
      "AnalysisType": "HighRiskEntities"
    }
  }
}
```

### Sentinel Webhook Trigger

**Setup:**
1. Create Sentinel automation rule
2. Configure webhook action
3. Point to Function App URL: `https://{function-app}.azurewebsites.net/api/sentinel/webhook`

**Configuration:**
```json
{
  "SentinelWebhook": {
    "Enabled": true,
    "MinimumSeverity": "Medium",
    "ProcessOnCreate": true,
    "ProcessOnUpdate": false
  }
}
```

### Defender Polling Trigger

Polls Microsoft 365 Defender for new incidents:

```json
{
  "DefenderPolling": {
    "Enabled": true,
    "IntervalMinutes": 15,
    "MinimumSeverity": "High",
    "PollingWindowMinutes": 30,
    "ProcessedIncidentCache": true
  }
}
```

**Note:** Timer trigger runs every 15 minutes by default (configurable in `function.json`).

### Scheduled Analysis Trigger

Run analysis on schedule:

```json
{
  "ScheduledAnalysis": {
    "Enabled": true,
    "CronSchedule": "0 */6 * * *",  // Every 6 hours
    "AnalysisType": "HighRiskEntities",
    "LookbackDays": 7
  }
}
```

## Advanced Configuration

### Watchlists

Integrate with Sentinel watchlists:

```json
{
  "Watchlists": {
    "Enabled": true,
    "Lists": [
      {
        "Name": "VIP Users",
        "WorkspaceId": "workspace-id",
        "Alias": "vip_users",
        "ScoreMultiplier": 1.5
      },
      {
        "Name": "Known Bad IPs",
        "WorkspaceId": "workspace-id",
        "Alias": "bad_ips",
        "AutoBlock": false
      }
    ]
  }
}
```

### UEBA Integration

Configure User and Entity Behavior Analytics:

```json
{
  "UEBA": {
    "Enabled": true,
    "BaselineDays": 30,
    "AnomalyThreshold": 2.0,
    "MinimumActivities": 10,
    "DetectionTypes": [
      "ImpossibleTravel",
      "AnomalousAccess",
      "MassDownload",
      "SuspiciousIPLogin"
    ]
  }
}
```

### Enrichment Configuration

Configure external enrichment sources:

```json
{
  "Enrichment": {
    "ThreatIntelligence": {
      "Enabled": true,
      "Sources": [
        "MicrosoftThreatIntelligence",
        "VirusTotal",
        "AlienVaultOTX"
      ],
      "CacheExpirationHours": 24,
      "ParallelRequests": 5
    },
    "GeoLocation": {
      "Enabled": true,
      "HighRiskCountries": ["KP", "IR", "SY"],
      "DetectImpossibleTravel": true,
      "ImpossibleTravelThresholdKmH": 800
    },
    "Reputation": {
      "Enabled": true,
      "LowReputationThreshold": 30,
      "Sources": ["URLhaus", "PhishTank"]
    }
  }
}
```

### Correlation Configuration

Configure multi-product correlation:

```json
{
  "Correlation": {
    "Enabled": true,
    "TimeWindowMinutes": 60,
    "MinimumProducts": 2,
    "ScenarioWeights": {
      "EmailToEndpoint": 20,
      "IdentityToEndpoint": 25,
      "CloudToIdentity": 20,
      "EndpointToNetwork": 30,
      "FullKillChain": 50
    },
    "EntityMatchingThreshold": 0.9
  }
}
```

### Playbook Configuration

Configure manual investigation playbooks:

```json
{
  "Playbooks": {
    "AutoExecute": false,
    "RequireApproval": true,
    "DefaultPlaybooks": {
      "MDE": [
        "DeviceCompromiseDetection",
        "MalwareAnalysis"
      ],
      "EntraID": [
        "RiskySignInAnalysis",
        "MFABypassAttempts"
      ]
    },
    "ExecutionTimeout": 300
  }
}
```

### Logging Configuration

Configure logging behavior:

```json
{
  "Logging": {
    "Level": "Information",
    "ConsoleOutput": true,
    "ApplicationInsights": true,
    "LogAnalytics": {
      "Enabled": true,
      "WorkspaceId": "workspace-id",
      "SharedKey": "workspace-key",
      "CustomTableName": "DefenderXSOAR_CL"
    },
    "SensitiveDataMasking": true
  }
}
```

## Applying Configuration

### Method 1: PowerShell Script

```powershell
.\Deploy\Configure-DefenderXSOAR.ps1 `
    -FunctionAppName "defenderxsoar-func-xxxxx" `
    -ResourceGroupName "DefenderXSOAR-RG" `
    -ConfigPath ".\Config\DefenderXSOAR.json"
```

### Method 2: Manual Key Vault Update

```powershell
# Load configuration
$config = Get-Content -Path ".\Config\DefenderXSOAR.json" -Raw

# Store in Key Vault
$secretValue = ConvertTo-SecureString $config -AsPlainText -Force
Set-AzKeyVaultSecret `
    -VaultName $keyVaultName `
    -Name "DefenderXSOAR-Configuration" `
    -SecretValue $secretValue
```

### Method 3: Azure Portal

1. Navigate to Key Vault
2. Go to **Secrets**
3. Click **DefenderXSOAR-Configuration**
4. Click **+ New Version**
5. Paste JSON configuration
6. Click **Create**

## Configuration Validation

Test configuration:

```powershell
.\Deploy\Test-DefenderXSOAR.ps1 `
    -FunctionAppName "defenderxsoar-func-xxxxx" `
    -ResourceGroupName "DefenderXSOAR-RG" `
    -TestConfiguration
```

Expected output:
```
✓ Configuration loaded successfully
✓ All tenant configurations valid
✓ Product configurations valid
✓ Risk scoring configuration valid
✓ Trigger configuration valid
```

## Best Practices

1. **Use Key Vault**: Never store secrets in configuration files
2. **Version Control**: Keep configuration templates in git (without secrets)
3. **Regular Updates**: Review and update configuration monthly
4. **Test Changes**: Use separate dev/test environments
5. **Document Changes**: Maintain change log for configurations
6. **Backup**: Export configuration regularly

## Environment-Specific Configurations

### Development

```json
{
  "Logging": {
    "Level": "Debug",
    "ConsoleOutput": true
  },
  "Triggers": {
    "DefenderPolling": {
      "IntervalMinutes": 60
    }
  }
}
```

### Production

```json
{
  "Logging": {
    "Level": "Information",
    "ConsoleOutput": false
  },
  "Triggers": {
    "DefenderPolling": {
      "IntervalMinutes": 15
    }
  },
  "IncidentDecisions": {
    "AutoEscalate": {
      "Enabled": true,
      "MinimumRiskScore": 80
    }
  }
}
```

## Next Steps

- 📖 Review [Deployment Guide](Deployment.md)
- 🔐 Review [Permissions Guide](Permissions.md)
- 🏗️ Review [Architecture Documentation](Architecture.md)
- 🧪 Test configuration changes
- 📊 Monitor Application Insights

## Support

For configuration assistance:
- 📧 Open an issue on [GitHub](https://github.com/akefallonitis/defenderc2enrichement/issues)
- 📖 Review [Troubleshooting Guide](Troubleshooting.md)
