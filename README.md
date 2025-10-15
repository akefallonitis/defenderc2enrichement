# DefenderXSOAR - Comprehensive Security Orchestration, Automation & Response

[![PowerShell](https://img.shields.io/badge/PowerShell-7.0%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fakefallonitis%2Fdefenderc2enrichement%2Fmain%2FDefenderXSOAR%2FDeploy%2Fdefenderxsoar-deploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fakefallonitis%2Fdefenderc2enrichement%2Fmain%2FDefenderXSOAR%2FDeploy%2FcreateUiDefinition.json)

A production-ready, enterprise-grade Security Orchestration, Automation, and Response (SOAR) platform that consolidates Microsoft Defender product capabilities with advanced risk scoring, entity normalization, and multi-tenant support for MSSP environments.

## 🚀 Quick Deploy

Deploy DefenderXSOAR to Azure in minutes with our one-click deployment:

**[📘 Complete Deployment Guide](DefenderXSOAR/Deploy/README.md)** | **[🔧 Prerequisites](DefenderXSOAR/Deploy/Documentation/Prerequisites.md)** | **[📖 Architecture](DefenderXSOAR/Deploy/Documentation/Architecture.md)**

## 🎯 Overview

DefenderXSOAR is a comprehensive orchestration platform that:
- **Integrates** all Microsoft Defender products (MDE, MDC, MCAS, MDI, MDO, Entra ID)
- **Normalizes** entities across different security products using official Microsoft Sentinel entity schemas
- **Calculates** risk scores using a unified scoring engine (Microsoft + STAT + Custom)
- **Automates** incident response decisions with ML-like analytics
- **Supports** multi-tenant MSSP scenarios
- **Provides** production-ready hunting playbooks with real KQL queries
- **Uses** direct Microsoft API calls (no Logic Apps connectors required)
- **Executes** workers in parallel for improved performance
- **Implements** circuit breaker patterns for resilience

## 🏗️ Architecture

```
DefenderXSOAR/
├── Modules/
│   ├── DefenderXSOARBrain.psm1        # Central orchestrator
│   ├── Common/
│   │   ├── AuthenticationHelper.psm1   # Multi-tenant auth
│   │   ├── EntityNormalizer.psm1       # Entity unification
│   │   ├── DataTableManager.psm1       # Log Analytics integration
│   │   └── UnifiedRiskScorer.psm1      # ⭐ NEW: Unified risk scoring engine
│   ├── Workers/
│   │   ├── MDEWorker.psm1              # Microsoft Defender for Endpoint
│   │   ├── MDCWorker.psm1              # Microsoft Defender for Cloud
│   │   ├── MCASWorker.psm1             # Microsoft Defender for Cloud Apps
│   │   ├── MDIWorker.psm1              # Microsoft Defender for Identity
│   │   ├── MDOWorker.psm1              # Microsoft Defender for Office 365
│   │   └── EntraIDWorker.psm1          # Microsoft Entra ID
│   └── Playbooks/
│       ├── MDEPlaybooks.psm1           # MDE hunting queries
│       ├── MDCPlaybooks.psm1           # MDC hunting queries
│       ├── MCASPlaybooks.psm1          # MCAS hunting queries
│       ├── MDIPlaybooks.psm1           # MDI hunting queries
│       ├── MDOPlaybooks.psm1           # MDO hunting queries
│       └── EntraIDPlaybooks.psm1       # Entra ID hunting queries
├── Functions/
│   └── Start-DefenderXSOAROrchestration.ps1  # Main entry point
├── Config/
│   └── DefenderXSOAR.json              # Configuration template
└── Deploy/
    ├── defenderxsoar-deploy.json       # ARM template
    ├── createUiDefinition.json         # Azure Portal UI
    ├── Deploy-DefenderXSOAR.ps1        # Legacy deployment script
    ├── Deploy-DefenderXSOARCode.ps1    # Code deployment
    ├── Grant-DefenderXSOARPermissions.ps1  # Permission setup (✅ Included)
    ├── Configure-DefenderXSOAR.ps1     # Post-deployment config
    ├── Test-DefenderXSOAR.ps1          # Validation tests
    ├── Create-MultiTenantApp.ps1       # MSSP app registration
    ├── Grant-CustomerConsent.ps1       # Customer consent workflow
    ├── Setup-Monitoring.ps1            # Monitoring configuration
    └── Documentation/                   # Complete documentation
        ├── Prerequisites.md
        ├── Permissions.md
        ├── Architecture.md
        ├── Deployment.md               # ✅ New: Complete deployment guide
        ├── Configuration.md            # ✅ New: Configuration guide
        ├── API-Reference.md            # ✅ New: API documentation
        ├── Troubleshooting.md
        └── Upgrade.md
```

## 🚀 Features

### Product Workers

#### 1. Microsoft Defender for Endpoint (MDE)
- Device compromise detection
- Malware analysis and file reputation
- Process tree analysis
- Network connection analysis
- Lateral movement detection
- Advanced hunting with KQL

#### 2. Microsoft Defender for Cloud (MDC)
- Cloud security posture analysis
- Vulnerability assessment
- Compliance deviation detection
- Resource configuration analysis
- Azure Secure Score integration

#### 3. Microsoft Defender for Cloud Apps (MCAS)
- Cloud app risk assessment
- Data exfiltration detection
- User behavior analytics (UEBA)
- OAuth app analysis
- Anomaly detection

#### 4. Microsoft Defender for Identity (MDI)
- Identity compromise detection
- Lateral movement analysis
- Privilege escalation detection
- Kerberos attack detection (Golden/Silver Ticket)
- Active Directory security

#### 5. Microsoft Defender for Office 365 (MDO)
- Phishing campaign detection
- Safe Attachments analysis
- Email security posture
- Collaboration security (Teams/SharePoint)
- Threat intelligence integration

#### 6. Microsoft Entra ID
- Risky sign-in analysis
- Conditional Access violations
- Identity Protection alerts
- MFA bypass detection
- Anomalous authentication patterns

### Core Capabilities

#### DefenderXSOAR Brain
- **Centralized Orchestration**: Controls all workers and coordinates enrichment
- **Decision Engine**: Makes intelligent decisions on incident handling (escalate, investigate, close)
- **Risk Scoring**: Advanced risk calculation across all products
- **Multi-Tenant**: Full MSSP support with tenant isolation
- **Workflow Integration**: Triggers external Logic Apps/Function Apps

#### Entity Normalization
- Unified entity format across all products
- Support for: Users, Devices, IPs, Files, URLs, Processes, Emails, Cloud Apps, Azure Resources
- Automatic entity correlation and deduplication

#### Risk Scoring (⭐ Enhanced with Unified Scoring)
- **Unified Risk Scoring Engine**: Combines Microsoft native scores (35%), STAT analytics (35%), and custom scoring (30%)
- **ML-like Feature Extraction**: Behavioral patterns, temporal analysis, geographic anomalies
- **Confidence Scoring**: Score agreement validation and data completeness checks
- **Contextual Adjustments**: After-hours boost, critical asset boost
- **Explainability**: Detailed breakdown of scoring factors and top contributors
- **Actionable Recommendations**: Risk-based guidance for incident response
- Product-weighted risk calculation (fallback mode)
- Threat intelligence integration
- UEBA behavioral analysis
- Configurable thresholds and weights

#### Data Management
- Custom Log Analytics table (DefenderXSOAR_CL)
- Automatic incident comments
- Workbook-ready data structure
- 90-day retention by default

## 🚀 Quick Start - Deploy to Azure

Deploy DefenderXSOAR to Azure in minutes with our comprehensive deployment package:

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fakefallonitis%2Fdefenderc2enrichement%2Fmain%2FDefenderXSOAR%2FDeploy%2Fdefenderxsoar-deploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fakefallonitis%2Fdefenderc2enrichement%2Fmain%2FDefenderXSOAR%2FDeploy%2FcreateUiDefinition.json)

### What Gets Deployed
- ✅ Azure Function App (PowerShell 7.2 runtime)
- ✅ Storage Account (Standard_LRS)
- ✅ Key Vault (RBAC-enabled, soft delete)
- ✅ Application Insights (linked to Sentinel)
- ✅ System-Assigned Managed Identity
- ✅ Pre-configured application settings

### Deployment Time
- **ARM Template**: ~5 minutes
- **Post-deployment scripts**: ~20 minutes
- **Total**: ~30 minutes

### Cost Estimate
- **Consumption Plan**: $30-130/month
- **Premium EP1**: $215-318/month

**📘 [Complete Deployment Guide](DefenderXSOAR/Deploy/README.md)** | **[Prerequisites](DefenderXSOAR/Deploy/Documentation/Prerequisites.md)** | **[Troubleshooting](DefenderXSOAR/Deploy/Documentation/Troubleshooting.md)**

---

## 📋 Prerequisites

- PowerShell 7.0 or later
- Azure subscription with Sentinel workspace
- Azure AD app registration with appropriate permissions
- Access to Microsoft Defender products
- Log Analytics workspace

## 🔧 Installation

### 1. Clone the Repository

```powershell
git clone https://github.com/akefallonitis/defenderc2enrichement.git
cd defenderc2enrichement/DefenderXSOAR
```

### 2. Deploy Azure Resources

```powershell
.\Deploy\Deploy-DefenderXSOAR.ps1 `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "DefenderXSOAR-RG" `
    -Location "eastus" `
    -WorkspaceName "defenderxsoar-workspace" `
    -CreateAppRegistration $true
```

### 3. Grant API Permissions

```powershell
.\Deploy\Grant-DefenderXSOARPermissions.ps1 `
    -ApplicationId "your-app-id" `
    -TenantId "your-tenant-id"
```

Follow the on-screen instructions to grant required permissions in Azure Portal.

### 4. Configure Settings

Edit `Config/DefenderXSOAR.json` with your environment details:

```json
{
  "Tenants": [
    {
      "TenantName": "Production",
      "TenantId": "your-tenant-id",
      "ClientId": "your-client-id",
      "ClientSecret": "your-client-secret",
      "SubscriptionId": "your-subscription-id",
      "Enabled": true
    }
  ],
  "LogAnalytics": {
    "Enabled": true,
    "WorkspaceId": "your-workspace-id",
    "SharedKey": "your-shared-key"
  }
}
```

## 💡 Usage

### Basic Usage

```powershell
# Import the orchestration function
. .\Functions\Start-DefenderXSOAROrchestration.ps1

# Define incident entities
$entities = @(
    @{
        Type = "User"
        UserPrincipalName = "user@domain.com"
    },
    @{
        Type = "Device"
        HostName = "DESKTOP-001"
    },
    @{
        Type = "IP"
        Address = "192.168.1.100"
    }
)

# Start orchestration
$result = .\Functions\Start-DefenderXSOAROrchestration.ps1 `
    -ConfigPath ".\Config\DefenderXSOAR.json" `
    -IncidentId "12345" `
    -IncidentArmId "/subscriptions/.../incidents/12345" `
    -Entities $entities `
    -TenantId "your-tenant-id" `
    -Products @('MDE', 'MDC', 'MCAS', 'MDI', 'MDO', 'EntraID')
```

### Azure Logic App Integration

```json
{
  "type": "Function",
  "inputs": {
    "method": "POST",
    "body": {
      "IncidentId": "@{triggerBody()?['object']?['properties']?['incidentNumber']}",
      "IncidentArmId": "@{triggerBody()?['object']?['id']}",
      "Entities": "@{triggerBody()?['object']?['properties']?['entities']}",
      "TenantId": "@parameters('TenantId')"
    },
    "function": {
      "id": "/subscriptions/.../functions/DefenderXSOAR"
    }
  }
}
```

### Sentinel Automation Rule

Create an automation rule in Sentinel:
1. Trigger: When incident is created
2. Condition: Incident severity is Medium or higher
3. Action: Run playbook → DefenderXSOAR
4. Result: Automatic enrichment and incident comments

## 📊 Hunting Playbooks

### MDE Playbooks
- **DeviceCompromiseDetection**: Detects device compromise indicators
- **MalwareAnalysis**: Comprehensive malware analysis
- **ProcessTreeAnalysis**: Analyzes process hierarchies
- **NetworkConnectionAnalysis**: Identifies suspicious network activity
- **FileReputationCheck**: Assesses file reputation
- **LateralMovementDetection**: Detects lateral movement

### MDC Playbooks
- **SecurityPostureAnalysis**: Cloud security posture
- **VulnerabilityAssessment**: Vulnerability prioritization
- **ComplianceDeviation**: Compliance gap analysis
- **ResourceConfigAnalysis**: Configuration change analysis

### MCAS Playbooks
- **CloudAppRiskAssessment**: Cloud app risk scoring
- **DataExfiltrationDetection**: Data exfiltration patterns
- **UserBehaviorAnalytics**: UEBA analysis
- **OAuthAppAnalysis**: OAuth application risks

### MDI Playbooks
- **IdentityCompromiseDetection**: Identity compromise indicators
- **LateralMovementAnalysis**: Lateral movement patterns
- **PrivilegeEscalationDetection**: Privilege escalation attempts
- **KerberosAttackDetection**: Kerberos-based attacks

### MDO Playbooks
- **PhishingCampaignDetection**: Phishing campaigns
- **SafeAttachmentsAnalysis**: Malicious attachments
- **EmailSecurityAnalysis**: Email security posture
- **CollaborationSecurity**: Teams/SharePoint security

### Entra ID Playbooks
- **RiskySignInAnalysis**: Risky authentication events
- **ConditionalAccessViolations**: CA policy violations
- **IdentityProtectionAlerts**: Identity risk detections
- **MFABypassAttempts**: MFA bypass detection
- **AnomalousSignInPatterns**: Behavioral anomalies

## 🔐 Required Permissions

### Microsoft Graph API
- SecurityEvents.Read.All
- SecurityAlert.Read.All
- IdentityRiskEvent.Read.All
- IdentityRiskyUser.Read.All
- User.Read.All
- AuditLog.Read.All
- Directory.Read.All

### Microsoft Defender ATP API
- Machine.Read.All
- Alert.Read.All
- File.Read.All
- AdvancedQuery.Read.All
- Vulnerability.Read.All

### Azure RBAC
- Security Reader
- Log Analytics Reader

## 📈 Output Format

### Log Analytics Custom Table

```
DefenderXSOAR_CL
├── TimeGenerated
├── IncidentId
├── Product
├── RiskScore
├── Severity
├── EntitiesCount
├── RelatedAlertsCount
├── ThreatIntelCount
├── WatchlistMatches
├── UEBAInsights
├── Recommendations
└── EnrichmentData (JSON)
```

### Incident Comment Format

```markdown
## DefenderXSOAR Enrichment Results
**Product:** All Products
**Risk Score:** 75/100
**Severity:** High

### Entities Analyzed
15 entities processed

### Related Alerts
23 related alerts found

### Recommendations
- High risk score detected - prioritize investigation
- Multiple behavioral anomalies detected
- User signing in from 15 different IPs - possible account compromise
```

## 🎛️ Configuration Options

### Risk Scoring
```json
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
  }
}
```

### Incident Decisions
```json
"IncidentDecisions": {
  "AutoEscalate": {
    "Enabled": true,
    "MinimumRiskScore": 80,
    "RequiredThreatIntelCount": 3
  },
  "AutoClose": {
    "Enabled": false,
    "MaximumRiskScore": 10
  }
}
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👥 Authors

- **akefallonitis** - Initial work

## 🙏 Acknowledgments

- Microsoft Defender product teams
- Microsoft Sentinel community
- PowerShell community

## 📞 Support

For issues, questions, or contributions, please open an issue on GitHub.

## 🔄 Version History

- **v1.0.0** - Initial release with full product integration
  - All 6 product workers implemented
  - 25+ hunting playbooks with real KQL queries
  - Multi-tenant support
  - Risk scoring engine
  - Log Analytics integration

## 🗺️ Roadmap

- [ ] Machine learning-based anomaly detection
- [ ] Automated remediation actions
- [ ] Custom playbook designer
- [ ] Advanced threat hunting UI
- [ ] Integration with third-party SIEM
- [ ] Extended UEBA capabilities
- [ ] Threat intelligence enrichment APIs
