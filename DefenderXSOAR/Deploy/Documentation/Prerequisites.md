# DefenderXSOAR - Prerequisites

This document outlines all prerequisites for deploying and running DefenderXSOAR.

## Azure Requirements

### Azure Subscription
- **Active Azure subscription** with sufficient permissions
- **Recommended roles**:
  - Contributor (for resource deployment)
  - User Access Administrator (for RBAC assignments)
  - Global Administrator or Privileged Role Administrator (for API consent)

### Microsoft Sentinel
- **Log Analytics workspace** with Sentinel enabled
- **Minimum tier**: Pay-as-you-go
- **Recommended retention**: 90 days
- **Location**: Same region as DefenderXSOAR deployment (recommended)

### Resource Quotas
Ensure your subscription has quota for:
- Storage Accounts: 1
- Function Apps: 1
- Key Vaults: 1
- Application Insights: 1

## Software Requirements

### Local Development/Deployment Machine

#### PowerShell
- **PowerShell 7.0 or later** (PowerShell Core)
- Download: https://github.com/PowerShell/PowerShell/releases

Verify version:
```powershell
$PSVersionTable.PSVersion
# Should show 7.0 or higher
```

#### Azure PowerShell Modules
Required modules:
- Az.Accounts (≥ 2.10.0)
- Az.Resources (≥ 6.0.0)
- Az.Websites (≥ 3.0.0)
- Az.KeyVault (≥ 4.9.0)
- Az.OperationalInsights (≥ 3.2.0)

Install all modules:
```powershell
Install-Module -Name Az.Accounts, Az.Resources, Az.Websites, Az.KeyVault, Az.OperationalInsights -Force -AllowClobber
```

Verify installation:
```powershell
Get-Module -ListAvailable Az.Accounts, Az.Resources, Az.Websites, Az.KeyVault, Az.OperationalInsights
```

#### Git (Optional)
- For cloning the repository
- Download: https://git-scm.com/downloads

### Azure CLI (Optional)
- Useful for alternative deployment methods
- Version 2.40.0 or later
- Download: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli

## Microsoft Defender Product Licenses

DefenderXSOAR requires licenses for the Microsoft Defender products you want to integrate:

### Core Products
1. **Microsoft Defender for Endpoint (MDE)**
   - Plan 1 or Plan 2
   - Required for: Device analysis, malware detection, threat hunting

2. **Microsoft Defender for Cloud (MDC)**
   - Azure Defender enabled
   - Required for: Cloud security posture, vulnerability assessment

3. **Microsoft Defender for Cloud Apps (MCAS)**
   - Standalone or part of E5
   - Required for: Cloud app discovery, user behavior analytics

4. **Microsoft Defender for Identity (MDI)**
   - Standalone or part of E5
   - Required for: Identity threat detection, lateral movement analysis

5. **Microsoft Defender for Office 365 (MDO)**
   - Plan 1 or Plan 2
   - Required for: Email security, phishing detection

6. **Microsoft Entra ID (Azure AD)**
   - Premium P1 or P2
   - Required for: Identity risk events, risky sign-ins

### Licensing Bundles
DefenderXSOAR is included in:
- **Microsoft 365 E5**: All products included
- **Microsoft 365 E5 Security**: All Defender products
- **Enterprise Mobility + Security E5**: MDI, Entra ID P2

## Azure AD Permissions

### For Deployment
The user deploying DefenderXSOAR needs:
- **Application Administrator** or **Cloud Application Administrator** (for app registration)
- **Global Administrator** (for granting admin consent to API permissions)

### For App Registration
Create or use an app registration with:
- **Multi-tenant** enabled (for MSSP scenarios)
- **Client secret** or **Certificate** for authentication

## Network Requirements

### Outbound Connectivity
DefenderXSOAR Function App needs outbound access to:

#### Microsoft APIs
- `*.security.microsoft.com` (MDE, M365 Defender)
- `graph.microsoft.com` (Microsoft Graph)
- `management.azure.com` (Azure Resource Manager)
- `*.portal.cloudappsecurity.com` (MCAS)
- `*.manage.office.com` (Office 365 Management)

#### Azure Services
- `*.blob.core.windows.net` (Azure Storage)
- `*.vault.azure.net` (Key Vault)
- `*.applicationinsights.azure.com` (Application Insights)
- `*.ods.opinsights.azure.com` (Log Analytics)

### Firewall Rules
If using network restrictions:
1. Allow Function App outbound to all Microsoft service tags
2. Service Tags needed:
   - AzureCloud
   - AzureActiveDirectory
   - AzureKeyVault
   - Storage

### Private Endpoints (Optional)
For enhanced security:
- Key Vault private endpoint
- Storage account private endpoint
- Requires VNet integration (Premium Function plan)

## Security Requirements

### Authentication Methods
Choose one:
1. **Managed Identity** (Recommended)
   - No credential management
   - Automatic token rotation
   - Azure-only

2. **Service Principal with Certificate**
   - Multi-tenant support
   - Enterprise security
   - Manual certificate renewal

3. **Service Principal with Secret**
   - Quick setup
   - Secret rotation required
   - Less secure than certificate

### Key Vault Configuration
- **Soft delete enabled** (mandatory for production)
- **Purge protection** (recommended for production)
- **RBAC authorization** (recommended over access policies)

## Capacity Planning

### Function App Sizing

#### Consumption Plan (Y1)
- **Best for**: Small to medium deployments (< 100 incidents/day)
- **Cost**: Pay per execution
- **Limits**: 10-minute timeout, 1.5 GB memory
- **Scale**: Automatic up to 200 instances

#### Premium Plan (EP1/EP2/EP3)
- **Best for**: Large deployments, VNet integration
- **Cost**: Fixed monthly + execution
- **Limits**: Unlimited timeout, up to 14 GB memory
- **Scale**: Pre-warmed instances, faster cold starts

#### Recommendation Matrix
| Incidents/Day | Plan | Estimated Cost |
|---------------|------|----------------|
| < 100 | Consumption (Y1) | $10-50/month |
| 100-500 | Premium EP1 | $180/month |
| 500-2000 | Premium EP2 | $360/month |
| > 2000 | Premium EP3 | $540/month |

### Storage Requirements
- **Consumption plan**: ~1 GB minimum
- **Log Analytics**: 100 MB - 10 GB/day (depends on incident volume)
- **Application Insights**: 1-5 GB/month

### Log Analytics Sizing
Calculate daily data ingestion:
- DefenderXSOAR logs: ~5 KB per incident
- Custom tables: ~10 KB per incident
- Total per incident: ~15 KB

Example: 100 incidents/day = 1.5 MB/day = ~45 MB/month

## Multi-Tenant MSSP Requirements

For managed service providers managing multiple customer tenants:

### MSSP Tenant
- **Azure subscription** for hosting DefenderXSOAR
- **App registration** with multi-tenant enabled
- **Certificate** for authentication (recommended)

### Customer Tenant
Each customer needs:
- **Admin consent** for app registration
- **Microsoft Defender licenses**
- **Global Administrator** to grant consent

### Network Considerations
- Function App can access multiple tenants
- No VPN or ExpressRoute required
- Uses Microsoft's multi-tenant authentication

## Compliance Requirements

### Data Residency
- DefenderXSOAR processes data in the Azure region deployed
- Log Analytics data stored in workspace region
- No cross-region data transfer (configurable)

### Regulatory Compliance
DefenderXSOAR supports:
- **GDPR**: Data retention policies, encryption at rest
- **HIPAA**: Available in Azure Government regions
- **SOC 2**: Azure-native compliance
- **ISO 27001**: Key Vault, TLS 1.2 enforcement

## Optional Components

### Advanced Features
- **Azure Front Door**: CDN for Logic Apps interface
- **Azure Monitor**: Additional alerting and dashboards
- **Azure Automation**: Scheduled maintenance tasks
- **Azure DevOps**: CI/CD for updates

### Third-Party Integrations
- **VirusTotal API**: File reputation enrichment
- **AlienVault OTX**: Threat intelligence
- **TAXII Servers**: Threat intelligence feeds

## Pre-Deployment Checklist

Before starting deployment, verify:

- [ ] Azure subscription with appropriate permissions
- [ ] Microsoft Sentinel workspace deployed
- [ ] PowerShell 7.0+ installed
- [ ] Azure PowerShell modules installed
- [ ] Required Defender product licenses
- [ ] Network connectivity to Microsoft APIs
- [ ] Understanding of authentication method (managed identity vs service principal)
- [ ] Capacity planning completed
- [ ] Budget approval for Azure resources
- [ ] Security review completed (if required)
- [ ] Change management approval (if required)

## Resource Naming Conventions

Recommended naming pattern:
- Function App: `defenderxsoar-func-<env>-<region>`
- Storage Account: `defxsoar<env><random>`
- Key Vault: `defenderxsoar-kv-<env>`
- Resource Group: `DefenderXSOAR-<env>-RG`

Where:
- `<env>`: prod, dev, test
- `<region>`: eastus, westeurope, etc.
- `<random>`: unique string for global uniqueness

## Next Steps

After verifying all prerequisites:
1. Review [Architecture Documentation](Architecture.md)
2. Review [Permissions Documentation](Permissions.md)
3. Proceed with [Main Deployment Guide](../README.md)
