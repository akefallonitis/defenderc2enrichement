# DefenderXSOAR - Azure Deployment Guide

This deployment package provides a comprehensive one-click deployment solution for DefenderXSOAR, based on the Microsoft STAT deployment architecture.

## 🚀 Quick Deploy to Azure

Click the button below to deploy DefenderXSOAR to your Azure subscription:

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fakefallonitis%2Fdefenderc2enrichement%2Fmain%2FDefenderXSOAR%2FDeploy%2Fdefenderxsoar-deploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fakefallonitis%2Fdefenderc2enrichement%2Fmain%2FDefenderXSOAR%2FDeploy%2FcreateUiDefinition.json)

## 📋 What Gets Deployed

The ARM template deploys the following Azure resources:

### Core Infrastructure
- **Azure Function App** - PowerShell 7.2 runtime hosting DefenderXSOAR modules
- **Storage Account** - Function app storage and artifact storage (Standard_LRS)
- **Key Vault** - Secure storage for API keys and secrets with RBAC
- **Application Insights** - Monitoring, telemetry, and performance tracking
- **App Service Plan** - Consumption or Premium tier (configurable)

### Configuration
- **System-Assigned Managed Identity** - For Function App to access Key Vault and Azure resources
- **Integration with Sentinel** - Connection to existing Log Analytics workspace
- **Application Settings** - Pre-configured environment variables

## 📖 Deployment Steps

### Prerequisites

Before deploying, ensure you have:

1. **Azure Subscription** with appropriate permissions:
   - Contributor role on the subscription or resource group
   - User Access Administrator (for RBAC assignments)

2. **Microsoft Sentinel** workspace already deployed

3. **PowerShell 7.0+** (for post-deployment scripts)

4. **Azure PowerShell modules** (for post-deployment scripts):
   ```powershell
   Install-Module -Name Az.Accounts, Az.Resources, Az.KeyVault, Az.OperationalInsights -Force
   ```

### Step 1: Deploy Azure Resources (5 minutes)

1. Click the **Deploy to Azure** button above
2. Fill in the required parameters:
   - **DefenderXSOAR Name**: Base name for resources (e.g., "DefenderXSOAR")
   - **Sentinel Workspace**: Select your existing Sentinel workspace
   - **Multi-Tenant App ID**: (Optional) For MSSP scenarios
   - **Function App SKU**: Choose Consumption (Y1) or Premium (EP1-EP3)
3. Click **Review + Create**, then **Create**
4. Wait for deployment to complete (~5 minutes)
5. **Save the deployment outputs** - you'll need them for subsequent steps

### Step 2: Grant API Permissions (10 minutes)

After deployment, you need to grant required API permissions to the Function App's managed identity:

```powershell
# Navigate to the Deploy directory
cd DefenderXSOAR/Deploy

# Run the permissions script
.\Grant-DefenderXSOARPermissions.ps1 `
    -FunctionAppName "<your-function-app-name>" `
    -ResourceGroupName "<your-resource-group-name>" `
    -TenantId "<your-tenant-id>"
```

This script will configure permissions for:
- Microsoft Graph API
- Microsoft Defender for Endpoint API
- Microsoft 365 Defender API
- Azure Resource Manager

See [Permissions.md](Documentation/Permissions.md) for detailed permission requirements.

### Step 3: Deploy Function Code (5 minutes)

Deploy the PowerShell modules to your Function App:

```powershell
# Run the code deployment script
.\Deploy-DefenderXSOARCode.ps1 `
    -FunctionAppName "<your-function-app-name>" `
    -ResourceGroupName "<your-resource-group-name>"
```

This will package and deploy:
- All DefenderXSOAR PowerShell modules
- Worker modules (MDE, MDC, MCAS, MDI, MDO, EntraID)
- Playbook modules
- Authentication helpers
- Function entry points

### Step 4: Configure Settings (5 minutes)

Configure tenant-specific settings:

```powershell
# Run the configuration script
.\Configure-DefenderXSOAR.ps1 `
    -FunctionAppName "<your-function-app-name>" `
    -ResourceGroupName "<your-resource-group-name>" `
    -ConfigFilePath "..\Config\DefenderXSOAR.json"
```

This will:
- Upload configuration to Key Vault
- Set up tenant-specific settings
- Configure risk thresholds
- Enable/disable products

### Step 5: Test Deployment (3 minutes)

Validate the deployment:

```powershell
# Run the test script
.\Test-DefenderXSOAR.ps1 `
    -FunctionAppName "<your-function-app-name>" `
    -ResourceGroupName "<your-resource-group-name>"
```

This performs:
- Connectivity tests to all APIs
- Authentication validation
- Log Analytics integration test
- Sample incident processing

## 🔐 Multi-Tenant MSSP Configuration

For managed security service provider (MSSP) scenarios with multiple customer tenants:

### 1. Create Multi-Tenant App Registration

Create a single app registration that will be used across all customer tenants:

```powershell
# In your MSSP tenant
.\Create-MultiTenantApp.ps1 `
    -AppName "DefenderXSOAR-MultiTenant" `
    -TenantId "<mssp-tenant-id>"
```

This creates an app registration with:
- Multi-tenant authentication enabled
- Required API permissions pre-configured
- Certificate-based authentication (recommended)
- Client secret fallback

### 2. Grant Consent in Customer Tenants

For each customer tenant, have the customer admin grant consent:

```powershell
# Customer admin runs this in their tenant
.\Grant-CustomerConsent.ps1 `
    -MultiTenantAppId "<app-id-from-step-1>" `
    -CustomerTenantId "<customer-tenant-id>"
```

### 3. Configure Customer Tenant Settings

Add customer tenant configuration:

```json
{
  "Tenants": [
    {
      "TenantName": "Customer1",
      "TenantId": "customer1-tenant-id",
      "ClientId": "multi-tenant-app-id",
      "ClientSecret": "client-secret-or-cert-thumbprint",
      "SubscriptionId": "customer1-subscription-id",
      "Enabled": true
    }
  ]
}
```

## 📊 Monitoring and Alerting

After deployment, configure monitoring:

### Application Insights

The Function App is pre-configured with Application Insights for:
- **Custom Metrics**: Track worker performance, API calls, enrichment success rate
- **Live Metrics**: Real-time monitoring of function executions
- **Failure Analysis**: Automatic failure detection and alerting
- **Dependency Tracking**: Monitor external API calls and latencies

Access Application Insights:
1. Azure Portal → Resource Group → Application Insights
2. View metrics, logs, and performance data

### Log Analytics Integration

DefenderXSOAR writes to custom tables in your Sentinel workspace:
- **DefenderXSOAR_CL**: Main enrichment results
- **DefenderXSOAR_Entities_CL**: Normalized entity data
- **DefenderXSOAR_Risk_CL**: Risk scoring data
- **DefenderXSOAR_Decisions_CL**: Incident decision recommendations

Sample KQL queries:

```kql
// View recent enrichment results
DefenderXSOAR_CL
| where TimeGenerated > ago(24h)
| summarize count() by Severity_s, RiskScore_d
| render piechart

// Identify high-risk incidents
DefenderXSOAR_CL
| where RiskScore_d > 80
| project TimeGenerated, IncidentId_s, Severity_s, RiskScore_d, Products_s
| order by RiskScore_d desc
```

### Recommended Alerts

Create alerts for:
1. **Failed Authentications**: Alert when API authentication fails
2. **High Error Rate**: Alert when error rate > 10% in 5 minutes
3. **Processing Delays**: Alert when incidents take > 5 minutes to process
4. **Critical Incidents**: Alert on risk score > 90

## 🔧 Configuration Options

### Function App Settings

Key application settings (configured automatically):

| Setting | Description | Default |
|---------|-------------|---------|
| `FUNCTIONS_WORKER_RUNTIME` | Runtime environment | powershell |
| `FUNCTIONS_WORKER_RUNTIME_VERSION` | PowerShell version | 7.2 |
| `KeyVaultName` | Key Vault for secrets | (auto-generated) |
| `SentinelWorkspaceId` | Workspace ID | (from parameter) |
| `MultiTenantAppId` | Multi-tenant app | (optional) |

### Risk Scoring Configuration

Customize risk scoring in `DefenderXSOAR.json`:

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
    }
  }
}
```

### Auto-Action Configuration

Configure automatic incident actions:

```json
{
  "IncidentDecisions": {
    "AutoEscalate": {
      "Enabled": true,
      "MinimumRiskScore": 80,
      "RequiredThreatIntelCount": 3
    },
    "AutoClose": {
      "Enabled": false,
      "MaximumRiskScore": 10
    },
    "AutoMerge": {
      "Enabled": true,
      "SimilarityThreshold": 0.8
    }
  }
}
```

## 🔄 Integration Options

### Logic Apps Integration

DefenderXSOAR can be triggered from Logic Apps for automatic incident enrichment:

1. Deploy the Logic Apps connector (optional):
   ```powershell
   .\Deploy-LogicAppsConnector.ps1
   ```

2. Create a Logic App with Sentinel trigger
3. Add HTTP action to call DefenderXSOAR Function
4. Pass incident data as JSON payload

### Sentinel Automation Rule

Create an automation rule in Sentinel:

1. Navigate to Microsoft Sentinel → Automation
2. Create new automation rule
3. Trigger: When incident is created
4. Condition: Severity is Medium or higher
5. Action: Run playbook → DefenderXSOAR Function

## 📚 Additional Resources

- [Prerequisites Documentation](Documentation/Prerequisites.md)
- [Permissions Reference](Documentation/Permissions.md)
- [Architecture Overview](Documentation/Architecture.md)
- [Troubleshooting Guide](Documentation/Troubleshooting.md)
- [Upgrade Procedures](Documentation/Upgrade.md)

## 🆘 Troubleshooting

### Common Issues

**Issue**: Function App fails to authenticate
- **Solution**: Verify managed identity has required API permissions
- Run: `.\Grant-DefenderXSOARPermissions.ps1` again

**Issue**: Cannot connect to Sentinel workspace
- **Solution**: Verify workspace exists and Function App has Log Analytics Contributor role
- Check: Application Insights logs for detailed error messages

**Issue**: Deployment fails with "Resource already exists"
- **Solution**: Use a different DefenderXSOAR name or deploy to a different resource group
- Or: Delete existing resources and redeploy

**Issue**: Multi-tenant authentication not working
- **Solution**: Ensure customer admin has granted consent in their tenant
- Verify: App registration is configured as multi-tenant

See [Troubleshooting.md](Documentation/Troubleshooting.md) for more solutions.

## 🔐 Security Considerations

1. **Key Vault Access**: Only Function App managed identity has access to Key Vault
2. **TLS 1.2**: All connections enforce TLS 1.2 minimum
3. **HTTPS Only**: Function App only accepts HTTPS traffic
4. **Secret Management**: Never store secrets in code or configuration files
5. **RBAC**: Use role-based access control for all Azure resources
6. **Soft Delete**: Key Vault has soft delete enabled (90-day retention)

## 📝 Post-Deployment Checklist

After deployment, verify:

- [ ] All Azure resources deployed successfully
- [ ] Function App managed identity created
- [ ] API permissions granted and consented
- [ ] Function code deployed
- [ ] Configuration uploaded to Key Vault
- [ ] Test enrichment completed successfully
- [ ] Application Insights receiving telemetry
- [ ] Log Analytics custom tables created
- [ ] Monitoring alerts configured
- [ ] Documentation reviewed

## 🆙 Upgrading

To upgrade an existing DefenderXSOAR deployment:

```powershell
.\Upgrade-DefenderXSOAR.ps1 `
    -FunctionAppName "<your-function-app-name>" `
    -ResourceGroupName "<your-resource-group-name>"
```

See [Upgrade.md](Documentation/Upgrade.md) for detailed upgrade procedures.

## 💰 Cost Estimation

Estimated monthly costs (based on typical usage):

| Resource | SKU | Estimated Cost |
|----------|-----|----------------|
| Function App | Consumption (Y1) | $10-50/month |
| Storage Account | Standard_LRS | $2-5/month |
| Application Insights | Pay-as-you-go | $5-20/month |
| Key Vault | Standard | $3/month |
| Log Analytics | Per GB | $10-50/month (depends on volume) |
| **Total** | | **$30-130/month** |

Premium Function App (EP1): Add ~$180/month

> Note: Costs vary based on incident volume and data retention settings.

## 📄 License

MIT License - See [LICENSE](../../LICENSE) file for details.

## 🙏 Support

For issues, questions, or contributions:
- GitHub Issues: [Report an issue](https://github.com/akefallonitis/defenderc2enrichement/issues)
- Documentation: [Full documentation](../README.md)
- Community: [Discussions](https://github.com/akefallonitis/defenderc2enrichement/discussions)
