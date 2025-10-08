# DefenderXSOAR Deployment Guide

Complete guide for deploying DefenderXSOAR to Azure.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Deployment Options](#deployment-options)
- [One-Click Deployment](#one-click-deployment)
- [Manual Deployment](#manual-deployment)
- [Multi-Tenant Configuration](#multi-tenant-configuration)
- [Post-Deployment Steps](#post-deployment-steps)
- [Validation](#validation)
- [Troubleshooting](#troubleshooting)

## Prerequisites

Before deploying DefenderXSOAR, ensure you have:

### Azure Resources

- ✅ Active Azure subscription
- ✅ Microsoft Sentinel workspace
- ✅ Contributor or Owner role on the resource group
- ✅ Global Administrator or Application Administrator role (for app registration)

### Required Licenses

- ✅ Microsoft 365 E5 or Microsoft 365 E5 Security
- ✅ Azure Active Directory Premium P2
- ✅ Microsoft Defender for Endpoint
- ✅ Microsoft Defender for Cloud (Standard tier)
- ✅ Microsoft Defender for Cloud Apps
- ✅ Microsoft Defender for Identity
- ✅ Microsoft Defender for Office 365

### Tools

- ✅ Azure PowerShell Az module (7.0+)
- ✅ PowerShell 7.2 or later

**Installation:**
```powershell
# Install Azure PowerShell
Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force

# Verify installation
Get-Module -Name Az -ListAvailable
```

## Deployment Options

DefenderXSOAR can be deployed using:

1. **One-Click ARM Template** (Recommended) - Deploy via Azure Portal
2. **PowerShell Script** - Automated deployment with pre/post steps
3. **Azure CLI** - Command-line deployment
4. **Azure DevOps Pipeline** - CI/CD deployment

## One-Click Deployment

The fastest way to deploy DefenderXSOAR.

### Step 1: Click Deploy to Azure

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fakefallonitis%2Fdefenderc2enrichement%2Fmain%2FDefenderXSOAR%2FDeploy%2Fdefenderxsoar-deploy.json)

### Step 2: Fill in Parameters

**Required Parameters:**

| Parameter | Description | Example |
|-----------|-------------|---------|
| DefenderXSOARName | Name prefix for resources | `DefenderXSOAR` |
| SentinelWorkspaceName | Sentinel workspace name | `my-sentinel-ws` |
| SentinelResourceGroupName | Resource group with Sentinel | `Sentinel-RG` |
| Location | Azure region | `eastus` |

**Optional Parameters:**

| Parameter | Description | Default |
|-----------|-------------|---------|
| FunctionAppSku | Function App pricing tier | `Y1` (Consumption) |
| MultiTenantAppId | App registration ID for MSSP | (empty) |
| MultiTenantAppSecret | App registration secret | (empty) |

### Step 3: Review + Create

1. Review the parameters
2. Check the Terms and Conditions
3. Click **Create**

**Deployment Time:** ~5-7 minutes

### What Gets Deployed

- ✅ Azure Function App (PowerShell 7.2 runtime)
- ✅ Storage Account (Standard_LRS)
- ✅ Key Vault (RBAC-enabled, soft delete)
- ✅ Application Insights (linked to Sentinel)
- ✅ App Service Plan (Consumption or Premium)
- ✅ System-Assigned Managed Identity

## Manual Deployment

For advanced scenarios or customization.

### Step 1: Clone Repository

```powershell
git clone https://github.com/akefallonitis/defenderc2enrichement.git
cd defenderc2enrichement/DefenderXSOAR
```

### Step 2: Connect to Azure

```powershell
Connect-AzAccount
Set-AzContext -SubscriptionId "your-subscription-id"
```

### Step 3: Create Resource Group

```powershell
$resourceGroup = "DefenderXSOAR-RG"
$location = "eastus"

New-AzResourceGroup -Name $resourceGroup -Location $location
```

### Step 4: Deploy ARM Template

```powershell
$deploymentParams = @{
    DefenderXSOARName = "DefenderXSOAR"
    SentinelWorkspaceName = "my-sentinel-ws"
    SentinelResourceGroupName = "Sentinel-RG"
    Location = $location
    FunctionAppSku = "Y1"
}

New-AzResourceGroupDeployment `
    -ResourceGroupName $resourceGroup `
    -TemplateFile ".\Deploy\defenderxsoar-deploy.json" `
    -TemplateParameterObject $deploymentParams `
    -Verbose
```

### Step 5: Deploy Code

```powershell
.\Deploy\Deploy-DefenderXSOARCode.ps1 `
    -FunctionAppName "defenderxsoar-func-xxxxx" `
    -ResourceGroupName $resourceGroup
```

## Multi-Tenant Configuration

For MSSP environments serving multiple customers.

### Step 1: Create Multi-Tenant App Registration

```powershell
.\Deploy\Create-MultiTenantApp.ps1 `
    -AppName "DefenderXSOAR-MultiTenant" `
    -TenantId "your-mssp-tenant-id" `
    -UseCertificate
```

**Output:**
- Application ID
- Certificate thumbprint (if using certificate auth)
- Required permissions list

### Step 2: Grant Admin Consent

For each customer tenant:

1. Navigate to Azure Portal
2. Go to **Azure Active Directory** > **App registrations**
3. Find **DefenderXSOAR-MultiTenant**
4. Click **API permissions**
5. Click **Grant admin consent**

Or use the consent URL:

```
https://login.microsoftonline.com/{customer-tenant-id}/adminconsent?client_id={app-id}
```

### Step 3: Configure Tenant Settings

```powershell
.\Deploy\Configure-DefenderXSOAR.ps1 `
    -FunctionAppName "defenderxsoar-func-xxxxx" `
    -ResourceGroupName $resourceGroup `
    -AddTenant `
    -TenantName "Customer1" `
    -TenantId "customer1-tenant-id" `
    -ClientId $appId `
    -ClientSecret $secret
```

## Post-Deployment Steps

### Step 1: Grant API Permissions

```powershell
.\Deploy\Grant-DefenderXSOARPermissions.ps1 `
    -TenantId "your-tenant-id" `
    -FunctionAppName "defenderxsoar-func-xxxxx" `
    -ResourceGroupName $resourceGroup
```

Follow the output instructions to grant permissions in Azure Portal.

### Step 2: Configure RBAC Roles

```powershell
# Get Function App principal ID
$functionApp = Get-AzWebApp -ResourceGroupName $resourceGroup -Name $functionAppName
$principalId = $functionApp.Identity.PrincipalId

# Assign Security Reader role
New-AzRoleAssignment `
    -ObjectId $principalId `
    -RoleDefinitionName "Security Reader" `
    -Scope "/subscriptions/$subscriptionId"

# Assign Log Analytics Reader role
$workspaceId = "/subscriptions/$subscriptionId/resourceGroups/$sentinelRG/providers/Microsoft.OperationalInsights/workspaces/$workspaceName"
New-AzRoleAssignment `
    -ObjectId $principalId `
    -RoleDefinitionName "Microsoft Sentinel Contributor" `
    -Scope $workspaceId
```

### Step 3: Configure Sentinel Automation

Create an automation rule in Sentinel:

1. Navigate to Microsoft Sentinel
2. Go to **Automation** > **Automation rules**
3. Click **+ Create** > **Automation rule**
4. Configure:
   - **Name**: DefenderXSOAR Auto-Enrichment
   - **Trigger**: When incident is created
   - **Conditions**: Severity equals High or Critical
   - **Actions**: Run playbook > DefenderXSOAR Webhook
5. Save

### Step 4: Test Deployment

```powershell
.\Deploy\Test-DefenderXSOAR.ps1 `
    -FunctionAppName "defenderxsoar-func-xxxxx" `
    -ResourceGroupName $resourceGroup
```

Expected output:
```
✓ Function App is running
✓ Managed identity is configured
✓ Key Vault access verified
✓ Application Insights connected
✓ API connectivity test passed
✓ Entity normalization test passed
```

## Validation

### Check Deployment Status

```powershell
# Check Function App status
$functionApp = Get-AzWebApp -ResourceGroupName $resourceGroup -Name $functionAppName
$functionApp.State  # Should be "Running"

# Check Application Insights
$ai = Get-AzApplicationInsights -ResourceGroupName $resourceGroup -Name $appInsightsName
$ai.ProvisioningState  # Should be "Succeeded"

# Check Key Vault
$kv = Get-AzKeyVault -VaultName $keyVaultName
$kv.VaultUri  # Should return URI
```

### Test HTTP Trigger

```powershell
# Get function URL
$functionKey = (Get-AzWebAppFunctionKey -ResourceGroupName $resourceGroup -Name $functionAppName -FunctionName "DefenderXSOAROrchestrator" -KeyName "default").Value
$functionUrl = "https://$functionAppName.azurewebsites.net/api/DefenderXSOAROrchestrator?code=$functionKey"

# Test invocation
$body = @{
    IncidentId = "12345"
    TenantId = "your-tenant-id"
    Entities = @()
    Products = @('MDE', 'EntraID')
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri $functionUrl -Method Post -Body $body -ContentType "application/json"
$response
```

### Check Application Insights

```powershell
# View recent traces
$query = "traces | where timestamp > ago(1h) | order by timestamp desc | limit 50"
$results = Invoke-AzOperationalInsightsQuery -WorkspaceId $aiWorkspaceId -Query $query
$results.Results
```

## Troubleshooting

### Issue: Deployment Fails

**Symptoms:**
- ARM template deployment returns error
- Resources not created

**Solutions:**
1. Check resource name uniqueness (storage account, Key Vault)
2. Verify subscription quota
3. Check RBAC permissions
4. Review deployment logs:

```powershell
Get-AzResourceGroupDeploymentOperation -ResourceGroupName $resourceGroup -DeploymentName $deploymentName
```

### Issue: Function App Not Starting

**Symptoms:**
- Function App shows "Stopped" status
- HTTP triggers return 503

**Solutions:**
1. Check Function App logs:
```powershell
Get-AzWebAppLog -ResourceGroupName $resourceGroup -Name $functionAppName
```

2. Verify storage account connection
3. Check Application Settings
4. Restart Function App:
```powershell
Restart-AzWebApp -ResourceGroupName $resourceGroup -Name $functionAppName
```

### Issue: API Permission Denied

**Symptoms:**
- HTTP 401 Unauthorized
- HTTP 403 Forbidden
- "Insufficient privileges" error

**Solutions:**
1. Verify API permissions granted
2. Wait 10-15 minutes after granting consent
3. Check admin consent status:
```powershell
Get-AzADServicePrincipal -ApplicationId $appId | Select-Object -ExpandProperty AppRole
```

### Issue: Key Vault Access Denied

**Symptoms:**
- "Access denied to Key Vault" error
- Cannot read secrets

**Solutions:**
1. Grant managed identity access:
```powershell
Set-AzKeyVaultAccessPolicy `
    -VaultName $keyVaultName `
    -ObjectId $principalId `
    -PermissionsToSecrets Get,List
```

2. Or use RBAC (recommended):
```powershell
New-AzRoleAssignment `
    -ObjectId $principalId `
    -RoleDefinitionName "Key Vault Secrets User" `
    -Scope $keyVaultId
```

## Cost Estimation

### Consumption Plan (Y1)

| Resource | Monthly Cost |
|----------|--------------|
| Function App | $0 (1M free executions) |
| Storage Account | $5-10 |
| Application Insights | $10-50 |
| Key Vault | $5 |
| **Total** | **$20-65/month** |

### Premium Plan (EP1)

| Resource | Monthly Cost |
|----------|--------------|
| Function App (EP1) | $200 |
| Storage Account | $10 |
| Application Insights | $50-100 |
| Key Vault | $5 |
| **Total** | **$265-315/month** |

## Next Steps

After successful deployment:

1. 📖 Review [Configuration Guide](Configuration.md)
2. 🔐 Review [Permissions Guide](Permissions.md)
3. 🏗️ Review [Architecture Documentation](Architecture.md)
4. 🧪 Create test incidents in Sentinel
5. 📊 Monitor Application Insights

## Support

- 📧 Open an issue on [GitHub](https://github.com/akefallonitis/defenderc2enrichement/issues)
- 📖 Review [Troubleshooting Guide](Troubleshooting.md)
- 📚 Check [API Reference](API-Reference.md)
