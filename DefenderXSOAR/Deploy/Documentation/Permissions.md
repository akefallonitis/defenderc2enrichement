# DefenderXSOAR - API Permissions Reference

This document provides a comprehensive reference for all API permissions required by DefenderXSOAR.

## Overview

DefenderXSOAR requires permissions to access multiple Microsoft security APIs. This document details each permission, its purpose, and how to grant it.

## Authentication Models

### Model 1: Managed Identity (Recommended for Single Tenant)
- Function App uses system-assigned managed identity
- No credential management required
- Automatic token rotation
- Azure RBAC for permission management

### Model 2: Multi-Tenant App Registration (For MSSP)
- Single app registration across multiple customer tenants
- Certificate or client secret authentication
- Requires admin consent in each tenant
- Centralized credential management

## Required API Permissions

### Microsoft Graph API

**Resource App ID**: `00000003-0000-0000-c000-000000000000`

| Permission | Type | ID | Purpose | Risk Level |
|------------|------|----|---------|-----------| 
| SecurityEvents.Read.All | Application | bf394140-e372-4bf9-a898-299cfc7564e5 | Read security events from Sentinel | Low |
| SecurityActions.Read.All | Application | 5e0edab9-c148-49d0-b423-ac253e121825 | Read security actions and recommendations | Low |
| IdentityRiskEvent.Read.All | Application | 6e472fd1-ad78-48da-a0f0-97ab2c6b769e | Read identity risk events (Entra ID Protection) | Medium |
| IdentityRiskyUser.Read.All | Application | dc5007c0-2d7d-4c42-879c-2dab87571379 | Read risky users information | Medium |
| Directory.Read.All | Application | 7ab1d382-f21e-4acd-a863-ba3e13f7da61 | Read directory data (users, groups, devices) | Medium |
| User.Read.All | Application | df021288-bdef-4463-88db-98f22de89214 | Read all user profiles | Medium |
| Device.Read.All | Application | 7438b122-aefc-4978-80ed-43db9fcc7715 | Read device information | Low |
| Application.Read.All | Application | 9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30 | Read application registrations | Low |
| AuditLog.Read.All | Application | b0afded3-3588-46d8-8b3d-9842eff778da | Read audit logs | Medium |
| SecurityAlert.Read.All | Application | 45cc0394-e837-488b-a098-1918f48d186c | Read security alerts | Low |
| ThreatIndicators.Read.All | Application | 197ee4e9-b993-4066-898f-d6aecc55125b | Read threat intelligence indicators | Low |

**Notes:**
- All permissions are **Application** type (not Delegated)
- Requires **Global Administrator** consent
- Read-only permissions minimize security risk

### Microsoft Defender for Endpoint API

**Resource App ID**: `fc780465-2017-40d4-a0c5-307022471b92`

| Permission | Type | ID | Purpose | Risk Level |
|------------|------|----|---------|-----------| 
| Machine.Read.All | Application | ea8291d3-4b9a-44b5-bc3a-6cea3026dc79 | Read device/machine information | Low |
| Alert.Read.All | Application | 3b14d7f8-5c27-4d2e-9e67-7b1b6b9f0b3a | Read MDE alerts | Low |
| File.Read.All | Application | 7734e8e5-8dde-42fc-b5ae-6eafea078693 | Read file information and hashes | Low |
| AdvancedQuery.Read.All | Application | b152f2ba-5d6d-4b0d-8c1e-1e0e4c1c1e0e | Run advanced hunting queries | Low |
| Vulnerability.Read.All | Application | ea8291d3-4b9a-44b5-bc3a-6cea3026dc79 | Read vulnerability information | Low |

**API Endpoint**: `https://api.securitycenter.microsoft.com`

**Notes:**
- Required for device analysis and threat hunting
- Available with MDE Plan 1 or Plan 2 license

### Microsoft 365 Defender API

**Resource App ID**: `8ee8fdad-f234-4243-8f3b-15c294843740`

| Permission | Type | ID | Purpose | Risk Level |
|------------|------|----|---------|-----------| 
| AdvancedHunting.Read.All | Application | 7734e8e5-8dde-42fc-b5ae-6eafea078693 | Run advanced hunting across M365 | Low |
| Incident.Read.All | Application | 3b14d7f8-5c27-4d2e-9e67-7b1b6b9f0b3a | Read unified incidents | Low |

**API Endpoint**: `https://api.security.microsoft.com`

**Notes:**
- Unified API for all Microsoft 365 Defender products
- Requires Microsoft 365 Defender or E5 license

### Office 365 Management API

**Resource App ID**: `c5393580-f805-4401-95e8-94b7a6ef2fc2`

| Permission | Type | ID | Purpose | Risk Level |
|------------|------|----|---------|-----------| 
| ActivityFeed.Read | Application | 594c1fb6-4f81-4475-ae41-0c394909246c | Read Office 365 activity feeds (MDO) | Low |
| ServiceHealth.Read | Application | 79c261e0-fe76-4144-aad5-bdc68fbe4037 | Read service health information | Low |

**API Endpoint**: `https://manage.office.com`

**Notes:**
- Required for Microsoft Defender for Office 365 (MDO)
- Provides email security and phishing data

### Azure Service Management API

**Resource App ID**: `797f4846-ba00-4fd7-ba43-dac1f8f63013`

| Permission | Type | ID | Purpose | Risk Level |
|------------|------|----|---------|-----------| 
| user_impersonation | Delegated | 41094075-9dad-400e-a0bd-54e686782033 | Access Azure Resource Manager | Medium |

**API Endpoint**: `https://management.azure.com`

**Notes:**
- Required for Microsoft Defender for Cloud (MDC)
- Accesses Azure security posture and compliance data

## Azure RBAC Permissions

In addition to API permissions, DefenderXSOAR requires Azure RBAC roles:

### On Sentinel Workspace

| Role | Scope | Purpose |
|------|-------|---------|
| Log Analytics Contributor | Workspace | Write custom tables to Log Analytics |
| Microsoft Sentinel Reader | Workspace | Read incident data |

Grant with:
```powershell
# Get workspace resource ID
$workspaceId = "/subscriptions/{subscription-id}/resourceGroups/{rg-name}/providers/Microsoft.OperationalInsights/workspaces/{workspace-name}"

# Get Function App managed identity principal ID
$principalId = (Get-AzWebApp -ResourceGroupName "DefenderXSOAR-RG" -Name "defenderxsoar-func").Identity.PrincipalId

# Grant Log Analytics Contributor
New-AzRoleAssignment -ObjectId $principalId -RoleDefinitionName "Log Analytics Contributor" -Scope $workspaceId

# Grant Sentinel Reader
New-AzRoleAssignment -ObjectId $principalId -RoleDefinitionName "Microsoft Sentinel Reader" -Scope $workspaceId
```

### On Subscription (for MDC)

| Role | Scope | Purpose |
|------|-------|---------|
| Security Reader | Subscription | Read Azure Defender recommendations |
| Reader | Subscription | Read Azure resources |

Grant with:
```powershell
$subscriptionId = "/subscriptions/{subscription-id}"
$principalId = (Get-AzWebApp -ResourceGroupName "DefenderXSOAR-RG" -Name "defenderxsoar-func").Identity.PrincipalId

New-AzRoleAssignment -ObjectId $principalId -RoleDefinitionName "Security Reader" -Scope $subscriptionId
New-AzRoleAssignment -ObjectId $principalId -RoleDefinitionName "Reader" -Scope $subscriptionId
```

### On Key Vault

| Role | Scope | Purpose |
|------|-------|---------|
| Key Vault Secrets User | Key Vault | Read secrets for configuration |

Grant with:
```powershell
$keyVaultId = "/subscriptions/{subscription-id}/resourceGroups/{rg-name}/providers/Microsoft.KeyVault/vaults/{kv-name}"
$principalId = (Get-AzWebApp -ResourceGroupName "DefenderXSOAR-RG" -Name "defenderxsoar-func").Identity.PrincipalId

New-AzRoleAssignment -ObjectId $principalId -RoleDefinitionName "Key Vault Secrets User" -Scope $keyVaultId
```

## Granting Permissions

### Method 1: Using Grant-DefenderXSOARPermissions.ps1 (Recommended)

For Function App with managed identity:
```powershell
.\Grant-DefenderXSOARPermissions.ps1 `
    -FunctionAppName "defenderxsoar-func-12345" `
    -ResourceGroupName "DefenderXSOAR-RG" `
    -TenantId "your-tenant-id"
```

For App Registration:
```powershell
.\Grant-DefenderXSOARPermissions.ps1 `
    -ApplicationId "your-app-id" `
    -TenantId "your-tenant-id"
```

### Method 2: Azure Portal (Manual)

1. Navigate to **Azure Portal** → **Azure Active Directory**
2. Go to **App registrations** or **Enterprise applications**
3. Find your application
4. Click **API permissions**
5. Click **Add a permission**
6. Select the API (Microsoft Graph, WindowsDefenderATP, etc.)
7. Select **Application permissions**
8. Search for and add each required permission
9. Click **Grant admin consent for [Tenant]**
10. Verify all permissions show "Granted" status

### Method 3: Microsoft Graph PowerShell SDK

```powershell
# Install Microsoft Graph PowerShell SDK
Install-Module Microsoft.Graph -Scope CurrentUser

# Connect with admin privileges
Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All"

# Get your service principal
$sp = Get-MgServicePrincipal -Filter "displayName eq 'DefenderXSOAR-ServicePrincipal'"

# Get Microsoft Graph service principal
$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

# Grant SecurityEvents.Read.All permission
$appRole = $graphSp.AppRoles | Where-Object { $_.Value -eq "SecurityEvents.Read.All" }
New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id -AppRoleId $appRole.Id -ResourceId $graphSp.Id

# Repeat for each permission...
```

### Method 4: Azure CLI

```bash
# Login
az login

# Get app ID
APP_ID="your-app-id"

# Add Microsoft Graph permissions
az ad app permission add --id $APP_ID --api 00000003-0000-0000-c000-000000000000 --api-permissions \
  bf394140-e372-4bf9-a898-299cfc7564e5=Role \
  5e0edab9-c148-49d0-b423-ac253e121825=Role \
  6e472fd1-ad78-48da-a0f0-97ab2c6b769e=Role

# Add MDE permissions
az ad app permission add --id $APP_ID --api fc780465-2017-40d4-a0c5-307022471b92 --api-permissions \
  ea8291d3-4b9a-44b5-bc3a-6cea3026dc79=Role \
  3b14d7f8-5c27-4d2e-9e67-7b1b6b9f0b3a=Role

# Grant admin consent
az ad app permission admin-consent --id $APP_ID
```

## Multi-Tenant MSSP Configuration

### Creating Multi-Tenant App Registration

```powershell
# Create app registration
$app = New-AzADApplication -DisplayName "DefenderXSOAR-MultiTenant" `
    -SignInAudience "AzureADMultipleOrgs"

# Create service principal
$sp = New-AzADServicePrincipal -ApplicationId $app.AppId

# Add permissions (use Method 3 above)

# Create certificate for authentication (recommended)
$cert = New-SelfSignedCertificate -CertStoreLocation "cert:\CurrentUser\My" `
    -Subject "CN=DefenderXSOAR" `
    -KeySpec KeyExchange `
    -NotAfter (Get-Date).AddYears(2)

# Upload certificate to app registration
$keyCredential = @{
    Type = "AsymmetricX509Cert"
    Usage = "Verify"
    Key = $cert.RawData
}
Update-AzADApplication -ApplicationId $app.AppId -KeyCredentials $keyCredential
```

### Granting Consent in Customer Tenants

Each customer tenant admin must grant consent:

```powershell
# Customer admin runs this
$appId = "your-multitenant-app-id"
$tenantId = "customer-tenant-id"

# Generate consent URL
$consentUrl = "https://login.microsoftonline.com/$tenantId/adminconsent?client_id=$appId"

# Open in browser
Start-Process $consentUrl

# Or use Azure CLI
az ad app permission admin-consent --id $appId --tenant $tenantId
```

## Special Cases

### Microsoft Defender for Cloud Apps (MCAS)

MCAS uses a different authentication model:

1. Log in to MCAS portal: `https://portal.cloudappsecurity.com`
2. Navigate to **Settings** → **Security extensions** → **API tokens**
3. Click **Generate new token**
4. Provide a name: "DefenderXSOAR"
5. Select permissions: **Read** only
6. Copy the token immediately (shown only once)
7. Store in Key Vault:

```powershell
$token = "your-mcas-api-token"
$keyVaultName = "defenderxsoar-kv-12345"
$secureToken = ConvertTo-SecureString -String $token -AsPlainText -Force
Set-AzKeyVaultSecret -VaultName $keyVaultName -Name "MCAS-APIToken" -SecretValue $secureToken
```

### Microsoft Defender for Identity (MDI)

MDI uses the same Microsoft Graph permissions. No additional setup required beyond Graph API permissions.

## Permission Verification

### Testing API Access

```powershell
# Test Microsoft Graph
$token = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com"
$headers = @{ Authorization = "Bearer $($token.Token)" }
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/security/alerts" -Headers $headers

# Test MDE
$token = Get-AzAccessToken -ResourceUrl "https://api.securitycenter.microsoft.com"
$headers = @{ Authorization = "Bearer $($token.Token)" }
Invoke-RestMethod -Uri "https://api.securitycenter.microsoft.com/api/machines" -Headers $headers
```

### Common Issues

**Issue**: "Insufficient privileges to complete the operation"
- **Cause**: Admin consent not granted
- **Solution**: Have Global Admin grant consent

**Issue**: "Application not found in directory"
- **Cause**: Service principal not created
- **Solution**: Create service principal: `New-AzADServicePrincipal -ApplicationId $appId`

**Issue**: "Token request failed"
- **Cause**: Incorrect resource URL
- **Solution**: Verify resource URL matches API (graph.microsoft.com, api.securitycenter.microsoft.com, etc.)

## Security Best Practices

1. **Use Managed Identity** when possible (single tenant)
2. **Use Certificates** over client secrets (multi-tenant)
3. **Rotate secrets** every 90 days minimum
4. **Monitor token usage** in Application Insights
5. **Audit permission changes** in Azure AD logs
6. **Use least privilege** - don't grant write permissions
7. **Separate environments** - different apps for dev/prod
8. **Review regularly** - quarterly permission audits

## Permission Audit

Regularly audit granted permissions:

```powershell
# Get app permissions
$appId = "your-app-id"
$sp = Get-AzADServicePrincipal -ApplicationId $appId

# Get assigned app roles
$assignments = Get-AzRoleAssignment -ObjectId $sp.Id

# Display
$assignments | Select-Object RoleDefinitionName, Scope | Format-Table
```

## Removing Permissions

If you need to remove permissions:

```powershell
# Remove API permission
Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -AppRoleAssignmentId $assignmentId

# Remove RBAC role
Remove-AzRoleAssignment -ObjectId $principalId -RoleDefinitionName "Security Reader" -Scope $scope
```

## Support

For permission-related issues:
- Review [Troubleshooting Guide](Troubleshooting.md)
- Check Azure AD audit logs
- Verify license requirements
- Contact Microsoft Support for API access issues
