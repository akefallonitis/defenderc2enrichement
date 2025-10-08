<#
.SYNOPSIS
    Grant Required API Permissions for DefenderXSOAR
.DESCRIPTION
    Grants all required API permissions to the DefenderXSOAR service principal
.PARAMETER ApplicationId
    Application (Client) ID
.PARAMETER TenantId
    Azure AD Tenant ID
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ApplicationId,
    
    [Parameter(Mandatory = $true)]
    [string]$TenantId
)

Write-Host @"
╔═══════════════════════════════════════════════════════════════════╗
║           DefenderXSOAR Permission Grant Script                   ║
╚═══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Required API Permissions
$requiredPermissions = @{
    "Microsoft Graph" = @{
        AppId = "00000003-0000-0000-c000-000000000000"
        Permissions = @(
            @{ Name = "SecurityEvents.Read.All"; Type = "Application" }
            @{ Name = "SecurityAlert.Read.All"; Type = "Application" }
            @{ Name = "IdentityRiskEvent.Read.All"; Type = "Application" }
            @{ Name = "IdentityRiskyUser.Read.All"; Type = "Application" }
            @{ Name = "User.Read.All"; Type = "Application" }
            @{ Name = "AuditLog.Read.All"; Type = "Application" }
            @{ Name = "Directory.Read.All"; Type = "Application" }
            @{ Name = "SecurityActions.Read.All"; Type = "Application" }
            @{ Name = "ThreatIndicators.Read.All"; Type = "Application" }
        )
    }
    "Microsoft Defender ATP" = @{
        AppId = "fc780465-2017-40d4-a0c5-307022471b92"
        Permissions = @(
            @{ Name = "Machine.Read.All"; Type = "Application" }
            @{ Name = "Alert.Read.All"; Type = "Application" }
            @{ Name = "File.Read.All"; Type = "Application" }
            @{ Name = "AdvancedQuery.Read.All"; Type = "Application" }
            @{ Name = "Vulnerability.Read.All"; Type = "Application" }
        )
    }
    "Azure Service Management" = @{
        AppId = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
        Permissions = @(
            @{ Name = "user_impersonation"; Type = "Delegated" }
        )
    }
}

Write-Host "`nRequired API Permissions for DefenderXSOAR:" -ForegroundColor Yellow
Write-Host "Application ID: $ApplicationId" -ForegroundColor Cyan
Write-Host "Tenant ID: $TenantId`n" -ForegroundColor Cyan

foreach ($api in $requiredPermissions.Keys) {
    Write-Host "API: $api" -ForegroundColor Green
    $apiInfo = $requiredPermissions[$api]
    Write-Host "  Resource App ID: $($apiInfo.AppId)" -ForegroundColor Gray
    
    foreach ($permission in $apiInfo.Permissions) {
        Write-Host "  - $($permission.Name) ($($permission.Type))" -ForegroundColor White
    }
    Write-Host ""
}

Write-Host @"
╔═══════════════════════════════════════════════════════════════════╗
║                    MANUAL STEPS REQUIRED                          ║
╚═══════════════════════════════════════════════════════════════════╝

To grant these permissions, follow these steps:

1. Navigate to Azure Portal (https://portal.azure.com)
2. Go to Azure Active Directory > App registrations
3. Find your app: DefenderXSOAR-ServicePrincipal
4. Click on "API permissions"
5. Click "Add a permission"

For Microsoft Graph:
  - Select "Microsoft Graph"
  - Select "Application permissions"
  - Add each permission listed above
  
For Microsoft Defender ATP:
  - Select "APIs my organization uses"
  - Search for "WindowsDefenderATP"
  - Select "Application permissions"
  - Add each permission listed above

For Azure Service Management:
  - Select "Azure Service Management"
  - Select "Delegated permissions"
  - Add user_impersonation

6. After adding all permissions, click "Grant admin consent for [Tenant]"
7. Verify all permissions show "Granted" status

Alternative - PowerShell Method:
Run the following commands to grant permissions programmatically:

# Install Microsoft Graph PowerShell SDK
Install-Module Microsoft.Graph -Scope CurrentUser

# Connect to Microsoft Graph
Connect-MgGraph -TenantId "$TenantId" -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All"

# Grant permissions (requires Global Administrator)
# [Commands would be generated based on your app ID]

"@ -ForegroundColor Yellow

# Generate Azure CLI commands
Write-Host @"
╔═══════════════════════════════════════════════════════════════════╗
║                   AZURE CLI COMMANDS                              ║
╚═══════════════════════════════════════════════════════════════════╝

You can also use Azure CLI to grant permissions:

# Login to Azure CLI
az login --tenant $TenantId

# Add Microsoft Graph permissions
"@ -ForegroundColor Cyan

$graphPermissions = $requiredPermissions["Microsoft Graph"].Permissions | ForEach-Object { $_.Name }
Write-Host "az ad app permission add --id $ApplicationId --api 00000003-0000-0000-c000-000000000000 --api-permissions $($graphPermissions -join ' ')" -ForegroundColor Gray

Write-Host "`n# Add Microsoft Defender ATP permissions" -ForegroundColor Cyan
$mdePermissions = $requiredPermissions["Microsoft Defender ATP"].Permissions | ForEach-Object { $_.Name }
Write-Host "az ad app permission add --id $ApplicationId --api fc780465-2017-40d4-a0c5-307022471b92 --api-permissions $($mdePermissions -join ' ')" -ForegroundColor Gray

Write-Host "`n# Grant admin consent" -ForegroundColor Cyan
Write-Host "az ad app permission admin-consent --id $ApplicationId" -ForegroundColor Gray

Write-Host @"

╔═══════════════════════════════════════════════════════════════════╗
║                   ADDITIONAL REQUIREMENTS                         ║
╚═══════════════════════════════════════════════════════════════════╝

For Microsoft Defender for Cloud Apps (MCAS):
  - Generate API token from MCAS portal
  - Settings > Security extensions > API tokens
  - Create new token with "Read" permissions
  - Add to configuration file

For Azure RBAC:
  - Assign "Security Reader" role to the service principal
  - Assign "Log Analytics Reader" role for workspace access
  
Commands:
az role assignment create --assignee $ApplicationId --role "Security Reader" --scope /subscriptions/{subscription-id}
az role assignment create --assignee $ApplicationId --role "Log Analytics Reader" --scope /subscriptions/{subscription-id}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{workspace}

"@ -ForegroundColor Yellow

Write-Host "Permission grant information generated successfully!" -ForegroundColor Green
Write-Host "Please complete the manual steps above to finalize the setup.`n" -ForegroundColor Yellow
