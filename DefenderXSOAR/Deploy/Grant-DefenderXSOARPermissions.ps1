<#
.SYNOPSIS
    Grant Required API Permissions for DefenderXSOAR
.DESCRIPTION
    Grants all required API permissions to the DefenderXSOAR service principal or managed identity
.PARAMETER ApplicationId
    Application (Client) ID (for app registration)
.PARAMETER TenantId
    Azure AD Tenant ID
.PARAMETER FunctionAppName
    Function App name (for managed identity)
.PARAMETER ResourceGroupName
    Resource Group name (for managed identity)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ApplicationId,
    
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$FunctionAppName,
    
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName
)

Write-Host @"
╔═══════════════════════════════════════════════════════════════════╗
║           DefenderXSOAR Permission Grant Script                   ║
╚═══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Determine if using managed identity or app registration
if ($FunctionAppName -and $ResourceGroupName) {
    Write-Host "`nUsing Function App Managed Identity..." -ForegroundColor Yellow
    
    # Check for required modules
    if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
        Write-Host "Installing Az.Accounts module..." -ForegroundColor Yellow
        Install-Module -Name Az.Accounts -Force -AllowClobber -Scope CurrentUser
    }
    
    Import-Module Az.Accounts -Force
    
    # Connect to Azure if not already connected
    $context = Get-AzContext
    if (-not $context) {
        Connect-AzAccount -TenantId $TenantId
    }
    
    # Get Function App managed identity
    $functionApp = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName
    if (-not $functionApp) {
        Write-Error "Function App '$FunctionAppName' not found in resource group '$ResourceGroupName'"
        exit 1
    }
    
    if (-not $functionApp.Identity -or $functionApp.Identity.Type -ne "SystemAssigned") {
        Write-Error "Function App does not have a system-assigned managed identity enabled"
        exit 1
    }
    
    $principalId = $functionApp.Identity.PrincipalId
    Write-Host "  ✓ Found managed identity: $principalId" -ForegroundColor Green
    $ApplicationId = $principalId
}
elseif ($ApplicationId) {
    Write-Host "`nUsing App Registration: $ApplicationId" -ForegroundColor Yellow
}
else {
    Write-Error "Either ApplicationId or (FunctionAppName and ResourceGroupName) must be provided"
    exit 1
}

# Required API Permissions (Complete list for all Microsoft Defender products)
$requiredPermissions = @{
    "Microsoft Graph" = @{
        AppId = "00000003-0000-0000-c000-000000000000"
        Permissions = @(
            @{ Name = "SecurityEvents.Read.All"; Type = "Application"; Id = "bf394140-e372-4bf9-a898-299cfc7564e5" }
            @{ Name = "SecurityActions.Read.All"; Type = "Application"; Id = "5e0edab9-c148-49d0-b423-ac253e121825" }
            @{ Name = "IdentityRiskEvent.Read.All"; Type = "Application"; Id = "6e472fd1-ad78-48da-a0f0-97ab2c6b769e" }
            @{ Name = "IdentityRiskyUser.Read.All"; Type = "Application"; Id = "dc5007c0-2d7d-4c42-879c-2dab87571379" }
            @{ Name = "Directory.Read.All"; Type = "Application"; Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61" }
            @{ Name = "User.Read.All"; Type = "Application"; Id = "df021288-bdef-4463-88db-98f22de89214" }
            @{ Name = "Device.Read.All"; Type = "Application"; Id = "7438b122-aefc-4978-80ed-43db9fcc7715" }
            @{ Name = "Application.Read.All"; Type = "Application"; Id = "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30" }
            @{ Name = "AuditLog.Read.All"; Type = "Application"; Id = "b0afded3-3588-46d8-8b3d-9842eff778da" }
            @{ Name = "SecurityAlert.Read.All"; Type = "Application"; Id = "45cc0394-e837-488b-a098-1918f48d186c" }
            @{ Name = "ThreatIndicators.Read.All"; Type = "Application"; Id = "197ee4e9-b993-4066-898f-d6aecc55125b" }
        )
    }
    "Microsoft Defender for Endpoint" = @{
        AppId = "fc780465-2017-40d4-a0c5-307022471b92"
        Permissions = @(
            @{ Name = "Machine.Read.All"; Type = "Application"; Id = "ea8291d3-4b9a-44b5-bc3a-6cea3026dc79" }
            @{ Name = "Alert.Read.All"; Type = "Application"; Id = "3b14d7f8-5c27-4d2e-9e67-7b1b6b9f0b3a" }
            @{ Name = "File.Read.All"; Type = "Application"; Id = "7734e8e5-8dde-42fc-b5ae-6eafea078693" }
            @{ Name = "AdvancedQuery.Read.All"; Type = "Application"; Id = "b152f2ba-5d6d-4b0d-8c1e-1e0e4c1c1e0e" }
            @{ Name = "Vulnerability.Read.All"; Type = "Application"; Id = "ea8291d3-4b9a-44b5-bc3a-6cea3026dc79" }
        )
    }
    "Microsoft 365 Defender" = @{
        AppId = "8ee8fdad-f234-4243-8f3b-15c294843740"
        Permissions = @(
            @{ Name = "AdvancedHunting.Read.All"; Type = "Application"; Id = "7734e8e5-8dde-42fc-b5ae-6eafea078693" }
            @{ Name = "Incident.Read.All"; Type = "Application"; Id = "3b14d7f8-5c27-4d2e-9e67-7b1b6b9f0b3a" }
        )
    }
    "Office 365 Management APIs" = @{
        AppId = "c5393580-f805-4401-95e8-94b7a6ef2fc2"
        Permissions = @(
            @{ Name = "ActivityFeed.Read"; Type = "Application"; Id = "594c1fb6-4f81-4475-ae41-0c394909246c" }
            @{ Name = "ServiceHealth.Read"; Type = "Application"; Id = "79c261e0-fe76-4144-aad5-bdc68fbe4037" }
        )
    }
    "Azure Service Management" = @{
        AppId = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
        Permissions = @(
            @{ Name = "user_impersonation"; Type = "Delegated"; Id = "41094075-9dad-400e-a0bd-54e686782033" }
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
