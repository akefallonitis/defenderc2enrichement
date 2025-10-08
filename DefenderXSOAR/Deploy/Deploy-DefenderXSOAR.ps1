<#
.SYNOPSIS
    Deploy DefenderXSOAR to Azure environment
.DESCRIPTION
    Deploys DefenderXSOAR solution including required Azure resources and permissions
.PARAMETER SubscriptionId
    Azure subscription ID
.PARAMETER ResourceGroupName
    Resource group name for deployment
.PARAMETER Location
    Azure region for deployment
.PARAMETER WorkspaceName
    Log Analytics workspace name
.PARAMETER CreateAppRegistration
    Whether to create Azure AD app registration
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $false)]
    [string]$Location = "eastus",
    
    [Parameter(Mandatory = $false)]
    [string]$WorkspaceName = "defenderxsoar-workspace",
    
    [Parameter(Mandatory = $false)]
    [bool]$CreateAppRegistration = $true
)

Write-Host @"
╔═══════════════════════════════════════════════════════════════════╗
║              DefenderXSOAR Deployment Script                      ║
╚═══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Check for required modules
Write-Host "`nChecking prerequisites..." -ForegroundColor Yellow

$requiredModules = @('Az.Accounts', 'Az.Resources', 'Az.OperationalInsights')

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "  Installing module: $module" -ForegroundColor Yellow
        Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
    }
    Import-Module $module -Force
    Write-Host "  ✓ $module loaded" -ForegroundColor Green
}

# Connect to Azure
Write-Host "`nConnecting to Azure..." -ForegroundColor Yellow
Connect-AzAccount -SubscriptionId $SubscriptionId

# Set context
Set-AzContext -SubscriptionId $SubscriptionId

# Create Resource Group
Write-Host "`nCreating/Verifying Resource Group..." -ForegroundColor Yellow
$rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue

if (-not $rg) {
    Write-Host "  Creating resource group: $ResourceGroupName" -ForegroundColor Yellow
    $rg = New-AzResourceGroup -Name $ResourceGroupName -Location $Location
    Write-Host "  ✓ Resource group created" -ForegroundColor Green
}
else {
    Write-Host "  ✓ Resource group exists" -ForegroundColor Green
}

# Create Log Analytics Workspace
Write-Host "`nCreating/Verifying Log Analytics Workspace..." -ForegroundColor Yellow
$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName -ErrorAction SilentlyContinue

if (-not $workspace) {
    Write-Host "  Creating workspace: $WorkspaceName" -ForegroundColor Yellow
    $workspace = New-AzOperationalInsightsWorkspace `
        -ResourceGroupName $ResourceGroupName `
        -Name $WorkspaceName `
        -Location $Location `
        -Sku "PerGB2018"
    Write-Host "  ✓ Workspace created" -ForegroundColor Green
}
else {
    Write-Host "  ✓ Workspace exists" -ForegroundColor Green
}

# Get workspace keys
$workspaceKeys = Get-AzOperationalInsightsWorkspaceSharedKey -ResourceGroupName $ResourceGroupName -Name $WorkspaceName
$workspaceId = $workspace.CustomerId

Write-Host "`nWorkspace Configuration:" -ForegroundColor Cyan
Write-Host "  Workspace ID: $workspaceId" -ForegroundColor White
Write-Host "  Primary Key: [REDACTED]" -ForegroundColor White

# Create App Registration if requested
if ($CreateAppRegistration) {
    Write-Host "`nCreating Azure AD App Registration..." -ForegroundColor Yellow
    
    $appName = "DefenderXSOAR-ServicePrincipal"
    
    # Check if Az.Resources module is available for app registration
    if (Get-Command New-AzADApplication -ErrorAction SilentlyContinue) {
        $app = Get-AzADApplication -DisplayName $appName -ErrorAction SilentlyContinue
        
        if (-not $app) {
            Write-Host "  Creating app registration: $appName" -ForegroundColor Yellow
            $app = New-AzADApplication -DisplayName $appName
            
            # Create service principal
            $sp = New-AzADServicePrincipal -ApplicationId $app.AppId
            
            # Create client secret
            $secret = New-AzADAppCredential -ApplicationId $app.AppId -EndDate (Get-Date).AddYears(2)
            
            Write-Host "  ✓ App registration created" -ForegroundColor Green
            Write-Host "`n  Application (Client) ID: $($app.AppId)" -ForegroundColor Cyan
            Write-Host "  Client Secret: $($secret.SecretText)" -ForegroundColor Cyan
            Write-Host "  Object ID: $($app.Id)" -ForegroundColor Cyan
            
            Write-Host "`n  IMPORTANT: Save the Client Secret - it won't be shown again!" -ForegroundColor Red
        }
        else {
            Write-Host "  ✓ App registration already exists" -ForegroundColor Green
            Write-Host "  Application ID: $($app.AppId)" -ForegroundColor Cyan
        }
    }
    else {
        Write-Warning "  Az.Resources module not available for app registration"
        Write-Host "  Please create app registration manually" -ForegroundColor Yellow
    }
}

# Create configuration template
Write-Host "`nCreating configuration template..." -ForegroundColor Yellow

$configPath = Join-Path $PSScriptRoot "..\Config\DefenderXSOAR-Deployed.json"

$config = @{
    Version = "1.0.0"
    Description = "DefenderXSOAR Deployed Configuration"
    Tenants = @(
        @{
            TenantName = "Production"
            TenantId = (Get-AzContext).Tenant.Id
            ClientId = if ($app) { $app.AppId } else { "your-client-id-here" }
            ClientSecret = if ($secret) { $secret.SecretText } else { "your-client-secret-here" }
            SubscriptionId = $SubscriptionId
            Enabled = $true
        }
    )
    LogAnalytics = @{
        Enabled = $true
        WorkspaceId = $workspaceId
        SharedKey = $workspaceKeys.PrimarySharedKey
        CustomTableName = "DefenderXSOAR_CL"
        RetentionDays = 90
    }
} | ConvertTo-Json -Depth 10

$config | Out-File -FilePath $configPath -Encoding UTF8

Write-Host "  ✓ Configuration saved to: $configPath" -ForegroundColor Green

# Summary
Write-Host @"

╔═══════════════════════════════════════════════════════════════════╗
║                    DEPLOYMENT SUMMARY                             ║
╚═══════════════════════════════════════════════════════════════════╝

Resource Group: $ResourceGroupName
Location: $Location
Workspace: $WorkspaceName
Workspace ID: $workspaceId

Next Steps:
1. Run Grant-Permissions.ps1 to assign required API permissions
2. Update the configuration file with your specific settings
3. Test the deployment with Start-DefenderXSOAROrchestration.ps1

Configuration file location:
$configPath

"@ -ForegroundColor Green

Write-Host "Deployment completed successfully!" -ForegroundColor Green
