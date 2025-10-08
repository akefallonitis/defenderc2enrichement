<#
.SYNOPSIS
    Configure DefenderXSOAR post-deployment settings
.DESCRIPTION
    Uploads configuration to Key Vault and sets up tenant-specific settings
.PARAMETER FunctionAppName
    Name of the deployed Function App
.PARAMETER ResourceGroupName
    Resource Group containing the Function App
.PARAMETER ConfigFilePath
    Path to DefenderXSOAR configuration JSON file
.PARAMETER KeyVaultName
    Name of Key Vault (auto-detected if not provided)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$FunctionAppName,
    
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigFilePath = "..\Config\DefenderXSOAR.json",
    
    [Parameter(Mandatory = $false)]
    [string]$KeyVaultName
)

Write-Host @"
╔═══════════════════════════════════════════════════════════════════╗
║         DefenderXSOAR Configuration Script                        ║
╚═══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Check for required modules
Write-Host "`nChecking prerequisites..." -ForegroundColor Yellow
$requiredModules = @('Az.Accounts', 'Az.Websites', 'Az.KeyVault')

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "  Installing module: $module" -ForegroundColor Yellow
        Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
    }
    Import-Module $module -Force
    Write-Host "  ✓ $module loaded" -ForegroundColor Green
}

# Connect to Azure if not already connected
$context = Get-AzContext
if (-not $context) {
    Write-Host "`nConnecting to Azure..." -ForegroundColor Yellow
    Connect-AzAccount
}

Write-Host "  ✓ Connected to Azure" -ForegroundColor Green

# Get Function App
Write-Host "`nRetrieving Function App information..." -ForegroundColor Yellow
$functionApp = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName -ErrorAction SilentlyContinue

if (-not $functionApp) {
    Write-Error "Function App '$FunctionAppName' not found in resource group '$ResourceGroupName'"
    exit 1
}

Write-Host "  ✓ Function App found: $FunctionAppName" -ForegroundColor Green

# Get Key Vault name from app settings if not provided
if (-not $KeyVaultName) {
    $appSettings = $functionApp.SiteConfig.AppSettings
    $kvSetting = $appSettings | Where-Object { $_.Name -eq "KeyVaultName" }
    if ($kvSetting) {
        $KeyVaultName = $kvSetting.Value
        Write-Host "  ✓ Key Vault detected: $KeyVaultName" -ForegroundColor Green
    }
    else {
        Write-Error "KeyVaultName not found in Function App settings. Please provide it manually."
        exit 1
    }
}

# Verify Key Vault exists
$keyVault = Get-AzKeyVault -VaultName $KeyVaultName -ErrorAction SilentlyContinue
if (-not $keyVault) {
    Write-Error "Key Vault '$KeyVaultName' not found"
    exit 1
}

Write-Host "  ✓ Key Vault validated: $KeyVaultName" -ForegroundColor Green

# Load configuration file
Write-Host "`nLoading configuration file..." -ForegroundColor Yellow
if (-not (Test-Path $ConfigFilePath)) {
    Write-Error "Configuration file not found: $ConfigFilePath"
    exit 1
}

$config = Get-Content $ConfigFilePath -Raw | ConvertFrom-Json
Write-Host "  ✓ Configuration loaded" -ForegroundColor Green

# Validate configuration
Write-Host "`nValidating configuration..." -ForegroundColor Yellow

$validationErrors = @()

if (-not $config.Tenants -or $config.Tenants.Count -eq 0) {
    $validationErrors += "No tenants configured"
}

if (-not $config.LogAnalytics) {
    $validationErrors += "LogAnalytics section missing"
}

if (-not $config.Products) {
    $validationErrors += "Products section missing"
}

if ($validationErrors.Count -gt 0) {
    Write-Host "`nConfiguration validation failed:" -ForegroundColor Red
    foreach ($error in $validationErrors) {
        Write-Host "  ✗ $error" -ForegroundColor Red
    }
    exit 1
}

Write-Host "  ✓ Configuration validated" -ForegroundColor Green

# Upload sensitive configuration to Key Vault
Write-Host "`nUploading sensitive configuration to Key Vault..." -ForegroundColor Yellow

foreach ($tenant in $config.Tenants) {
    $tenantName = $tenant.TenantName
    
    Write-Host "  Processing tenant: $tenantName" -ForegroundColor Cyan
    
    # Store tenant credentials
    if ($tenant.ClientSecret) {
        $secretName = "DefenderXSOAR-$tenantName-ClientSecret"
        $secureSecret = ConvertTo-SecureString -String $tenant.ClientSecret -AsPlainText -Force
        Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $secretName -SecretValue $secureSecret | Out-Null
        Write-Host "    ✓ Client secret stored" -ForegroundColor Green
        
        # Remove from config object
        $tenant.ClientSecret = "[STORED_IN_KEYVAULT]"
    }
    
    # Store MCAS token if present
    if ($tenant.MCASToken) {
        $secretName = "DefenderXSOAR-$tenantName-MCASToken"
        $secureSecret = ConvertTo-SecureString -String $tenant.MCASToken -AsPlainText -Force
        Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $secretName -SecretValue $secureSecret | Out-Null
        Write-Host "    ✓ MCAS token stored" -ForegroundColor Green
        
        # Remove from config object
        $tenant.MCASToken = "[STORED_IN_KEYVAULT]"
    }
}

# Store Log Analytics shared key
if ($config.LogAnalytics.SharedKey) {
    $secretName = "DefenderXSOAR-LogAnalytics-SharedKey"
    $secureSecret = ConvertTo-SecureString -String $config.LogAnalytics.SharedKey -AsPlainText -Force
    Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $secretName -SecretValue $secureSecret | Out-Null
    Write-Host "  ✓ Log Analytics shared key stored" -ForegroundColor Green
    
    # Remove from config object
    $config.LogAnalytics.SharedKey = "[STORED_IN_KEYVAULT]"
}

# Store sanitized configuration as secret
$sanitizedConfig = $config | ConvertTo-Json -Depth 10
$secureConfig = ConvertTo-SecureString -String $sanitizedConfig -AsPlainText -Force
Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name "DefenderXSOAR-Configuration" -SecretValue $secureConfig | Out-Null
Write-Host "  ✓ Configuration stored in Key Vault" -ForegroundColor Green

# Update Function App settings
Write-Host "`nUpdating Function App settings..." -ForegroundColor Yellow

$newSettings = @{
    "DefenderXSOAR_ConfigVersion" = $config.Version
    "DefenderXSOAR_ConfigUpdated" = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
}

foreach ($key in $newSettings.Keys) {
    Set-AzWebApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName -AppSettings @{ $key = $newSettings[$key] } | Out-Null
}

Write-Host "  ✓ Function App settings updated" -ForegroundColor Green

# Grant Function App access to Key Vault
Write-Host "`nConfiguring Key Vault access..." -ForegroundColor Yellow

$functionAppIdentity = $functionApp.Identity.PrincipalId

if ($functionAppIdentity) {
    # Grant Key Vault Secrets User role
    $kvScope = $keyVault.ResourceId
    $roleAssignment = Get-AzRoleAssignment -ObjectId $functionAppIdentity -RoleDefinitionName "Key Vault Secrets User" -Scope $kvScope -ErrorAction SilentlyContinue
    
    if (-not $roleAssignment) {
        New-AzRoleAssignment -ObjectId $functionAppIdentity -RoleDefinitionName "Key Vault Secrets User" -Scope $kvScope | Out-Null
        Write-Host "  ✓ Key Vault access granted" -ForegroundColor Green
    }
    else {
        Write-Host "  ✓ Key Vault access already configured" -ForegroundColor Green
    }
}
else {
    Write-Warning "Function App does not have a managed identity. Please enable it manually."
}

# Configure Log Analytics access
Write-Host "`nConfiguring Log Analytics access..." -ForegroundColor Yellow

$workspaceId = $config.LogAnalytics.WorkspaceId

if ($workspaceId -and $functionAppIdentity) {
    # Note: Actual workspace access would require the full resource ID
    Write-Host "  ℹ Log Analytics workspace ID configured: $workspaceId" -ForegroundColor Cyan
    Write-Host "  ℹ Ensure Function App has 'Log Analytics Contributor' role on workspace" -ForegroundColor Yellow
}

# Summary
Write-Host @"

╔═══════════════════════════════════════════════════════════════════╗
║                   CONFIGURATION SUMMARY                           ║
╚═══════════════════════════════════════════════════════════════════╝

Function App: $FunctionAppName
Resource Group: $ResourceGroupName
Key Vault: $KeyVaultName

Configuration Status:
✓ Sensitive data stored in Key Vault
✓ Configuration uploaded
✓ Function App settings updated
✓ Key Vault access configured

Tenants Configured: $($config.Tenants.Count)
"@ -ForegroundColor Green

foreach ($tenant in $config.Tenants) {
    Write-Host "  - $($tenant.TenantName) (Enabled: $($tenant.Enabled))" -ForegroundColor Cyan
}

Write-Host @"

Products Enabled:
"@ -ForegroundColor Green

foreach ($product in $config.Products.PSObject.Properties) {
    $status = if ($product.Value.Enabled) { "✓" } else { "✗" }
    Write-Host "  $status $($product.Name) (Priority: $($product.Value.Priority))" -ForegroundColor Cyan
}

Write-Host @"

Next Steps:
1. Verify API permissions are granted (run Grant-DefenderXSOARPermissions.ps1)
2. Deploy function code (run Deploy-DefenderXSOARCode.ps1)
3. Test the deployment (run Test-DefenderXSOAR.ps1)

"@ -ForegroundColor Yellow

Write-Host "Configuration completed successfully!" -ForegroundColor Green
