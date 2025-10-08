<#
.SYNOPSIS
    Test DefenderXSOAR deployment
.DESCRIPTION
    Validates deployment by testing connectivity, authentication, and processing
.PARAMETER FunctionAppName
    Name of the deployed Function App
.PARAMETER ResourceGroupName
    Resource Group containing the Function App
.PARAMETER SkipAuthentication
    Skip authentication tests (useful if permissions not yet granted)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$FunctionAppName,
    
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipAuthentication
)

Write-Host @"
╔═══════════════════════════════════════════════════════════════════╗
║            DefenderXSOAR Deployment Test Script                   ║
╚═══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Test results tracking
$testResults = @{
    Total = 0
    Passed = 0
    Failed = 0
    Skipped = 0
    Tests = @()
}

function Add-TestResult {
    param(
        [string]$TestName,
        [string]$Status,
        [string]$Message
    )
    
    $testResults.Total++
    
    switch ($Status) {
        "Passed" { 
            $testResults.Passed++
            Write-Host "  ✓ $TestName" -ForegroundColor Green
        }
        "Failed" {
            $testResults.Failed++
            Write-Host "  ✗ $TestName" -ForegroundColor Red
            if ($Message) {
                Write-Host "    $Message" -ForegroundColor Gray
            }
        }
        "Skipped" {
            $testResults.Skipped++
            Write-Host "  ⊘ $TestName (Skipped)" -ForegroundColor Yellow
        }
    }
    
    $testResults.Tests += @{
        Name = $TestName
        Status = $Status
        Message = $Message
        Timestamp = Get-Date
    }
}

# Check for required modules
Write-Host "`nChecking prerequisites..." -ForegroundColor Yellow
$requiredModules = @('Az.Accounts', 'Az.Websites', 'Az.KeyVault', 'Az.OperationalInsights')

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "  Installing module: $module" -ForegroundColor Yellow
        Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
    }
    Import-Module $module -Force
}

Write-Host "  ✓ Prerequisites checked" -ForegroundColor Green

# Connect to Azure
Write-Host "`nConnecting to Azure..." -ForegroundColor Yellow
$context = Get-AzContext
if (-not $context) {
    Connect-AzAccount
}
Write-Host "  ✓ Connected to Azure" -ForegroundColor Green

# Test 1: Function App Exists
Write-Host "`n[Test 1] Validating Function App..." -ForegroundColor Yellow
try {
    $functionApp = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName -ErrorAction Stop
    Add-TestResult -TestName "Function App Exists" -Status "Passed"
}
catch {
    Add-TestResult -TestName "Function App Exists" -Status "Failed" -Message $_.Exception.Message
    Write-Host "`nCannot continue without Function App. Exiting." -ForegroundColor Red
    exit 1
}

# Test 2: Managed Identity
Write-Host "`n[Test 2] Validating Managed Identity..." -ForegroundColor Yellow
if ($functionApp.Identity -and $functionApp.Identity.Type -eq "SystemAssigned") {
    Add-TestResult -TestName "Managed Identity Enabled" -Status "Passed"
    $principalId = $functionApp.Identity.PrincipalId
    Write-Host "    Principal ID: $principalId" -ForegroundColor Cyan
}
else {
    Add-TestResult -TestName "Managed Identity Enabled" -Status "Failed" -Message "System-assigned managed identity not enabled"
}

# Test 3: Application Settings
Write-Host "`n[Test 3] Validating Application Settings..." -ForegroundColor Yellow
$appSettings = $functionApp.SiteConfig.AppSettings
$requiredSettings = @("AzureWebJobsStorage", "FUNCTIONS_WORKER_RUNTIME", "KeyVaultName", "SentinelWorkspaceId")

$allSettingsPresent = $true
foreach ($setting in $requiredSettings) {
    $settingValue = $appSettings | Where-Object { $_.Name -eq $setting }
    if ($settingValue) {
        Write-Host "    ✓ $setting configured" -ForegroundColor Green
    }
    else {
        Write-Host "    ✗ $setting missing" -ForegroundColor Red
        $allSettingsPresent = $false
    }
}

if ($allSettingsPresent) {
    Add-TestResult -TestName "Application Settings" -Status "Passed"
}
else {
    Add-TestResult -TestName "Application Settings" -Status "Failed" -Message "Some required settings are missing"
}

# Test 4: Key Vault Access
Write-Host "`n[Test 4] Validating Key Vault Access..." -ForegroundColor Yellow
$kvSetting = $appSettings | Where-Object { $_.Name -eq "KeyVaultName" }
if ($kvSetting) {
    $keyVaultName = $kvSetting.Value
    try {
        $keyVault = Get-AzKeyVault -VaultName $keyVaultName -ErrorAction Stop
        Add-TestResult -TestName "Key Vault Exists" -Status "Passed"
        
        # Check if managed identity has access
        if ($principalId) {
            $roleAssignment = Get-AzRoleAssignment -ObjectId $principalId -Scope $keyVault.ResourceId -ErrorAction SilentlyContinue
            if ($roleAssignment) {
                Add-TestResult -TestName "Key Vault Access" -Status "Passed"
            }
            else {
                Add-TestResult -TestName "Key Vault Access" -Status "Failed" -Message "Managed identity does not have Key Vault access"
            }
        }
    }
    catch {
        Add-TestResult -TestName "Key Vault Exists" -Status "Failed" -Message $_.Exception.Message
    }
}
else {
    Add-TestResult -TestName "Key Vault Access" -Status "Skipped" -Message "KeyVaultName not configured"
}

# Test 5: Application Insights
Write-Host "`n[Test 5] Validating Application Insights..." -ForegroundColor Yellow
$aiSetting = $appSettings | Where-Object { $_.Name -eq "APPINSIGHTS_INSTRUMENTATIONKEY" }
if ($aiSetting -and $aiSetting.Value) {
    Add-TestResult -TestName "Application Insights Configured" -Status "Passed"
}
else {
    Add-TestResult -TestName "Application Insights Configured" -Status "Failed" -Message "Application Insights not configured"
}

# Test 6: Log Analytics Workspace
Write-Host "`n[Test 6] Validating Log Analytics Integration..." -ForegroundColor Yellow
$workspaceIdSetting = $appSettings | Where-Object { $_.Name -eq "SentinelWorkspaceId" }
if ($workspaceIdSetting -and $workspaceIdSetting.Value) {
    $workspaceId = $workspaceIdSetting.Value
    Write-Host "    Workspace ID: $workspaceId" -ForegroundColor Cyan
    Add-TestResult -TestName "Log Analytics Configured" -Status "Passed"
}
else {
    Add-TestResult -TestName "Log Analytics Configured" -Status "Failed" -Message "Sentinel Workspace ID not configured"
}

# Test 7: Function App Running
Write-Host "`n[Test 7] Validating Function App Status..." -ForegroundColor Yellow
if ($functionApp.State -eq "Running") {
    Add-TestResult -TestName "Function App Running" -Status "Passed"
}
else {
    Add-TestResult -TestName "Function App Running" -Status "Failed" -Message "Function App state: $($functionApp.State)"
}

# Test 8: HTTPS Only
Write-Host "`n[Test 8] Validating Security Settings..." -ForegroundColor Yellow
if ($functionApp.HttpsOnly) {
    Add-TestResult -TestName "HTTPS Only Enabled" -Status "Passed"
}
else {
    Add-TestResult -TestName "HTTPS Only Enabled" -Status "Failed" -Message "HTTPS Only is not enabled"
}

# Test 9: TLS Version
if ($functionApp.SiteConfig.MinTlsVersion -eq "1.2") {
    Add-TestResult -TestName "TLS 1.2 Minimum" -Status "Passed"
}
else {
    Add-TestResult -TestName "TLS 1.2 Minimum" -Status "Failed" -Message "Minimum TLS version: $($functionApp.SiteConfig.MinTlsVersion)"
}

# Test 10: Authentication Tests (if not skipped)
if (-not $SkipAuthentication) {
    Write-Host "`n[Test 10] Testing API Authentication..." -ForegroundColor Yellow
    
    # This would require the actual function code to be deployed
    # For now, we'll mark as skipped if code not deployed
    Add-TestResult -TestName "API Authentication" -Status "Skipped" -Message "Requires function code deployment"
}
else {
    Write-Host "`n[Test 10] Skipping authentication tests..." -ForegroundColor Yellow
    Add-TestResult -TestName "API Authentication" -Status "Skipped" -Message "Skipped by parameter"
}

# Test 11: Function Code Deployment
Write-Host "`n[Test 11] Checking Function Code..." -ForegroundColor Yellow
# Check if any functions are deployed
$functions = Get-AzWebAppSlot -ResourceGroupName $ResourceGroupName -Name $FunctionAppName -Slot "production" -ErrorAction SilentlyContinue

if ($functions) {
    Add-TestResult -TestName "Function Code Deployed" -Status "Passed"
}
else {
    Add-TestResult -TestName "Function Code Deployed" -Status "Skipped" -Message "No functions detected (deploy code next)"
}

# Test Summary
Write-Host @"

╔═══════════════════════════════════════════════════════════════════╗
║                        TEST SUMMARY                               ║
╚═══════════════════════════════════════════════════════════════════╝

Total Tests: $($testResults.Total)
✓ Passed:    $($testResults.Passed)
✗ Failed:    $($testResults.Failed)
⊘ Skipped:   $($testResults.Skipped)

"@ -ForegroundColor Cyan

# Show failed tests
if ($testResults.Failed -gt 0) {
    Write-Host "Failed Tests:" -ForegroundColor Red
    foreach ($test in $testResults.Tests | Where-Object { $_.Status -eq "Failed" }) {
        Write-Host "  ✗ $($test.Name)" -ForegroundColor Red
        if ($test.Message) {
            Write-Host "    $($test.Message)" -ForegroundColor Gray
        }
    }
    Write-Host ""
}

# Recommendations
Write-Host "Recommendations:" -ForegroundColor Yellow

$recommendations = @()

if ($testResults.Tests | Where-Object { $_.Name -eq "Managed Identity Enabled" -and $_.Status -eq "Failed" }) {
    $recommendations += "Enable system-assigned managed identity on the Function App"
}

if ($testResults.Tests | Where-Object { $_.Name -eq "Key Vault Access" -and $_.Status -eq "Failed" }) {
    $recommendations += "Grant 'Key Vault Secrets User' role to Function App managed identity"
}

if ($testResults.Tests | Where-Object { $_.Name -eq "Function Code Deployed" -and $_.Status -ne "Passed" }) {
    $recommendations += "Deploy function code using Deploy-DefenderXSOARCode.ps1"
}

if ($testResults.Tests | Where-Object { $_.Name -eq "API Authentication" -and $_.Status -eq "Skipped" }) {
    $recommendations += "Grant API permissions using Grant-DefenderXSOARPermissions.ps1"
}

if ($recommendations.Count -eq 0) {
    Write-Host "  ✓ All critical tests passed! Deployment looks good." -ForegroundColor Green
}
else {
    foreach ($rec in $recommendations) {
        Write-Host "  • $rec" -ForegroundColor Yellow
    }
}

Write-Host ""

# Overall status
if ($testResults.Failed -eq 0) {
    Write-Host "✓ Deployment validation completed successfully!" -ForegroundColor Green
    exit 0
}
else {
    Write-Host "✗ Deployment validation found issues. Please review and fix." -ForegroundColor Red
    exit 1
}
