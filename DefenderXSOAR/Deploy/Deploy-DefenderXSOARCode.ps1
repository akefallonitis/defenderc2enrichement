<#
.SYNOPSIS
    Deploy DefenderXSOAR PowerShell code to Azure Function App
.DESCRIPTION
    Packages and deploys all PowerShell modules and functions to the Azure Function App
.PARAMETER FunctionAppName
    Name of the Azure Function App
.PARAMETER ResourceGroupName
    Resource Group containing the Function App
.PARAMETER SourcePath
    Path to DefenderXSOAR source code (default: ..\)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$FunctionAppName,
    
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $false)]
    [string]$SourcePath = ".."
)

Write-Host @"
╔═══════════════════════════════════════════════════════════════════╗
║         DefenderXSOAR Code Deployment Script                      ║
╚═══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Check for required modules
Write-Host "`nChecking prerequisites..." -ForegroundColor Yellow
$requiredModules = @('Az.Accounts', 'Az.Websites')

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

# Verify Function App exists
Write-Host "`nVerifying Function App..." -ForegroundColor Yellow
$functionApp = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName -ErrorAction SilentlyContinue

if (-not $functionApp) {
    Write-Error "Function App '$FunctionAppName' not found in resource group '$ResourceGroupName'"
    exit 1
}

Write-Host "  ✓ Function App found: $FunctionAppName" -ForegroundColor Green

# Prepare deployment package
Write-Host "`nPreparing deployment package..." -ForegroundColor Yellow

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$packageName = "DefenderXSOAR-$timestamp.zip"
$packagePath = Join-Path $env:TEMP $packageName
$tempDir = Join-Path $env:TEMP "DefenderXSOAR-Package-$timestamp"

# Create temp directory
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

# Define what to include
$itemsToCopy = @(
    "Modules",
    "Functions",
    "Config"
)

# Copy items to temp directory
foreach ($item in $itemsToCopy) {
    $sourcePath = Join-Path $SourcePath $item
    $destPath = Join-Path $tempDir $item
    
    if (Test-Path $sourcePath) {
        Copy-Item -Path $sourcePath -Destination $destPath -Recurse -Force
        Write-Host "  ✓ Copied $item" -ForegroundColor Green
    }
    else {
        Write-Warning "  ⚠ $item not found at $sourcePath"
    }
}

# Create host.json if not exists
$hostJsonPath = Join-Path $tempDir "host.json"
if (-not (Test-Path $hostJsonPath)) {
    $hostJson = @{
        version = "2.0"
        extensionBundle = @{
            id = "Microsoft.Azure.Functions.ExtensionBundle"
            version = "[3.*, 4.0.0)"
        }
        logging = @{
            applicationInsights = @{
                samplingSettings = @{
                    isEnabled = $true
                    maxTelemetryItemsPerSecond = 20
                }
            }
        }
        functionTimeout = "00:05:00"
    } | ConvertTo-Json -Depth 10
    
    $hostJson | Out-File -FilePath $hostJsonPath -Encoding UTF8
    Write-Host "  ✓ Created host.json" -ForegroundColor Green
}

# Create profile.ps1 if not exists
$profilePath = Join-Path $tempDir "profile.ps1"
if (-not (Test-Path $profilePath)) {
    $profile = @"
# Azure Functions profile.ps1
# This profile is loaded on every cold start
# Import common modules for faster function execution
if (`$env:MSI_SECRET) {
    Disable-AzContextAutosave -Scope Process | Out-Null
}

# Import DefenderXSOAR modules
`$ModulePath = Join-Path `$PSScriptRoot "Modules"
if (Test-Path `$ModulePath) {
    Get-ChildItem -Path `$ModulePath -Filter "*.psm1" -Recurse | ForEach-Object {
        Import-Module `$_.FullName -Force
    }
}
"@
    
    $profile | Out-File -FilePath $profilePath -Encoding UTF8
    Write-Host "  ✓ Created profile.ps1" -ForegroundColor Green
}

# Create requirements.psd1 for PowerShell dependencies
$requirementsPath = Join-Path $tempDir "requirements.psd1"
if (-not (Test-Path $requirementsPath)) {
    $requirements = @"
@{
    'Az.Accounts' = '2.*'
    'Az.KeyVault' = '4.*'
    'Az.OperationalInsights' = '3.*'
}
"@
    
    $requirements | Out-File -FilePath $requirementsPath -Encoding UTF8
    Write-Host "  ✓ Created requirements.psd1" -ForegroundColor Green
}

# Create HTTP triggered function wrapper
$httpFunctionDir = Join-Path $tempDir "Start-DefenderXSOAROrchestration"
New-Item -ItemType Directory -Path $httpFunctionDir -Force | Out-Null

# Create function.json
$functionJson = @{
    bindings = @(
        @{
            authLevel = "function"
            type = "httpTrigger"
            direction = "in"
            name = "Request"
            methods = @("post")
        }
        @{
            type = "http"
            direction = "out"
            name = "Response"
        }
    )
} | ConvertTo-Json -Depth 10

$functionJson | Out-File -FilePath (Join-Path $httpFunctionDir "function.json") -Encoding UTF8

# Create run.ps1
$runPs1 = @"
using namespace System.Net

param(`$Request, `$TriggerMetadata)

Write-Host "DefenderXSOAR Orchestration triggered at `$(Get-Date)"

try {
    # Parse request body
    `$requestBody = `$Request.Body
    
    # Extract parameters
    `$incidentId = `$requestBody.IncidentId
    `$incidentArmId = `$requestBody.IncidentArmId
    `$entities = `$requestBody.Entities
    `$tenantId = `$requestBody.TenantId
    `$products = `$requestBody.Products
    
    if (-not `$products) {
        `$products = @('MDE', 'MDC', 'MCAS', 'MDI', 'MDO', 'EntraID')
    }
    
    # Load configuration from Key Vault
    `$kvName = `$env:KeyVaultName
    if (`$kvName) {
        try {
            `$configSecret = Get-AzKeyVaultSecret -VaultName `$kvName -Name "DefenderXSOAR-Configuration" -AsPlainText -ErrorAction Stop
            `$config = `$configSecret | ConvertFrom-Json
        }
        catch {
            Write-Warning "Could not load configuration from Key Vault: `$_"
            `$config = `$null
        }
    }
    
    # Import and execute orchestration
    `$FunctionsPath = Join-Path `$PSScriptRoot ".." "Functions"
    `$orchestrationScript = Join-Path `$FunctionsPath "Start-DefenderXSOAROrchestration.ps1"
    
    if (Test-Path `$orchestrationScript) {
        `$result = & `$orchestrationScript ``
            -ConfigPath `$null ``
            -IncidentId `$incidentId ``
            -IncidentArmId `$incidentArmId ``
            -Entities `$entities ``
            -TenantId `$tenantId ``
            -Products `$products
        
        `$status = [HttpStatusCode]::OK
        `$body = `$result | ConvertTo-Json -Depth 10
    }
    else {
        throw "Orchestration script not found at `$orchestrationScript"
    }
}
catch {
    Write-Error "DefenderXSOAR execution failed: `$_"
    `$status = [HttpStatusCode]::InternalServerError
    `$body = @{
        Error = `$_.Exception.Message
        StackTrace = `$_.ScriptStackTrace
    } | ConvertTo-Json
}

Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = `$status
    Body = `$body
    ContentType = "application/json"
})

Write-Host "DefenderXSOAR Orchestration completed at `$(Get-Date)"
"@

$runPs1 | Out-File -FilePath (Join-Path $httpFunctionDir "run.ps1") -Encoding UTF8
Write-Host "  ✓ Created HTTP trigger function" -ForegroundColor Green

# Create deployment package
Write-Host "`nCreating deployment package..." -ForegroundColor Yellow
Compress-Archive -Path "$tempDir\*" -DestinationPath $packagePath -Force
Write-Host "  ✓ Package created: $packagePath" -ForegroundColor Green

$packageSize = (Get-Item $packagePath).Length / 1MB
Write-Host "  Package size: $([math]::Round($packageSize, 2)) MB" -ForegroundColor Cyan

# Deploy to Function App
Write-Host "`nDeploying to Function App..." -ForegroundColor Yellow
Write-Host "  This may take 2-3 minutes..." -ForegroundColor Gray

try {
    Publish-AzWebApp `
        -ResourceGroupName $ResourceGroupName `
        -Name $FunctionAppName `
        -ArchivePath $packagePath `
        -Force `
        -ErrorAction Stop
    
    Write-Host "  ✓ Deployment successful" -ForegroundColor Green
}
catch {
    Write-Error "Deployment failed: $_"
    exit 1
}

# Cleanup temp files
Write-Host "`nCleaning up temporary files..." -ForegroundColor Yellow
Remove-Item -Path $tempDir -Recurse -Force
Remove-Item -Path $packagePath -Force
Write-Host "  ✓ Cleanup completed" -ForegroundColor Green

# Restart Function App to ensure changes take effect
Write-Host "`nRestarting Function App..." -ForegroundColor Yellow
Restart-AzWebApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName | Out-Null
Write-Host "  ✓ Function App restarted" -ForegroundColor Green

# Wait for app to be ready
Write-Host "`nWaiting for Function App to be ready..." -ForegroundColor Yellow
Start-Sleep -Seconds 30

# Get Function App URL
$functionAppUrl = "https://$FunctionAppName.azurewebsites.net"
$functionKeys = Invoke-AzResourceAction `
    -ResourceGroupName $ResourceGroupName `
    -ResourceType "Microsoft.Web/sites/functions" `
    -ResourceName "$FunctionAppName/Start-DefenderXSOAROrchestration" `
    -Action "listkeys" `
    -ApiVersion "2022-03-01" `
    -Force

$functionUrl = "$functionAppUrl/api/Start-DefenderXSOAROrchestration?code=$($functionKeys.default)"

# Summary
Write-Host @"

╔═══════════════════════════════════════════════════════════════════╗
║                  DEPLOYMENT COMPLETED                             ║
╚═══════════════════════════════════════════════════════════════════╝

Function App: $FunctionAppName
Resource Group: $ResourceGroupName
Package Size: $([math]::Round($packageSize, 2)) MB
Deployment Time: $(Get-Date)

Function Endpoint:
$functionAppUrl/api/Start-DefenderXSOAROrchestration

Function Key:
$($functionKeys.default)

Complete URL (for testing):
$functionUrl

Next Steps:
1. Verify deployment with Test-DefenderXSOAR.ps1
2. Configure Sentinel automation rules to call this endpoint
3. Test with a sample incident

To test the function:
`$body = @{
    IncidentId = "TEST-001"
    Entities = @(@{ Type = "Account"; Name = "test@domain.com" })
    TenantId = "your-tenant-id"
} | ConvertTo-Json

Invoke-RestMethod -Uri "$functionUrl" ``
    -Method Post ``
    -Body `$body ``
    -ContentType "application/json"

"@ -ForegroundColor Green

Write-Host "Code deployment completed successfully!" -ForegroundColor Green
