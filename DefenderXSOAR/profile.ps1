# Azure Functions profile.ps1
#
# This profile.ps1 will get executed every "cold start" of your Function App.
# "cold start" occurs when:
#
# * A Function App starts up for the very first time
# * A Function App starts up after being de-allocated due to inactivity
#
# You can define helper functions, run commands, or specify environment variables
# NOTE: any variables defined that are not environment variables will get reset after the first execution

# Authenticate with Azure PowerShell using MSI.
# Remove this if you are not planning on using MSI or Azure PowerShell.
if ($env:MSI_SECRET) {
    Disable-AzContextAutosave -Scope Process | Out-Null
    Connect-AzAccount -Identity
}

# Uncomment the next line to enable legacy AzureRm alias in Azure PowerShell.
# Enable-AzureRmAlias

# You can also define functions or aliases that can be referenced in any of your PowerShell functions.

# Import DefenderXSOAR modules on startup
$ModulesPath = Join-Path $PSScriptRoot "Modules"

if (Test-Path $ModulesPath) {
    Write-Host "Loading DefenderXSOAR modules..."
    
    # Import Common modules
    $commonModules = @(
        'AuthenticationHelper.psm1',
        'EntityNormalizer.psm1',
        'DataTableManager.psm1',
        'CrossCorrelationEngine.psm1'
    )
    
    foreach ($module in $commonModules) {
        $modulePath = Join-Path $ModulesPath "Common" $module
        if (Test-Path $modulePath) {
            Import-Module $modulePath -Force -ErrorAction SilentlyContinue
        }
    }
    
    # Import Brain module
    $brainModule = Join-Path $ModulesPath "DefenderXSOARBrain.psm1"
    if (Test-Path $brainModule) {
        Import-Module $brainModule -Force -ErrorAction SilentlyContinue
    }
    
    Write-Host "DefenderXSOAR modules loaded successfully"
}

Write-Host "DefenderXSOAR profile loaded at $(Get-Date)"
