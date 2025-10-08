using namespace System.Net

<#
.SYNOPSIS
    DefenderXSOAR Orchestrator - Main HTTP Trigger Function
.DESCRIPTION
    Main entry point for DefenderXSOAR orchestration via HTTP trigger
    Supports direct invocation and Sentinel webhook integration
#>

param($Request, $TriggerMetadata)

Write-Host "DefenderXSOAR Orchestration triggered at $(Get-Date)"

try {
    # Parse request body
    $requestBody = $Request.Body
    
    # Extract parameters
    $incidentId = $requestBody.IncidentId
    $incidentArmId = $requestBody.IncidentArmId
    $entities = $requestBody.Entities
    $tenantId = $requestBody.TenantId
    $products = $requestBody.Products
    
    if (-not $products) {
        $products = @('MDE', 'MDC', 'MCAS', 'MDI', 'MDO', 'EntraID')
    }
    
    # Load configuration from Key Vault or environment variables
    $config = $null
    $kvName = $env:KeyVaultName
    if ($kvName) {
        try {
            $configSecret = Get-AzKeyVaultSecret -VaultName $kvName -Name "DefenderXSOAR-Configuration" -AsPlainText -ErrorAction Stop
            $config = $configSecret | ConvertFrom-Json
        }
        catch {
            Write-Warning "Could not load configuration from Key Vault: $_"
            $config = $null
        }
    }
    
    # Import and execute orchestration
    $FunctionsPath = Join-Path $PSScriptRoot ".." ".."
    $orchestrationScript = Join-Path $FunctionsPath "Start-DefenderXSOAROrchestration.ps1"
    
    if (Test-Path $orchestrationScript) {
        $result = & $orchestrationScript `
            -ConfigPath $null `
            -IncidentId $incidentId `
            -IncidentArmId $incidentArmId `
            -Entities $entities `
            -TenantId $tenantId `
            -Products $products
        
        $status = [HttpStatusCode]::OK
        $body = $result | ConvertTo-Json -Depth 10
    }
    else {
        throw "Orchestration script not found at $orchestrationScript"
    }
}
catch {
    Write-Error "DefenderXSOAR execution failed: $_"
    $status = [HttpStatusCode]::InternalServerError
    $body = @{
        Error = $_.Exception.Message
        StackTrace = $_.ScriptStackTrace
    } | ConvertTo-Json
}

Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = $status
    Body = $body
    ContentType = "application/json"
})

Write-Host "DefenderXSOAR Orchestration completed at $(Get-Date)"
