using namespace System.Net

<#
.SYNOPSIS
    DefenderXSOAR Webhook - Microsoft Sentinel Incident Webhook Handler
.DESCRIPTION
    Handles incoming webhooks from Microsoft Sentinel automation rules
    Automatically triggers DefenderXSOAR enrichment for new incidents
#>

param($Request, $TriggerMetadata)

Write-Host "DefenderXSOAR Webhook received at $(Get-Date)"

try {
    # Parse Sentinel incident data from webhook
    $sentinelIncident = $Request.Body
    
    Write-Host "Processing Sentinel incident: $($sentinelIncident.properties.incidentNumber)"
    Write-Host "  Severity: $($sentinelIncident.properties.severity)"
    Write-Host "  Status: $($sentinelIncident.properties.status)"
    Write-Host "  Title: $($sentinelIncident.properties.title)"
    
    # Validate severity threshold
    $minSeverity = $env:MinimumSeverity ?? "Medium"
    $severityLevels = @{
        "Informational" = 0
        "Low" = 1
        "Medium" = 2
        "High" = 3
        "Critical" = 4
    }
    
    $incidentSeverity = $sentinelIncident.properties.severity
    if ($severityLevels[$incidentSeverity] -lt $severityLevels[$minSeverity]) {
        Write-Host "Incident severity ($incidentSeverity) below threshold ($minSeverity). Skipping."
        
        $status = [HttpStatusCode]::OK
        $body = @{
            Message = "Incident severity below threshold"
            Processed = $false
        } | ConvertTo-Json
        
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = $status
            Body = $body
            ContentType = "application/json"
        })
        return
    }
    
    # Extract entities from incident
    $entities = @()
    if ($sentinelIncident.properties.relatedEntities) {
        $entities = $sentinelIncident.properties.relatedEntities
    }
    
    Write-Host "  Entities: $($entities.Count)"
    
    # Extract tenant information
    $tenantId = if ($sentinelIncident.properties.tenantId) { 
        $sentinelIncident.properties.tenantId 
    } else { 
        $env:TenantId 
    }
    
    # Prepare orchestration parameters
    $orchestrationParams = @{
        IncidentId = $sentinelIncident.properties.incidentNumber
        IncidentArmId = $sentinelIncident.id
        Entities = $entities
        TenantId = $tenantId
        Products = @('MDE', 'MDC', 'MCAS', 'MDI', 'MDO', 'EntraID')
    }
    
    # Import and execute orchestration
    $FunctionsPath = Join-Path $PSScriptRoot ".." ".."
    $orchestrationScript = Join-Path $FunctionsPath "Start-DefenderXSOAROrchestration.ps1"
    
    if (Test-Path $orchestrationScript) {
        Write-Host "Invoking DefenderXSOAR orchestration..."
        
        $result = & $orchestrationScript `
            -ConfigPath $null `
            -IncidentId $orchestrationParams.IncidentId `
            -IncidentArmId $orchestrationParams.IncidentArmId `
            -Entities $orchestrationParams.Entities `
            -TenantId $orchestrationParams.TenantId `
            -Products $orchestrationParams.Products
        
        $status = [HttpStatusCode]::OK
        $body = @{
            Message = "DefenderXSOAR orchestration completed successfully"
            Processed = $true
            Result = $result
        } | ConvertTo-Json -Depth 10
    }
    else {
        throw "Orchestration script not found at $orchestrationScript"
    }
}
catch {
    Write-Error "DefenderXSOAR webhook processing failed: $_"
    $status = [HttpStatusCode]::InternalServerError
    $body = @{
        Error = $_.Exception.Message
        StackTrace = $_.ScriptStackTrace
        Processed = $false
    } | ConvertTo-Json
}

Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = $status
    Body = $body
    ContentType = "application/json"
})

Write-Host "DefenderXSOAR Webhook processing completed at $(Get-Date)"
