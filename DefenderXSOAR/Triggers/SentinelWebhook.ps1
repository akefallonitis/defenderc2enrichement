<#
.SYNOPSIS
    Microsoft Sentinel Webhook Trigger for DefenderXSOAR
.DESCRIPTION
    Azure Function webhook that automatically triggers DefenderXSOAR enrichment when Sentinel incidents are created
.NOTES
    This script is designed to run as an Azure Function with HTTP trigger
#>

using namespace System.Net

# Input bindings are passed in via param block
param($Request, $TriggerMetadata)

# Write to the Azure Functions log stream
Write-Host "DefenderXSOAR Sentinel Webhook triggered"

# Initialize response
$statusCode = [HttpStatusCode]::OK
$body = @{
    Status = "Success"
    Message = "DefenderXSOAR enrichment initiated"
}

try {
    # Parse the incident data from Sentinel
    $incident = $Request.Body
    
    if (-not $incident) {
        throw "No incident data received"
    }
    
    Write-Host "Processing incident: $($incident.properties.incidentNumber)"
    
    # Extract incident details
    $incidentId = $incident.properties.incidentNumber
    $incidentArmId = $incident.id
    $incidentSeverity = $incident.properties.severity
    $entities = $incident.properties.relatedEntities
    
    # Get tenant information
    $tenantId = $incident.properties.additionalData.tenantId
    
    # Determine if enrichment should run based on severity
    $minSeverity = $env:MIN_SEVERITY_FOR_ENRICHMENT ?? "Medium"
    $severityLevels = @{
        "Informational" = 0
        "Low" = 1
        "Medium" = 2
        "High" = 3
    }
    
    if ($severityLevels[$incidentSeverity] -lt $severityLevels[$minSeverity]) {
        Write-Host "Incident severity ($incidentSeverity) below minimum threshold ($minSeverity). Skipping enrichment."
        $body.Message = "Incident severity below threshold - enrichment skipped"
        $body.Status = "Skipped"
    }
    else {
        # Load configuration
        $configPath = $env:DEFENDERXSOAR_CONFIG_PATH ?? "./Config/DefenderXSOAR.json"
        
        # Import DefenderXSOAR orchestration module
        $modulePath = $env:DEFENDERXSOAR_MODULE_PATH ?? "./Modules"
        Import-Module "$modulePath/DefenderXSOARBrain.psm1" -Force
        
        # Prepare products to query
        $products = @('MDE', 'MDC', 'MCAS', 'MDI', 'MDO', 'EntraID')
        if ($env:DEFENDERXSOAR_PRODUCTS) {
            $products = $env:DEFENDERXSOAR_PRODUCTS -split ','
        }
        
        Write-Host "Starting DefenderXSOAR enrichment for incident $incidentId"
        Write-Host "Entities: $($entities.Count)"
        Write-Host "Products: $($products -join ', ')"
        
        # Initialize DefenderXSOAR
        $initResult = Initialize-DefenderXSOARBrain -ConfigPath $configPath
        
        if (-not $initResult) {
            throw "Failed to initialize DefenderXSOAR Brain"
        }
        
        # Start enrichment
        $enrichmentResult = Start-DefenderXSOAREnrichment `
            -IncidentId $incidentId `
            -IncidentArmId $incidentArmId `
            -Entities $entities `
            -TenantId $tenantId `
            -Products $products
        
        if ($enrichmentResult.Success) {
            Write-Host "Enrichment completed successfully"
            Write-Host "Risk Score: $($enrichmentResult.RiskScore)"
            Write-Host "Severity: $($enrichmentResult.Severity)"
            
            $body.EnrichmentResults = @{
                RiskScore = $enrichmentResult.RiskScore
                Severity = $enrichmentResult.Severity
                EntitiesAnalyzed = $enrichmentResult.Entities.Count
                RelatedAlerts = $enrichmentResult.RelatedAlerts.Count
                Decision = $enrichmentResult.Decision
            }
        }
        else {
            throw "Enrichment failed: $($enrichmentResult.Error)"
        }
    }
}
catch {
    Write-Host "Error in DefenderXSOAR webhook: $_"
    $statusCode = [HttpStatusCode]::InternalServerError
    $body = @{
        Status = "Error"
        Message = $_.Exception.Message
        StackTrace = $_.ScriptStackTrace
    }
}

# Associate values to output bindings by calling 'Push-OutputBinding'
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = $statusCode
    Body = $body | ConvertTo-Json -Depth 10
    Headers = @{
        "Content-Type" = "application/json"
    }
})
