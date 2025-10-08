<#
.SYNOPSIS
    Microsoft Defender for Cloud Worker module
.DESCRIPTION
    Provides MDC-specific enrichment, vulnerability assessment, and security posture analysis
#>

# Import common modules
$CommonPath = Join-Path $PSScriptRoot "..\Common"
Import-Module (Join-Path $CommonPath "AuthenticationHelper.psm1") -Force
Import-Module (Join-Path $CommonPath "EntityNormalizer.psm1") -Force

function Get-MDCSecurityAlerts {
    <#
    .SYNOPSIS
        Gets security alerts from Microsoft Defender for Cloud
    .PARAMETER SubscriptionId
        Azure subscription ID
    .PARAMETER AccessToken
        Azure Management API access token
    .PARAMETER ResourceGroup
        Optional resource group filter
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory = $false)]
        [string]$ResourceGroup
    )
    
    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        if ($ResourceGroup) {
            $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Security/alerts?api-version=2022-01-01"
        }
        else {
            $uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Security/alerts?api-version=2022-01-01"
        }
        
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        return $response.value
    }
    catch {
        Write-Error "Failed to get MDC security alerts: $_"
        return @()
    }
}

function Get-MDCSecureScore {
    <#
    .SYNOPSIS
        Gets Azure Secure Score
    .PARAMETER SubscriptionId
        Azure subscription ID
    .PARAMETER AccessToken
        Azure Management API access token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )
    
    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        $uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Security/secureScores?api-version=2020-01-01"
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        
        return $response.value
    }
    catch {
        Write-Error "Failed to get MDC secure score: $_"
        return $null
    }
}

function Get-MDCVulnerabilityAssessment {
    <#
    .SYNOPSIS
        Gets vulnerability assessment results
    .PARAMETER SubscriptionId
        Azure subscription ID
    .PARAMETER ResourceId
        Azure resource ID
    .PARAMETER AccessToken
        Azure Management API access token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,
        
        [Parameter(Mandatory = $false)]
        [string]$ResourceId,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )
    
    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        if ($ResourceId) {
            $uri = "https://management.azure.com$ResourceId/providers/Microsoft.Security/assessments?api-version=2020-01-01"
        }
        else {
            $uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Security/assessments?api-version=2020-01-01"
        }
        
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        return $response.value
    }
    catch {
        Write-Error "Failed to get vulnerability assessment: $_"
        return @()
    }
}

function Get-MDCComplianceResults {
    <#
    .SYNOPSIS
        Gets compliance assessment results
    .PARAMETER SubscriptionId
        Azure subscription ID
    .PARAMETER AccessToken
        Azure Management API access token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )
    
    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        $uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Security/complianceResults?api-version=2017-08-01"
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        
        return $response.value
    }
    catch {
        Write-Error "Failed to get compliance results: $_"
        return @()
    }
}

function Get-MDCResourceSecurityState {
    <#
    .SYNOPSIS
        Gets security state for Azure resources
    .PARAMETER SubscriptionId
        Azure subscription ID
    .PARAMETER ResourceGroup
        Resource group name
    .PARAMETER ResourceName
        Resource name
    .PARAMETER AccessToken
        Azure Management API access token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,
        
        [Parameter(Mandatory = $false)]
        [string]$ResourceGroup,
        
        [Parameter(Mandatory = $false)]
        [string]$ResourceName,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )
    
    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        if ($ResourceGroup -and $ResourceName) {
            $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Security/locations/centralus/applicationWhitelistings?api-version=2020-01-01"
        }
        else {
            $uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Security/securityStatuses?api-version=2015-06-01-preview"
        }
        
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        return $response.value
    }
    catch {
        Write-Error "Failed to get resource security state: $_"
        return @()
    }
}

function Start-MDCEnrichment {
    <#
    .SYNOPSIS
        Performs comprehensive MDC enrichment
    .PARAMETER Entities
        Array of entities to enrich
    .PARAMETER SubscriptionId
        Azure subscription ID
    .PARAMETER AccessToken
        Azure Management API access token
    .PARAMETER IncidentId
        Incident identifier
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Entities,
        
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory = $true)]
        [string]$IncidentId
    )
    
    $enrichmentResults = @{
        Entities          = @()
        RelatedAlerts     = @()
        ThreatIntel       = @()
        RiskScore         = 0
        Severity          = "Informational"
        Recommendations   = @()
        WatchlistMatches  = @()
        UEBAInsights      = @()
        KQLQueryResults   = @()
    }
    
    try {
        # Get security alerts
        $alerts = Get-MDCSecurityAlerts -SubscriptionId $SubscriptionId -AccessToken $AccessToken
        $enrichmentResults.RelatedAlerts = $alerts
        
        # Get secure score
        $secureScore = Get-MDCSecureScore -SubscriptionId $SubscriptionId -AccessToken $AccessToken
        if ($secureScore) {
            $enrichmentResults.ThreatIntel += @{
                Type = "SecureScore"
                Score = $secureScore[0].properties.score.current
                MaxScore = $secureScore[0].properties.score.max
                Percentage = ($secureScore[0].properties.score.current / $secureScore[0].properties.score.max) * 100
            }
            
            # Calculate risk score based on secure score
            $scorePercentage = ($secureScore[0].properties.score.current / $secureScore[0].properties.score.max) * 100
            $enrichmentResults.RiskScore = [int](100 - $scorePercentage)
        }
        
        # Process Azure Resource entities
        foreach ($entity in $Entities) {
            if ($entity.Type -eq 'AzureResource') {
                $normalizedResource = ConvertTo-NormalizedEntity -EntityData $entity -EntityType 'AzureResource' -Source 'MDC'
                $enrichmentResults.Entities += $normalizedResource
                
                # Get vulnerability assessments for resource
                if ($entity.ResourceId) {
                    $vulnerabilities = Get-MDCVulnerabilityAssessment -SubscriptionId $SubscriptionId -ResourceId $entity.ResourceId -AccessToken $AccessToken
                    
                    $highSeverityVulns = ($vulnerabilities | Where-Object { $_.properties.status.severity -eq 'High' }).Count
                    if ($highSeverityVulns -gt 0) {
                        $enrichmentResults.RiskScore += ($highSeverityVulns * 10)
                        $enrichmentResults.Recommendations += "Found $highSeverityVulns high severity vulnerabilities on resource $($entity.ResourceId)"
                    }
                }
            }
        }
        
        # Get compliance results
        $complianceResults = Get-MDCComplianceResults -SubscriptionId $SubscriptionId -AccessToken $AccessToken
        $nonCompliantCount = ($complianceResults | Where-Object { $_.properties.resourceStatus -eq 'NonCompliant' }).Count
        
        if ($nonCompliantCount -gt 0) {
            $enrichmentResults.Recommendations += "Found $nonCompliantCount non-compliant resources - review compliance standards"
        }
        
        # Determine overall severity
        if ($enrichmentResults.RiskScore -gt 75) {
            $enrichmentResults.Severity = "High"
        }
        elseif ($enrichmentResults.RiskScore -gt 50) {
            $enrichmentResults.Severity = "Medium"
        }
        elseif ($enrichmentResults.RiskScore -gt 25) {
            $enrichmentResults.Severity = "Low"
        }
        
        # Add security recommendations
        if ($alerts.Count -gt 3) {
            $enrichmentResults.Recommendations += "Multiple security alerts detected in MDC - investigate subscription security posture"
        }
        
        return $enrichmentResults
    }
    catch {
        Write-Error "MDC enrichment failed: $_"
        throw
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Get-MDCSecurityAlerts',
    'Get-MDCSecureScore',
    'Get-MDCVulnerabilityAssessment',
    'Get-MDCComplianceResults',
    'Get-MDCResourceSecurityState',
    'Start-MDCEnrichment'
)
