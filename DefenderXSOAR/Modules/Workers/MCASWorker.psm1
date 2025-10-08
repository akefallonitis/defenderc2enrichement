<#
.SYNOPSIS
    Microsoft Defender for Cloud Apps Worker module
.DESCRIPTION
    Provides MCAS-specific enrichment, cloud app risk assessment, and user behavior analytics
#>

# Import common modules
$CommonPath = Join-Path $PSScriptRoot "..\Common"
Import-Module (Join-Path $CommonPath "AuthenticationHelper.psm1") -Force
Import-Module (Join-Path $CommonPath "EntityNormalizer.psm1") -Force

function Get-MCASAlerts {
    <#
    .SYNOPSIS
        Gets alerts from Microsoft Defender for Cloud Apps
    .PARAMETER TenantUrl
        MCAS tenant URL (e.g., https://tenant.portal.cloudappsecurity.com)
    .PARAMETER AccessToken
        MCAS API token
    .PARAMETER Filter
        Optional filter for alerts
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantUrl,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Filter
    )
    
    try {
        $headers = @{
            "Authorization" = "Token $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        $uri = "$TenantUrl/api/v1/alerts/"
        
        if ($Filter) {
            $body = @{
                filters = $Filter
            } | ConvertTo-Json -Depth 10
            
            $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Post -Body $body
        }
        else {
            $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        }
        
        return $response.data
    }
    catch {
        Write-Error "Failed to get MCAS alerts: $_"
        return @()
    }
}

function Get-MCASUserActivities {
    <#
    .SYNOPSIS
        Gets user activities from MCAS
    .PARAMETER TenantUrl
        MCAS tenant URL
    .PARAMETER AccessToken
        MCAS API token
    .PARAMETER Username
        Username to query
    .PARAMETER Limit
        Maximum number of activities to return
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantUrl,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory = $true)]
        [string]$Username,
        
        [Parameter(Mandatory = $false)]
        [int]$Limit = 100
    )
    
    try {
        $headers = @{
            "Authorization" = "Token $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        $body = @{
            filters = @{
                user = @{
                    username = @{
                        eq = $Username
                    }
                }
            }
            limit = $Limit
        } | ConvertTo-Json -Depth 10
        
        $uri = "$TenantUrl/api/v1/activities/"
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Post -Body $body
        
        return $response.data
    }
    catch {
        Write-Error "Failed to get MCAS user activities: $_"
        return @()
    }
}

function Get-MCASAppRiskScore {
    <#
    .SYNOPSIS
        Gets cloud app risk score
    .PARAMETER TenantUrl
        MCAS tenant URL
    .PARAMETER AccessToken
        MCAS API token
    .PARAMETER AppId
        Application ID
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantUrl,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory = $true)]
        [string]$AppId
    )
    
    try {
        $headers = @{
            "Authorization" = "Token $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        $uri = "$TenantUrl/api/v1/apps/$AppId/"
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        
        return $response
    }
    catch {
        Write-Error "Failed to get MCAS app risk score: $_"
        return $null
    }
}

function Get-MCASFileActivities {
    <#
    .SYNOPSIS
        Gets file-related activities from MCAS
    .PARAMETER TenantUrl
        MCAS tenant URL
    .PARAMETER AccessToken
        MCAS API token
    .PARAMETER FileHash
        File hash to search for
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantUrl,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory = $true)]
        [string]$FileHash
    )
    
    try {
        $headers = @{
            "Authorization" = "Token $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        $body = @{
            filters = @{
                fileSelector = @{
                    sha256 = @{
                        eq = $FileHash
                    }
                }
            }
        } | ConvertTo-Json -Depth 10
        
        $uri = "$TenantUrl/api/v1/activities/"
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Post -Body $body
        
        return $response.data
    }
    catch {
        Write-Error "Failed to get MCAS file activities: $_"
        return @()
    }
}

function Get-MCASAnomalousActivities {
    <#
    .SYNOPSIS
        Gets anomalous user activities
    .PARAMETER TenantUrl
        MCAS tenant URL
    .PARAMETER AccessToken
        MCAS API token
    .PARAMETER Username
        Username to check for anomalies
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantUrl,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory = $true)]
        [string]$Username
    )
    
    try {
        $headers = @{
            "Authorization" = "Token $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        $body = @{
            filters = @{
                user = @{
                    username = @{
                        eq = $Username
                    }
                }
                activityType = @{
                    eq = "EVENT_CATEGORY_ANOMALOUS"
                }
            }
        } | ConvertTo-Json -Depth 10
        
        $uri = "$TenantUrl/api/v1/activities/"
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Post -Body $body
        
        return $response.data
    }
    catch {
        Write-Error "Failed to get MCAS anomalous activities: $_"
        return @()
    }
}

function Start-MCASEnrichment {
    <#
    .SYNOPSIS
        Performs comprehensive MCAS enrichment
    .PARAMETER Entities
        Array of entities to enrich
    .PARAMETER TenantUrl
        MCAS tenant URL
    .PARAMETER AccessToken
        MCAS API token
    .PARAMETER IncidentId
        Incident identifier
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Entities,
        
        [Parameter(Mandatory = $true)]
        [string]$TenantUrl,
        
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
        # Get all recent alerts
        $alerts = Get-MCASAlerts -TenantUrl $TenantUrl -AccessToken $AccessToken
        $enrichmentResults.RelatedAlerts = $alerts
        
        foreach ($entity in $Entities) {
            Write-Verbose "Processing MCAS entity: $($entity.Type)"
            
            switch ($entity.Type) {
                'User' {
                    $username = $entity.Name ?? $entity.UserPrincipalName
                    if ($username) {
                        # Get user activities
                        $activities = Get-MCASUserActivities -TenantUrl $TenantUrl -AccessToken $AccessToken -Username $username
                        
                        # Get anomalous activities
                        $anomalies = Get-MCASAnomalousActivities -TenantUrl $TenantUrl -AccessToken $AccessToken -Username $username
                        
                        if ($anomalies.Count -gt 0) {
                            $enrichmentResults.UEBAInsights += @{
                                Type = "AnomalousActivity"
                                User = $username
                                Count = $anomalies.Count
                                Activities = $anomalies
                            }
                            
                            $enrichmentResults.RiskScore += ($anomalies.Count * 15)
                            $enrichmentResults.Recommendations += "User $username has $($anomalies.Count) anomalous activities detected"
                        }
                        
                        # Analyze activity patterns
                        if ($activities.Count -gt 0) {
                            $uniqueIPs = ($activities | Select-Object -ExpandProperty ipAddress -Unique).Count
                            $uniqueApps = ($activities | Select-Object -ExpandProperty appId -Unique).Count
                            
                            $enrichmentResults.UEBAInsights += @{
                                Type = "ActivityPattern"
                                User = $username
                                TotalActivities = $activities.Count
                                UniqueIPs = $uniqueIPs
                                UniqueApps = $uniqueApps
                            }
                            
                            if ($uniqueIPs -gt 10) {
                                $enrichmentResults.RiskScore += 20
                                $enrichmentResults.Recommendations += "User accessing from $uniqueIPs different IP addresses - possible account compromise"
                            }
                        }
                    }
                }
                
                'File' {
                    if ($entity.FileHashes -and $entity.FileHashes.SHA256) {
                        $fileActivities = Get-MCASFileActivities -TenantUrl $TenantUrl -AccessToken $AccessToken -FileHash $entity.FileHashes.SHA256
                        
                        if ($fileActivities.Count -gt 0) {
                            $enrichmentResults.ThreatIntel += @{
                                Type = "FileActivity"
                                Hash = $entity.FileHashes.SHA256
                                ActivityCount = $fileActivities.Count
                                Activities = $fileActivities
                            }
                        }
                    }
                }
                
                'CloudApp' {
                    if ($entity.AppId) {
                        $appRisk = Get-MCASAppRiskScore -TenantUrl $TenantUrl -AccessToken $AccessToken -AppId $entity.AppId
                        
                        if ($appRisk) {
                            $normalizedApp = ConvertTo-NormalizedEntity -EntityData $appRisk -EntityType 'CloudApp' -Source 'MCAS'
                            $enrichmentResults.Entities += $normalizedApp
                            
                            if ($appRisk.riskScore -gt 7) {
                                $enrichmentResults.RiskScore += 25
                                $enrichmentResults.Recommendations += "High-risk cloud app detected: $($appRisk.name)"
                            }
                        }
                    }
                }
            }
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
        
        # Add general recommendations
        if ($enrichmentResults.UEBAInsights.Count -gt 5) {
            $enrichmentResults.Recommendations += "Multiple behavioral anomalies detected - comprehensive investigation recommended"
        }
        
        return $enrichmentResults
    }
    catch {
        Write-Error "MCAS enrichment failed: $_"
        throw
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Get-MCASAlerts',
    'Get-MCASUserActivities',
    'Get-MCASAppRiskScore',
    'Get-MCASFileActivities',
    'Get-MCASAnomalousActivities',
    'Start-MCASEnrichment'
)
