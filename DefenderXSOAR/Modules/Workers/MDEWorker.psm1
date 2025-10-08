<#
.SYNOPSIS
    Microsoft Defender for Endpoint Worker module
.DESCRIPTION
    Provides MDE-specific enrichment, investigation, and hunting capabilities
#>

# Import common modules
$CommonPath = Join-Path $PSScriptRoot "..\Common"
Import-Module (Join-Path $CommonPath "AuthenticationHelper.psm1") -Force
Import-Module (Join-Path $CommonPath "EntityNormalizer.psm1") -Force

function Get-MDEDeviceInfo {
    <#
    .SYNOPSIS
        Gets device information from MDE
    .PARAMETER DeviceName
        Device name or ID
    .PARAMETER AccessToken
        MDE API access token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeviceName,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )
    
    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        # Try to find device by name
        $uri = "https://api.securitycenter.microsoft.com/api/machines?`$filter=computerDnsName eq '$DeviceName'"
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        
        if ($response.value -and $response.value.Count -gt 0) {
            return $response.value[0]
        }
        
        return $null
    }
    catch {
        Write-Error "Failed to get MDE device info: $_"
        return $null
    }
}

function Get-MDEDeviceAlerts {
    <#
    .SYNOPSIS
        Gets alerts for a specific device
    .PARAMETER DeviceId
        MDE Device ID
    .PARAMETER AccessToken
        MDE API access token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeviceId,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )
    
    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        $uri = "https://api.securitycenter.microsoft.com/api/machines/$DeviceId/alerts"
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        
        return $response.value
    }
    catch {
        Write-Error "Failed to get MDE device alerts: $_"
        return @()
    }
}

function Get-MDEFileInfo {
    <#
    .SYNOPSIS
        Gets file information from MDE
    .PARAMETER FileHash
        SHA1 or SHA256 hash
    .PARAMETER AccessToken
        MDE API access token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileHash,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )
    
    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        $uri = "https://api.securitycenter.microsoft.com/api/files/$FileHash"
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        
        return $response
    }
    catch {
        Write-Error "Failed to get MDE file info: $_"
        return $null
    }
}

function Get-MDEFileDevices {
    <#
    .SYNOPSIS
        Gets devices where a file was observed
    .PARAMETER FileHash
        SHA1 or SHA256 hash
    .PARAMETER AccessToken
        MDE API access token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileHash,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )
    
    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        $uri = "https://api.securitycenter.microsoft.com/api/files/$FileHash/machines"
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        
        return $response.value
    }
    catch {
        Write-Error "Failed to get file devices: $_"
        return @()
    }
}

function Get-MDERelatedAlerts {
    <#
    .SYNOPSIS
        Gets related alerts from MDE
    .PARAMETER AlertId
        Alert ID to find related alerts for
    .PARAMETER AccessToken
        MDE API access token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AlertId,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )
    
    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        $uri = "https://api.securitycenter.microsoft.com/api/alerts/$AlertId/related"
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        
        return $response.value
    }
    catch {
        Write-Warning "Failed to get related alerts: $_"
        return @()
    }
}

function Invoke-MDEAdvancedHunting {
    <#
    .SYNOPSIS
        Executes advanced hunting query in MDE
    .PARAMETER Query
        KQL query to execute
    .PARAMETER AccessToken
        MDE API access token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Query,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )
    
    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        $body = @{
            Query = $Query
        } | ConvertTo-Json
        
        $uri = "https://api.securitycenter.microsoft.com/api/advancedhunting/run"
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Post -Body $body
        
        return $response.Results
    }
    catch {
        Write-Error "Failed to execute MDE advanced hunting: $_"
        return @()
    }
}

function Start-MDEEnrichment {
    <#
    .SYNOPSIS
        Performs comprehensive MDE enrichment
    .PARAMETER Entities
        Array of entities to enrich
    .PARAMETER AccessToken
        MDE API access token
    .PARAMETER IncidentId
        Incident identifier
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Entities,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory = $true)]
        [string]$IncidentId
    )
    
    $enrichmentResults = @{
        Entities       = @()
        RelatedAlerts  = @()
        ThreatIntel    = @()
        RiskScore      = 0
        Severity       = "Informational"
        Recommendations = @()
        WatchlistMatches = @()
        UEBAInsights   = @()
        KQLQueryResults = @()
    }
    
    try {
        foreach ($entity in $Entities) {
            Write-Verbose "Processing entity: $($entity.Type)"
            
            switch ($entity.Type) {
                'Device' {
                    $deviceInfo = Get-MDEDeviceInfo -DeviceName $entity.HostName -AccessToken $AccessToken
                    if ($deviceInfo) {
                        $normalizedDevice = ConvertTo-NormalizedEntity -EntityData $deviceInfo -EntityType 'Device' -Source 'MDE'
                        $enrichmentResults.Entities += $normalizedDevice
                        
                        # Get device alerts
                        $deviceAlerts = Get-MDEDeviceAlerts -DeviceId $deviceInfo.id -AccessToken $AccessToken
                        $enrichmentResults.RelatedAlerts += $deviceAlerts
                        
                        # Calculate risk score based on device risk
                        $enrichmentResults.RiskScore += $deviceInfo.riskScore ?? 0
                    }
                }
                
                'File' {
                    if ($entity.FileHashes) {
                        $fileHash = $entity.FileHashes.SHA1 ?? $entity.FileHashes.SHA256
                        if ($fileHash) {
                            $fileInfo = Get-MDEFileInfo -FileHash $fileHash -AccessToken $AccessToken
                            if ($fileInfo) {
                                $normalizedFile = ConvertTo-NormalizedEntity -EntityData $fileInfo -EntityType 'File' -Source 'MDE'
                                $enrichmentResults.Entities += $normalizedFile
                                
                                # Get devices where file was seen
                                $fileDevices = Get-MDEFileDevices -FileHash $fileHash -AccessToken $AccessToken
                                $enrichmentResults.ThreatIntel += @{
                                    Type = "FilePresence"
                                    Hash = $fileHash
                                    DeviceCount = $fileDevices.Count
                                    Devices = $fileDevices
                                }
                            }
                        }
                    }
                }
                
                'IP' {
                    # IP enrichment through advanced hunting
                    $ipQuery = @"
DeviceNetworkEvents
| where RemoteIP == '$($entity.Address)'
| summarize ConnectionCount = count(), 
            FirstSeen = min(Timestamp), 
            LastSeen = max(Timestamp),
            UniqueDevices = dcount(DeviceName)
            by RemoteIP, RemoteUrl
| order by ConnectionCount desc
| take 10
"@
                    $ipResults = Invoke-MDEAdvancedHunting -Query $ipQuery -AccessToken $AccessToken
                    if ($ipResults -and $ipResults.Count -gt 0) {
                        $enrichmentResults.KQLQueryResults += @{
                            QueryType = "IPConnections"
                            Results = $ipResults
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
        
        # Add recommendations based on findings
        if ($enrichmentResults.RelatedAlerts.Count -gt 5) {
            $enrichmentResults.Recommendations += "Multiple related alerts detected - consider investigating for a coordinated attack"
        }
        
        if ($enrichmentResults.RiskScore -gt 50) {
            $enrichmentResults.Recommendations += "High risk score detected - prioritize investigation and consider device isolation"
        }
        
        return $enrichmentResults
    }
    catch {
        Write-Error "MDE enrichment failed: $_"
        throw
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Get-MDEDeviceInfo',
    'Get-MDEDeviceAlerts',
    'Get-MDEFileInfo',
    'Get-MDEFileDevices',
    'Get-MDERelatedAlerts',
    'Invoke-MDEAdvancedHunting',
    'Start-MDEEnrichment'
)
