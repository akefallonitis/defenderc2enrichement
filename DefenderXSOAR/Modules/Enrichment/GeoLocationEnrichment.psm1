<#
.SYNOPSIS
    GeoLocation Enrichment module for DefenderXSOAR
.DESCRIPTION
    Provides geolocation enrichment for IP addresses
#>

function Invoke-GeoLocationEnrichment {
    <#
    .SYNOPSIS
        Enriches IP entities with geolocation data
    .PARAMETER Entities
        Array of IP entities to enrich
    .EXAMPLE
        Invoke-GeoLocationEnrichment -Entities $ipEntities
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Entities
    )
    
    $enrichmentResults = @{
        EnrichedEntities    = @()
        AnomalousLocations  = @()
        RiskScore           = 0
    }
    
    try {
        foreach ($entity in $Entities) {
            if ($entity.EntityType -eq 'IP') {
                $ipAddress = $entity.NormalizedData.IPAddress
                
                if (-not (Test-PrivateIP -IPAddress $ipAddress)) {
                    $geoData = Get-IPGeoLocation -IPAddress $ipAddress
                    
                    $enrichedEntity = $entity.PSObject.Copy()
                    $enrichedEntity | Add-Member -NotePropertyName 'GeoLocation' -NotePropertyValue $geoData -Force
                    
                    $enrichmentResults.EnrichedEntities += $enrichedEntity
                    
                    # Check for anomalous locations
                    if ($geoData.IsAnomalous) {
                        $enrichmentResults.AnomalousLocations += @{
                            IPAddress   = $ipAddress
                            Country     = $geoData.Country
                            City        = $geoData.City
                            Reason      = $geoData.AnomalyReason
                            RiskScore   = $geoData.RiskScore
                        }
                    }
                }
                else {
                    $enrichmentResults.EnrichedEntities += $entity
                }
            }
            else {
                $enrichmentResults.EnrichedEntities += $entity
            }
        }
        
        # Calculate overall risk score based on anomalous locations
        $anomalousCount = ($enrichmentResults.AnomalousLocations | Measure-Object).Count
        $enrichmentResults.RiskScore = [Math]::Min(($anomalousCount * 15), 100)
        
        return $enrichmentResults
    }
    catch {
        Write-Error "GeoLocation enrichment failed: $_"
        return $enrichmentResults
    }
}

function Get-IPGeoLocation {
    <#
    .SYNOPSIS
        Gets geolocation data for an IP address
    .PARAMETER IPAddress
        IP address to lookup
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$IPAddress
    )
    
    $geoData = @{
        Country         = 'Unknown'
        CountryCode     = 'Unknown'
        City            = 'Unknown'
        Region          = 'Unknown'
        Latitude        = 0.0
        Longitude       = 0.0
        ISP             = 'Unknown'
        Organization    = 'Unknown'
        IsProxy         = $false
        IsVPN           = $false
        IsTor           = $false
        IsAnomalous     = $false
        AnomalyReason   = @()
        RiskScore       = 0
    }
    
    try {
        # In production, integrate with IP geolocation services like:
        # - MaxMind GeoIP2
        # - IPInfo.io
        # - IP-API.com
        # - Azure IP Intelligence (if available)
        
        # For now, provide structure and logic for anomaly detection
        # This is a placeholder - actual API integration would go here
        
        # Check for high-risk locations (example logic)
        $highRiskCountries = @('NK', 'IR', 'SY', 'CU', 'SD')  # Example high-risk country codes
        
        # Simulate geolocation lookup (in production, call actual API)
        # For demonstration, we'll mark this as needing external integration
        $geoData['Note'] = 'Integrate with MaxMind GeoIP2, IPInfo.io, or Azure IP Intelligence API'
        
        # Example anomaly detection logic
        if ($highRiskCountries -contains $geoData.CountryCode) {
            $geoData.IsAnomalous = $true
            $geoData.AnomalyReason += 'High-risk country'
            $geoData.RiskScore += 40
        }
        
        if ($geoData.IsProxy -or $geoData.IsVPN) {
            $geoData.IsAnomalous = $true
            $geoData.AnomalyReason += 'Proxy/VPN detected'
            $geoData.RiskScore += 25
        }
        
        if ($geoData.IsTor) {
            $geoData.IsAnomalous = $true
            $geoData.AnomalyReason += 'Tor exit node'
            $geoData.RiskScore += 50
        }
        
        return $geoData
    }
    catch {
        Write-Verbose "GeoLocation lookup error: $_"
        return $geoData
    }
}

function Test-ImpossibleTravel {
    <#
    .SYNOPSIS
        Detects impossible travel scenarios
    .PARAMETER UserActivity
        Array of user activity records with timestamps and locations
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$UserActivity
    )
    
    $impossibleTravel = @()
    
    try {
        # Sort by timestamp
        $sortedActivity = $UserActivity | Sort-Object Timestamp
        
        for ($i = 1; $i -lt $sortedActivity.Count; $i++) {
            $current = $sortedActivity[$i]
            $previous = $sortedActivity[$i - 1]
            
            # Calculate time difference in hours
            $timeDiff = ($current.Timestamp - $previous.Timestamp).TotalHours
            
            # Calculate distance (simplified - in production use proper distance calculation)
            $distance = Get-Distance -Lat1 $previous.Latitude -Lon1 $previous.Longitude `
                                     -Lat2 $current.Latitude -Lon2 $current.Longitude
            
            # Check if travel is impossible (distance > 1000km and time < 2 hours)
            if ($distance -gt 1000 -and $timeDiff -lt 2) {
                $impossibleTravel += @{
                    User            = $current.User
                    FromLocation    = "$($previous.City), $($previous.Country)"
                    ToLocation      = "$($current.City), $($current.Country)"
                    Distance        = [int]$distance
                    TimeHours       = [math]::Round($timeDiff, 2)
                    FromTimestamp   = $previous.Timestamp
                    ToTimestamp     = $current.Timestamp
                    RiskScore       = 85
                }
            }
        }
        
        return $impossibleTravel
    }
    catch {
        Write-Verbose "Impossible travel detection error: $_"
        return $impossibleTravel
    }
}

function Get-Distance {
    <#
    .SYNOPSIS
        Calculates distance between two geographic coordinates using Haversine formula
    #>
    [CmdletBinding()]
    param(
        [double]$Lat1,
        [double]$Lon1,
        [double]$Lat2,
        [double]$Lon2
    )
    
    $R = 6371  # Earth's radius in kilometers
    
    $dLat = [Math]::PI * ($Lat2 - $Lat1) / 180
    $dLon = [Math]::PI * ($Lon2 - $Lon1) / 180
    
    $lat1Rad = [Math]::PI * $Lat1 / 180
    $lat2Rad = [Math]::PI * $Lat2 / 180
    
    $a = [Math]::Sin($dLat / 2) * [Math]::Sin($dLat / 2) +
         [Math]::Sin($dLon / 2) * [Math]::Sin($dLon / 2) * 
         [Math]::Cos($lat1Rad) * [Math]::Cos($lat2Rad)
    
    $c = 2 * [Math]::Atan2([Math]::Sqrt($a), [Math]::Sqrt(1 - $a))
    
    return $R * $c
}

function Test-PrivateIP {
    [CmdletBinding()]
    param([string]$IPAddress)
    
    try {
        $ip = [System.Net.IPAddress]::Parse($IPAddress)
        $bytes = $ip.GetAddressBytes()
        
        # Check for private IP ranges
        if ($bytes[0] -eq 10) { return $true }
        if ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) { return $true }
        if ($bytes[0] -eq 192 -and $bytes[1] -eq 168) { return $true }
        if ($bytes[0] -eq 127) { return $true }
        
        return $false
    }
    catch {
        return $false
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Invoke-GeoLocationEnrichment',
    'Get-IPGeoLocation',
    'Test-ImpossibleTravel',
    'Get-Distance'
)
