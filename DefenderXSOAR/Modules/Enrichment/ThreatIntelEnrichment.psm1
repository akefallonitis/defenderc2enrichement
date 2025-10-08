<#
.SYNOPSIS
    Threat Intelligence Enrichment module for DefenderXSOAR
.DESCRIPTION
    Provides threat intelligence enrichment from multiple sources including Microsoft Threat Intelligence API
#>

function Invoke-ThreatIntelEnrichment {
    <#
    .SYNOPSIS
        Enriches entities with threat intelligence data
    .PARAMETER Entities
        Array of entities to enrich
    .PARAMETER AccessToken
        Access token for Microsoft Threat Intelligence API
    .EXAMPLE
        Invoke-ThreatIntelEnrichment -Entities $entities -AccessToken $token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Entities,
        
        [Parameter(Mandatory = $false)]
        [string]$AccessToken
    )
    
    $enrichmentResults = @{
        EnrichedEntities = @()
        ThreatIndicators = @()
        OverallRiskScore = 0
    }
    
    try {
        foreach ($entity in $Entities) {
            $enrichedEntity = $entity.PSObject.Copy()
            $threatData = @{
                IsMalicious     = $false
                ThreatTypes     = @()
                ThreatSources   = @()
                Confidence      = 0
                LastSeen        = $null
            }
            
            switch ($entity.EntityType) {
                'IP' {
                    $threatData = Get-IPThreatIntel -IPAddress $entity.NormalizedData.IPAddress -AccessToken $AccessToken
                }
                'File' {
                    if ($entity.NormalizedData.FileHash.SHA256) {
                        $threatData = Get-FileHashThreatIntel -FileHash $entity.NormalizedData.FileHash.SHA256 -AccessToken $AccessToken
                    }
                }
                'URL' {
                    $threatData = Get-URLThreatIntel -URL $entity.NormalizedData.URL -AccessToken $AccessToken
                }
                'DNS' {
                    $threatData = Get-DomainThreatIntel -Domain $entity.NormalizedData.DomainName -AccessToken $AccessToken
                }
            }
            
            $enrichedEntity | Add-Member -NotePropertyName 'ThreatIntelligence' -NotePropertyValue $threatData -Force
            $enrichmentResults.EnrichedEntities += $enrichedEntity
            
            if ($threatData.IsMalicious) {
                $enrichmentResults.ThreatIndicators += @{
                    EntityType  = $entity.EntityType
                    Indicator   = Get-EntityIndicator -Entity $entity
                    ThreatTypes = $threatData.ThreatTypes
                    Confidence  = $threatData.Confidence
                }
            }
        }
        
        # Calculate overall risk score
        $maliciousCount = ($enrichmentResults.ThreatIndicators | Measure-Object).Count
        $enrichmentResults.OverallRiskScore = [Math]::Min(($maliciousCount * 25), 100)
        
        return $enrichmentResults
    }
    catch {
        Write-Error "Threat intelligence enrichment failed: $_"
        return $enrichmentResults
    }
}

function Get-IPThreatIntel {
    [CmdletBinding()]
    param(
        [string]$IPAddress,
        [string]$AccessToken
    )
    
    $threatData = @{
        IsMalicious     = $false
        ThreatTypes     = @()
        ThreatSources   = @()
        Confidence      = 0
        LastSeen        = $null
        Details         = @{}
    }
    
    try {
        # Check if IP is private (no need to check threat intel)
        if (Test-PrivateIP -IPAddress $IPAddress) {
            $threatData.Details['Note'] = 'Private IP address - no external threat intel available'
            return $threatData
        }
        
        # Microsoft Threat Intelligence API lookup
        if ($AccessToken) {
            $headers = @{
                "Authorization" = "Bearer $AccessToken"
                "Content-Type"  = "application/json"
            }
            
            try {
                $uri = "https://graph.microsoft.com/beta/security/threatIntelligence/ipAddresses/$IPAddress"
                $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction SilentlyContinue
                
                if ($response) {
                    $threatData.Details['MicrosoftThreatIntel'] = $response
                    if ($response.reputation -eq 'malicious') {
                        $threatData.IsMalicious = $true
                        $threatData.ThreatSources += 'Microsoft Threat Intelligence'
                        $threatData.Confidence = 85
                    }
                }
            }
            catch {
                Write-Verbose "Microsoft Threat Intelligence API call failed: $_"
            }
        }
        
        # Add placeholder for other threat intel sources
        $threatData.Details['Note'] = 'Additional threat intel sources can be integrated (VirusTotal, AlienVault OTX, etc.)'
        
        return $threatData
    }
    catch {
        Write-Verbose "IP threat intel lookup error: $_"
        return $threatData
    }
}

function Get-FileHashThreatIntel {
    [CmdletBinding()]
    param(
        [string]$FileHash,
        [string]$AccessToken
    )
    
    $threatData = @{
        IsMalicious     = $false
        ThreatTypes     = @()
        ThreatSources   = @()
        Confidence      = 0
        LastSeen        = $null
        Details         = @{}
    }
    
    try {
        # Microsoft Defender ATP file reputation check
        if ($AccessToken) {
            $headers = @{
                "Authorization" = "Bearer $AccessToken"
                "Content-Type"  = "application/json"
            }
            
            try {
                $uri = "https://api.securitycenter.microsoft.com/api/files/$FileHash"
                $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction SilentlyContinue
                
                if ($response) {
                    $threatData.Details['MDEFileInfo'] = $response
                    
                    if ($response.globalPrevalence -lt 10) {
                        $threatData.ThreatTypes += 'Rare file'
                        $threatData.Confidence += 20
                    }
                    
                    if ($response.determinationType -eq 'malware') {
                        $threatData.IsMalicious = $true
                        $threatData.ThreatTypes += 'Malware'
                        $threatData.ThreatSources += 'Microsoft Defender'
                        $threatData.Confidence = 95
                    }
                }
            }
            catch {
                Write-Verbose "MDE file reputation check failed: $_"
            }
        }
        
        $threatData.Details['Note'] = 'Additional file reputation sources can be integrated (VirusTotal, etc.)'
        
        return $threatData
    }
    catch {
        Write-Verbose "File hash threat intel lookup error: $_"
        return $threatData
    }
}

function Get-URLThreatIntel {
    [CmdletBinding()]
    param(
        [string]$URL,
        [string]$AccessToken
    )
    
    $threatData = @{
        IsMalicious     = $false
        ThreatTypes     = @()
        ThreatSources   = @()
        Confidence      = 0
        LastSeen        = $null
        Details         = @{}
    }
    
    try {
        # Microsoft Threat Intelligence API URL lookup
        if ($AccessToken) {
            $headers = @{
                "Authorization" = "Bearer $AccessToken"
                "Content-Type"  = "application/json"
            }
            
            try {
                # URL needs to be base64 encoded for the API
                $encodedUrl = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($URL))
                $uri = "https://graph.microsoft.com/beta/security/threatIntelligence/urls/$encodedUrl"
                $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction SilentlyContinue
                
                if ($response -and $response.reputation -eq 'malicious') {
                    $threatData.IsMalicious = $true
                    $threatData.ThreatTypes += 'Malicious URL'
                    $threatData.ThreatSources += 'Microsoft Threat Intelligence'
                    $threatData.Confidence = 85
                    $threatData.Details['MicrosoftThreatIntel'] = $response
                }
            }
            catch {
                Write-Verbose "Microsoft Threat Intelligence URL lookup failed: $_"
            }
        }
        
        return $threatData
    }
    catch {
        Write-Verbose "URL threat intel lookup error: $_"
        return $threatData
    }
}

function Get-DomainThreatIntel {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [string]$AccessToken
    )
    
    $threatData = @{
        IsMalicious     = $false
        ThreatTypes     = @()
        ThreatSources   = @()
        Confidence      = 0
        LastSeen        = $null
        Details         = @{}
    }
    
    try {
        # Microsoft Threat Intelligence API domain lookup
        if ($AccessToken -and $Domain) {
            $headers = @{
                "Authorization" = "Bearer $AccessToken"
                "Content-Type"  = "application/json"
            }
            
            try {
                $uri = "https://graph.microsoft.com/beta/security/threatIntelligence/hosts/$Domain"
                $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction SilentlyContinue
                
                if ($response -and $response.reputation -eq 'malicious') {
                    $threatData.IsMalicious = $true
                    $threatData.ThreatTypes += 'Malicious Domain'
                    $threatData.ThreatSources += 'Microsoft Threat Intelligence'
                    $threatData.Confidence = 85
                    $threatData.Details['MicrosoftThreatIntel'] = $response
                }
            }
            catch {
                Write-Verbose "Microsoft Threat Intelligence domain lookup failed: $_"
            }
        }
        
        return $threatData
    }
    catch {
        Write-Verbose "Domain threat intel lookup error: $_"
        return $threatData
    }
}

function Get-EntityIndicator {
    [CmdletBinding()]
    param($Entity)
    
    switch ($Entity.EntityType) {
        'IP' { return $Entity.NormalizedData.IPAddress }
        'File' { return $Entity.NormalizedData.FileHash.SHA256 }
        'URL' { return $Entity.NormalizedData.URL }
        'DNS' { return $Entity.NormalizedData.DomainName }
        default { return 'Unknown' }
    }
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
    'Invoke-ThreatIntelEnrichment',
    'Get-IPThreatIntel',
    'Get-FileHashThreatIntel',
    'Get-URLThreatIntel',
    'Get-DomainThreatIntel',
    'Get-EntityIndicator'
)
