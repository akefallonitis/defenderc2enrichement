<#
.SYNOPSIS
    Reputation Enrichment module for DefenderXSOAR
.DESCRIPTION
    Provides reputation scoring for various entity types
#>

function Invoke-ReputationEnrichment {
    <#
    .SYNOPSIS
        Enriches entities with reputation scores
    .PARAMETER Entities
        Array of entities to enrich
    .PARAMETER AccessToken
        Access token for Microsoft APIs
    .EXAMPLE
        Invoke-ReputationEnrichment -Entities $entities -AccessToken $token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Entities,
        
        [Parameter(Mandatory = $false)]
        [string]$AccessToken
    )
    
    $enrichmentResults = @{
        EnrichedEntities    = @()
        LowReputationItems  = @()
        OverallRiskScore    = 0
    }
    
    try {
        foreach ($entity in $Entities) {
            $enrichedEntity = $entity.PSObject.Copy()
            $reputationData = @{
                Score           = 50  # Neutral score
                Category        = 'Unknown'
                Prevalence      = 0
                FirstSeen       = $null
                LastSeen        = $null
                Sources         = @()
                IsLowReputation = $false
            }
            
            switch ($entity.EntityType) {
                'File' {
                    if ($entity.NormalizedData.FileHash.SHA256) {
                        $reputationData = Get-FileReputation -FileHash $entity.NormalizedData.FileHash.SHA256 -AccessToken $AccessToken
                    }
                }
                'IP' {
                    $reputationData = Get-IPReputation -IPAddress $entity.NormalizedData.IPAddress -AccessToken $AccessToken
                }
                'DNS' {
                    $reputationData = Get-DomainReputation -Domain $entity.NormalizedData.DomainName -AccessToken $AccessToken
                }
                'CloudApp' {
                    $reputationData = Get-CloudAppReputation -AppId $entity.NormalizedData.AppId -AccessToken $AccessToken
                }
            }
            
            $enrichedEntity | Add-Member -NotePropertyName 'Reputation' -NotePropertyValue $reputationData -Force
            $enrichmentResults.EnrichedEntities += $enrichedEntity
            
            if ($reputationData.IsLowReputation) {
                $enrichmentResults.LowReputationItems += @{
                    EntityType  = $entity.EntityType
                    Indicator   = Get-EntityIndicatorValue -Entity $entity
                    Score       = $reputationData.Score
                    Category    = $reputationData.Category
                }
            }
        }
        
        # Calculate overall risk score
        $lowRepCount = ($enrichmentResults.LowReputationItems | Measure-Object).Count
        $enrichmentResults.OverallRiskScore = [Math]::Min(($lowRepCount * 20), 100)
        
        return $enrichmentResults
    }
    catch {
        Write-Error "Reputation enrichment failed: $_"
        return $enrichmentResults
    }
}

function Get-FileReputation {
    [CmdletBinding()]
    param(
        [string]$FileHash,
        [string]$AccessToken
    )
    
    $reputation = @{
        Score           = 50
        Category        = 'Unknown'
        Prevalence      = 0
        FirstSeen       = $null
        LastSeen        = $null
        Sources         = @()
        IsLowReputation = $false
        Details         = @{}
    }
    
    try {
        if ($AccessToken) {
            $headers = @{
                "Authorization" = "Bearer $AccessToken"
                "Content-Type"  = "application/json"
            }
            
            try {
                # Microsoft Defender ATP file stats
                $uri = "https://api.securitycenter.microsoft.com/api/files/$FileHash/stats"
                $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction SilentlyContinue
                
                if ($response) {
                    $reputation.Prevalence = $response.globalPrevalence
                    $reputation.FirstSeen = $response.globalFirstObserved
                    $reputation.LastSeen = $response.globalLastObserved
                    $reputation.Sources += 'Microsoft Defender ATP'
                    
                    # Calculate reputation score based on prevalence
                    if ($reputation.Prevalence -eq 0) {
                        $reputation.Score = 10
                        $reputation.Category = 'Unknown/New'
                        $reputation.IsLowReputation = $true
                    }
                    elseif ($reputation.Prevalence -lt 10) {
                        $reputation.Score = 30
                        $reputation.Category = 'Rare'
                        $reputation.IsLowReputation = $true
                    }
                    elseif ($reputation.Prevalence -lt 100) {
                        $reputation.Score = 50
                        $reputation.Category = 'Uncommon'
                    }
                    else {
                        $reputation.Score = 70
                        $reputation.Category = 'Common'
                    }
                    
                    $reputation.Details['MDEStats'] = $response
                }
            }
            catch {
                Write-Verbose "File reputation lookup failed: $_"
            }
        }
        
        return $reputation
    }
    catch {
        Write-Verbose "File reputation error: $_"
        return $reputation
    }
}

function Get-IPReputation {
    [CmdletBinding()]
    param(
        [string]$IPAddress,
        [string]$AccessToken
    )
    
    $reputation = @{
        Score           = 50
        Category        = 'Unknown'
        Prevalence      = 0
        FirstSeen       = $null
        LastSeen        = $null
        Sources         = @()
        IsLowReputation = $false
        Details         = @{}
    }
    
    try {
        # Check if private IP
        if (Test-PrivateIP -IPAddress $IPAddress) {
            $reputation.Score = 80
            $reputation.Category = 'Private IP'
            $reputation.Details['Note'] = 'Private IP addresses are generally trusted within the network'
            return $reputation
        }
        
        # In production, integrate with IP reputation services
        # For now, provide placeholder structure
        $reputation.Details['Note'] = 'Integrate with IP reputation services (AbuseIPDB, IPVoid, etc.)'
        
        return $reputation
    }
    catch {
        Write-Verbose "IP reputation error: $_"
        return $reputation
    }
}

function Get-DomainReputation {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [string]$AccessToken
    )
    
    $reputation = @{
        Score           = 50
        Category        = 'Unknown'
        Prevalence      = 0
        FirstSeen       = $null
        LastSeen        = $null
        Sources         = @()
        IsLowReputation = $false
        Details         = @{}
    }
    
    try {
        # Check domain age (newly registered domains are suspicious)
        # In production, use WHOIS lookup or domain age services
        
        # Check if domain is in common safe lists (microsoft.com, google.com, etc.)
        $safeDomains = @('microsoft.com', 'office365.com', 'google.com', 'amazon.com', 'apple.com')
        
        foreach ($safeDomain in $safeDomains) {
            if ($Domain -like "*$safeDomain") {
                $reputation.Score = 90
                $reputation.Category = 'Trusted'
                $reputation.Details['Note'] = 'Domain matches trusted pattern'
                return $reputation
            }
        }
        
        $reputation.Details['Note'] = 'Integrate with domain reputation services (VirusTotal, URLVoid, etc.)'
        
        return $reputation
    }
    catch {
        Write-Verbose "Domain reputation error: $_"
        return $reputation
    }
}

function Get-CloudAppReputation {
    [CmdletBinding()]
    param(
        [string]$AppId,
        [string]$AccessToken
    )
    
    $reputation = @{
        Score           = 50
        Category        = 'Unknown'
        Prevalence      = 0
        FirstSeen       = $null
        LastSeen        = $null
        Sources         = @()
        IsLowReputation = $false
        Details         = @{}
    }
    
    try {
        # In production, integrate with Microsoft Defender for Cloud Apps API
        $reputation.Details['Note'] = 'Use MCAS API to retrieve app risk scores and categories'
        
        return $reputation
    }
    catch {
        Write-Verbose "Cloud app reputation error: $_"
        return $reputation
    }
}

function Get-EntityIndicatorValue {
    [CmdletBinding()]
    param($Entity)
    
    switch ($Entity.EntityType) {
        'File' { return $Entity.NormalizedData.FileHash.SHA256 }
        'IP' { return $Entity.NormalizedData.IPAddress }
        'DNS' { return $Entity.NormalizedData.DomainName }
        'CloudApp' { return $Entity.NormalizedData.AppName }
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
    'Invoke-ReputationEnrichment',
    'Get-FileReputation',
    'Get-IPReputation',
    'Get-DomainReputation',
    'Get-CloudAppReputation'
)
