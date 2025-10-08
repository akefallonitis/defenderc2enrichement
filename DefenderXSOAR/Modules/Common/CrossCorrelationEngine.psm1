<#
.SYNOPSIS
    Cross-Correlation Engine for DefenderXSOAR
.DESCRIPTION
    Implements advanced correlation across all Defender products to detect multi-product attack scenarios
#>

function Invoke-CrossProductCorrelation {
    <#
    .SYNOPSIS
        Performs cross-product correlation analysis
    .PARAMETER ProductResults
        Results from all product workers
    .PARAMETER TimeWindow
        Time window in minutes for correlation (default: 60)
    .EXAMPLE
        Invoke-CrossProductCorrelation -ProductResults $results -TimeWindow 120
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$ProductResults,
        
        [Parameter(Mandatory = $false)]
        [int]$TimeWindow = 60
    )
    
    $correlations = @{
        EmailToEndpoint     = @()
        IdentityToEndpoint  = @()
        CloudToIdentity     = @()
        EndpointToNetwork   = @()
        FullKillChain       = @()
        RiskLevel           = 'Low'
        CorrelationScore    = 0
    }
    
    try {
        # Email → Endpoint Correlation (Phishing leads to malware)
        $correlations.EmailToEndpoint = Get-EmailToEndpointCorrelation -ProductResults $ProductResults -TimeWindow $TimeWindow
        
        # Identity → Multiple Endpoints (Lateral movement)
        $correlations.IdentityToEndpoint = Get-IdentityToEndpointCorrelation -ProductResults $ProductResults -TimeWindow $TimeWindow
        
        # Cloud → Identity (Unusual cloud access + risky sign-ins)
        $correlations.CloudToIdentity = Get-CloudToIdentityCorrelation -ProductResults $ProductResults -TimeWindow $TimeWindow
        
        # Endpoint → Network (Device compromise + C2 communications)
        $correlations.EndpointToNetwork = Get-EndpointToNetworkCorrelation -ProductResults $ProductResults -TimeWindow $TimeWindow
        
        # Full Kill Chain (Identity → Email → Cloud multi-stage attack)
        $correlations.FullKillChain = Get-FullKillChainCorrelation -ProductResults $ProductResults -TimeWindow $TimeWindow
        
        # Calculate overall correlation score
        $correlations.CorrelationScore = Calculate-CorrelationScore -Correlations $correlations
        
        # Determine risk level based on correlations
        $correlations.RiskLevel = Get-CorrelationRiskLevel -CorrelationScore $correlations.CorrelationScore
        
        return $correlations
    }
    catch {
        Write-Error "Cross-product correlation failed: $_"
        return $correlations
    }
}

function Get-EmailToEndpointCorrelation {
    [CmdletBinding()]
    param($ProductResults, $TimeWindow)
    
    $correlations = @()
    
    try {
        # Check if MDO and MDE data exists
        if (-not $ProductResults.ContainsKey('MDO') -or -not $ProductResults.ContainsKey('MDE')) {
            return $correlations
        }
        
        $mdoAlerts = $ProductResults['MDO'].RelatedAlerts
        $mdeAlerts = $ProductResults['MDE'].RelatedAlerts
        
        # Correlate by user and time
        foreach ($emailAlert in $mdoAlerts) {
            foreach ($endpointAlert in $mdeAlerts) {
                # Check time proximity
                $timeDiff = [Math]::Abs(($emailAlert.Timestamp - $endpointAlert.Timestamp).TotalMinutes)
                
                if ($timeDiff -le $TimeWindow) {
                    # Check user correlation
                    if ($emailAlert.UserPrincipalName -and $endpointAlert.UserPrincipalName -and 
                        $emailAlert.UserPrincipalName -eq $endpointAlert.UserPrincipalName) {
                        
                        $correlations += @{
                            Type            = 'EmailToEndpoint'
                            Description     = 'Phishing email followed by malware execution'
                            EmailAlert      = $emailAlert.Title
                            EndpointAlert   = $endpointAlert.Title
                            User            = $emailAlert.UserPrincipalName
                            TimeGapMinutes  = [int]$timeDiff
                            RiskScore       = 85
                            Severity        = 'High'
                        }
                    }
                }
            }
        }
        
        return $correlations
    }
    catch {
        Write-Verbose "Email to endpoint correlation error: $_"
        return $correlations
    }
}

function Get-IdentityToEndpointCorrelation {
    [CmdletBinding()]
    param($ProductResults, $TimeWindow)
    
    $correlations = @()
    
    try {
        # Check if EntraID/MDI and MDE data exists
        if (-not $ProductResults.ContainsKey('MDE')) {
            return $correlations
        }
        
        $identityAlerts = @()
        if ($ProductResults.ContainsKey('EntraID')) {
            $identityAlerts += $ProductResults['EntraID'].RelatedAlerts
        }
        if ($ProductResults.ContainsKey('MDI')) {
            $identityAlerts += $ProductResults['MDI'].RelatedAlerts
        }
        
        $mdeAlerts = $ProductResults['MDE'].RelatedAlerts
        
        # Group MDE alerts by user to detect lateral movement
        $userDeviceMap = @{}
        foreach ($alert in $mdeAlerts) {
            if ($alert.UserPrincipalName) {
                if (-not $userDeviceMap.ContainsKey($alert.UserPrincipalName)) {
                    $userDeviceMap[$alert.UserPrincipalName] = @()
                }
                $userDeviceMap[$alert.UserPrincipalName] += $alert
            }
        }
        
        # Detect users accessing multiple devices (lateral movement pattern)
        foreach ($user in $userDeviceMap.Keys) {
            $devices = $userDeviceMap[$user] | Select-Object -ExpandProperty DeviceName -Unique
            
            if ($devices.Count -gt 2) {
                # Check if there's a corresponding identity alert
                $relatedIdentityAlert = $identityAlerts | Where-Object { $_.UserPrincipalName -eq $user } | Select-Object -First 1
                
                $correlations += @{
                    Type            = 'IdentityToEndpoint'
                    Description     = 'Compromised account lateral movement across multiple devices'
                    User            = $user
                    DeviceCount     = $devices.Count
                    Devices         = $devices
                    IdentityAlert   = if ($relatedIdentityAlert) { $relatedIdentityAlert.Title } else { 'No specific identity alert' }
                    RiskScore       = 90
                    Severity        = 'Critical'
                }
            }
        }
        
        return $correlations
    }
    catch {
        Write-Verbose "Identity to endpoint correlation error: $_"
        return $correlations
    }
}

function Get-CloudToIdentityCorrelation {
    [CmdletBinding()]
    param($ProductResults, $TimeWindow)
    
    $correlations = @()
    
    try {
        # Check if MCAS and EntraID data exists
        if (-not $ProductResults.ContainsKey('MCAS') -or -not $ProductResults.ContainsKey('EntraID')) {
            return $correlations
        }
        
        $mcasAlerts = $ProductResults['MCAS'].RelatedAlerts
        $entraIdAlerts = $ProductResults['EntraID'].RelatedAlerts
        
        # Correlate cloud app anomalies with risky sign-ins
        foreach ($cloudAlert in $mcasAlerts) {
            foreach ($identityAlert in $entraIdAlerts) {
                $timeDiff = [Math]::Abs(($cloudAlert.Timestamp - $identityAlert.Timestamp).TotalMinutes)
                
                if ($timeDiff -le $TimeWindow) {
                    if ($cloudAlert.UserPrincipalName -and $identityAlert.UserPrincipalName -and 
                        $cloudAlert.UserPrincipalName -eq $identityAlert.UserPrincipalName) {
                        
                        $correlations += @{
                            Type            = 'CloudToIdentity'
                            Description     = 'Unusual cloud access combined with risky authentication'
                            CloudAlert      = $cloudAlert.Title
                            IdentityAlert   = $identityAlert.Title
                            User            = $cloudAlert.UserPrincipalName
                            TimeGapMinutes  = [int]$timeDiff
                            RiskScore       = 80
                            Severity        = 'High'
                        }
                    }
                }
            }
        }
        
        return $correlations
    }
    catch {
        Write-Verbose "Cloud to identity correlation error: $_"
        return $correlations
    }
}

function Get-EndpointToNetworkCorrelation {
    [CmdletBinding()]
    param($ProductResults, $TimeWindow)
    
    $correlations = @()
    
    try {
        # Check if MDE data exists
        if (-not $ProductResults.ContainsKey('MDE')) {
            return $correlations
        }
        
        $mdeAlerts = $ProductResults['MDE'].RelatedAlerts
        
        # Look for combination of malware and network alerts
        $malwareAlerts = $mdeAlerts | Where-Object { $_.Category -like '*Malware*' -or $_.Category -like '*Execution*' }
        $networkAlerts = $mdeAlerts | Where-Object { $_.Category -like '*Network*' -or $_.Category -like '*C2*' -or $_.Category -like '*Command*Control*' }
        
        foreach ($malware in $malwareAlerts) {
            foreach ($network in $networkAlerts) {
                if ($malware.DeviceName -eq $network.DeviceName) {
                    $timeDiff = [Math]::Abs(($malware.Timestamp - $network.Timestamp).TotalMinutes)
                    
                    if ($timeDiff -le $TimeWindow) {
                        $correlations += @{
                            Type            = 'EndpointToNetwork'
                            Description     = 'Malware execution followed by suspicious network activity (possible C2)'
                            MalwareAlert    = $malware.Title
                            NetworkAlert    = $network.Title
                            Device          = $malware.DeviceName
                            TimeGapMinutes  = [int]$timeDiff
                            RiskScore       = 95
                            Severity        = 'Critical'
                        }
                    }
                }
            }
        }
        
        return $correlations
    }
    catch {
        Write-Verbose "Endpoint to network correlation error: $_"
        return $correlations
    }
}

function Get-FullKillChainCorrelation {
    [CmdletBinding()]
    param($ProductResults, $TimeWindow)
    
    $correlations = @()
    
    try {
        # Detect full kill chain: Identity → Email → Cloud
        if (-not ($ProductResults.ContainsKey('EntraID') -and 
                  $ProductResults.ContainsKey('MDO') -and 
                  $ProductResults.ContainsKey('MCAS'))) {
            return $correlations
        }
        
        $identityAlerts = $ProductResults['EntraID'].RelatedAlerts
        $emailAlerts = $ProductResults['MDO'].RelatedAlerts
        $cloudAlerts = $ProductResults['MCAS'].RelatedAlerts
        
        # Look for users appearing in all three product alerts
        $identityUsers = $identityAlerts | Where-Object { $_.UserPrincipalName } | Select-Object -ExpandProperty UserPrincipalName -Unique
        
        foreach ($user in $identityUsers) {
            $userEmailAlerts = $emailAlerts | Where-Object { $_.UserPrincipalName -eq $user }
            $userCloudAlerts = $cloudAlerts | Where-Object { $_.UserPrincipalName -eq $user }
            
            if ($userEmailAlerts -and $userCloudAlerts) {
                $correlations += @{
                    Type            = 'FullKillChain'
                    Description     = 'Multi-stage attack spanning Identity, Email, and Cloud products'
                    User            = $user
                    IdentityAlerts  = $identityAlerts | Where-Object { $_.UserPrincipalName -eq $user } | Select-Object -ExpandProperty Title
                    EmailAlerts     = $userEmailAlerts | Select-Object -ExpandProperty Title
                    CloudAlerts     = $userCloudAlerts | Select-Object -ExpandProperty Title
                    RiskScore       = 98
                    Severity        = 'Critical'
                    Impact          = 'Complete account compromise with data exfiltration risk'
                }
            }
        }
        
        return $correlations
    }
    catch {
        Write-Verbose "Full kill chain correlation error: $_"
        return $correlations
    }
}

function Calculate-CorrelationScore {
    [CmdletBinding()]
    param($Correlations)
    
    $score = 0
    
    # Weight different correlation types
    $weights = @{
        EmailToEndpoint    = 20
        IdentityToEndpoint = 25
        CloudToIdentity    = 20
        EndpointToNetwork  = 30
        FullKillChain      = 50
    }
    
    foreach ($type in $weights.Keys) {
        if ($Correlations.$type -and $Correlations.$type.Count -gt 0) {
            $score += $weights[$type]
        }
    }
    
    # Cap at 100
    return [Math]::Min($score, 100)
}

function Get-CorrelationRiskLevel {
    [CmdletBinding()]
    param([int]$CorrelationScore)
    
    if ($CorrelationScore -ge 80) { return 'Critical' }
    if ($CorrelationScore -ge 60) { return 'High' }
    if ($CorrelationScore -ge 40) { return 'Medium' }
    if ($CorrelationScore -ge 20) { return 'Low' }
    return 'Informational'
}

# Export module members
Export-ModuleMember -Function @(
    'Invoke-CrossProductCorrelation',
    'Get-EmailToEndpointCorrelation',
    'Get-IdentityToEndpointCorrelation',
    'Get-CloudToIdentityCorrelation',
    'Get-EndpointToNetworkCorrelation',
    'Get-FullKillChainCorrelation',
    'Calculate-CorrelationScore',
    'Get-CorrelationRiskLevel'
)
