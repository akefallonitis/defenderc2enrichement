<#
.SYNOPSIS
    Microsoft Entra ID Worker module
.DESCRIPTION
    Provides EntraID-specific enrichment, identity protection, and risky sign-in analysis
#>

# Import common modules
$CommonPath = Join-Path $PSScriptRoot "..\Common"
Import-Module (Join-Path $CommonPath "AuthenticationHelper.psm1") -Force
Import-Module (Join-Path $CommonPath "EntityNormalizer.psm1") -Force

function Get-EntraIDRiskyUsers {
    <#
    .SYNOPSIS
        Gets risky users from Entra ID
    .PARAMETER AccessToken
        Graph API access token
    .PARAMETER RiskLevel
        Filter by risk level
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('low', 'medium', 'high', 'none', 'hidden')]
        [string]$RiskLevel
    )
    
    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        $uri = "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers"
        if ($RiskLevel) {
            $uri += "?`$filter=riskLevel eq '$RiskLevel'"
        }
        
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        return $response.value
    }
    catch {
        Write-Error "Failed to get risky users: $_"
        return @()
    }
}

function Get-EntraIDRiskySignIns {
    <#
    .SYNOPSIS
        Gets risky sign-ins
    .PARAMETER AccessToken
        Graph API access token
    .PARAMETER UserPrincipalName
        Filter by user
    .PARAMETER Top
        Number of results to return
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory = $false)]
        [string]$UserPrincipalName,
        
        [Parameter(Mandatory = $false)]
        [int]$Top = 100
    )
    
    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        $uri = "https://graph.microsoft.com/v1.0/identityProtection/riskySignIns?`$top=$Top"
        if ($UserPrincipalName) {
            $uri += "&`$filter=userPrincipalName eq '$UserPrincipalName'"
        }
        
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        return $response.value
    }
    catch {
        Write-Error "Failed to get risky sign-ins: $_"
        return @()
    }
}

function Get-EntraIDRiskDetections {
    <#
    .SYNOPSIS
        Gets risk detections
    .PARAMETER AccessToken
        Graph API access token
    .PARAMETER UserPrincipalName
        Filter by user
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory = $false)]
        [string]$UserPrincipalName
    )
    
    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        $uri = "https://graph.microsoft.com/v1.0/identityProtection/riskDetections"
        if ($UserPrincipalName) {
            $uri += "?`$filter=userPrincipalName eq '$UserPrincipalName'"
        }
        
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        return $response.value
    }
    catch {
        Write-Error "Failed to get risk detections: $_"
        return @()
    }
}

function Get-EntraIDConditionalAccessViolations {
    <#
    .SYNOPSIS
        Gets conditional access policy violations
    .PARAMETER AccessToken
        Graph API access token
    .PARAMETER UserPrincipalName
        Filter by user
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory = $false)]
        [string]$UserPrincipalName
    )
    
    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        # Get sign-in logs with CA failures
        $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=conditionalAccessStatus eq 'failure'"
        if ($UserPrincipalName) {
            $uri += " and userPrincipalName eq '$UserPrincipalName'"
        }
        $uri += "&`$top=100"
        
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        return $response.value
    }
    catch {
        Write-Error "Failed to get CA violations: $_"
        return @()
    }
}

function Get-EntraIDMFAStatus {
    <#
    .SYNOPSIS
        Gets MFA status for a user
    .PARAMETER UserId
        User ID or UPN
    .PARAMETER AccessToken
        Graph API access token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserId,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )
    
    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        # Get user's authentication methods
        $uri = "https://graph.microsoft.com/v1.0/users/$UserId/authentication/methods"
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        
        $hasMFA = $false
        $mfaMethods = @()
        
        foreach ($method in $response.value) {
            if ($method.'@odata.type' -match 'phoneAuthentication|microsoftAuthenticator|fido2|windowsHelloForBusiness') {
                $hasMFA = $true
                $mfaMethods += $method.'@odata.type'
            }
        }
        
        return @{
            HasMFA = $hasMFA
            MFAMethods = $mfaMethods
            MethodCount = $mfaMethods.Count
        }
    }
    catch {
        Write-Error "Failed to get MFA status: $_"
        return @{
            HasMFA = $false
            MFAMethods = @()
            MethodCount = 0
        }
    }
}

function Get-EntraIDUserActivity {
    <#
    .SYNOPSIS
        Gets user activity and sign-in patterns
    .PARAMETER UserPrincipalName
        User principal name
    .PARAMETER AccessToken
        Graph API access token
    .PARAMETER Days
        Number of days to look back
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory = $false)]
        [int]$Days = 7
    )
    
    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        $startDate = (Get-Date).AddDays(-$Days).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=userPrincipalName eq '$UserPrincipalName' and createdDateTime ge $startDate&`$top=100"
        
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        
        $signIns = $response.value
        
        # Analyze patterns
        $uniqueIPs = ($signIns | Select-Object -ExpandProperty ipAddress -Unique).Count
        $uniqueLocations = ($signIns | Select-Object -ExpandProperty location -Unique).Count
        $failedSignIns = ($signIns | Where-Object { $_.status.errorCode -ne 0 }).Count
        $successfulSignIns = ($signIns | Where-Object { $_.status.errorCode -eq 0 }).Count
        
        return @{
            TotalSignIns = $signIns.Count
            UniqueIPs = $uniqueIPs
            UniqueLocations = $uniqueLocations
            FailedSignIns = $failedSignIns
            SuccessfulSignIns = $successfulSignIns
            SignIns = $signIns
        }
    }
    catch {
        Write-Error "Failed to get user activity: $_"
        return @{
            TotalSignIns = 0
            UniqueIPs = 0
            UniqueLocations = 0
            FailedSignIns = 0
            SuccessfulSignIns = 0
            SignIns = @()
        }
    }
}

function Start-EntraIDEnrichment {
    <#
    .SYNOPSIS
        Performs comprehensive Entra ID enrichment
    .PARAMETER Entities
        Array of entities to enrich
    .PARAMETER AccessToken
        Graph API access token
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
        # Get all risky users
        $riskyUsers = Get-EntraIDRiskyUsers -AccessToken $AccessToken
        if ($riskyUsers.Count -gt 0) {
            $enrichmentResults.ThreatIntel += @{
                Type = "RiskyUsers"
                Count = $riskyUsers.Count
                Users = $riskyUsers
            }
        }
        
        foreach ($entity in $Entities) {
            Write-Verbose "Processing Entra ID entity: $($entity.Type)"
            
            if ($entity.Type -eq 'User') {
                $userPrincipalName = $entity.UserPrincipalName ?? $entity.Name
                $userId = $entity.ObjectId ?? $userPrincipalName
                
                if ($userPrincipalName) {
                    # Normalize user entity
                    $normalizedUser = ConvertTo-NormalizedEntity -EntityData $entity -EntityType 'User' -Source 'EntraID'
                    $enrichmentResults.Entities += $normalizedUser
                    
                    # Get risky sign-ins
                    $riskySignIns = Get-EntraIDRiskySignIns -AccessToken $AccessToken -UserPrincipalName $userPrincipalName
                    if ($riskySignIns.Count -gt 0) {
                        $enrichmentResults.UEBAInsights += @{
                            Type = "RiskySignIns"
                            User = $userPrincipalName
                            Count = $riskySignIns.Count
                            SignIns = $riskySignIns
                        }
                        
                        $highRiskSignIns = ($riskySignIns | Where-Object { $_.riskLevel -eq 'high' }).Count
                        $enrichmentResults.RiskScore += ($highRiskSignIns * 20) + ($riskySignIns.Count * 5)
                        
                        if ($highRiskSignIns -gt 0) {
                            $enrichmentResults.Recommendations += "User $userPrincipalName has $highRiskSignIns high-risk sign-ins"
                        }
                    }
                    
                    # Get risk detections
                    $riskDetections = Get-EntraIDRiskDetections -AccessToken $AccessToken -UserPrincipalName $userPrincipalName
                    if ($riskDetections.Count -gt 0) {
                        $enrichmentResults.ThreatIntel += @{
                            Type = "RiskDetections"
                            User = $userPrincipalName
                            Count = $riskDetections.Count
                            Detections = $riskDetections
                        }
                        $enrichmentResults.RiskScore += ($riskDetections.Count * 10)
                    }
                    
                    # Get CA violations
                    $caViolations = Get-EntraIDConditionalAccessViolations -AccessToken $AccessToken -UserPrincipalName $userPrincipalName
                    if ($caViolations.Count -gt 0) {
                        $enrichmentResults.UEBAInsights += @{
                            Type = "CAViolations"
                            User = $userPrincipalName
                            Count = $caViolations.Count
                            Violations = $caViolations
                        }
                        $enrichmentResults.RiskScore += ($caViolations.Count * 5)
                        $enrichmentResults.Recommendations += "User has $($caViolations.Count) conditional access policy violations"
                    }
                    
                    # Get MFA status
                    if ($userId) {
                        $mfaStatus = Get-EntraIDMFAStatus -UserId $userId -AccessToken $AccessToken
                        if (-not $mfaStatus.HasMFA) {
                            $enrichmentResults.RiskScore += 15
                            $enrichmentResults.Recommendations += "User $userPrincipalName does not have MFA enabled - critical security gap"
                        }
                        
                        $enrichmentResults.ThreatIntel += @{
                            Type = "MFAStatus"
                            User = $userPrincipalName
                            HasMFA = $mfaStatus.HasMFA
                            Methods = $mfaStatus.MFAMethods
                        }
                    }
                    
                    # Get user activity patterns
                    $userActivity = Get-EntraIDUserActivity -UserPrincipalName $userPrincipalName -AccessToken $AccessToken
                    $enrichmentResults.UEBAInsights += @{
                        Type = "UserActivityPattern"
                        User = $userPrincipalName
                        Activity = $userActivity
                    }
                    
                    # Detect anomalies
                    if ($userActivity.UniqueIPs -gt 10) {
                        $enrichmentResults.RiskScore += 20
                        $enrichmentResults.Recommendations += "User signing in from $($userActivity.UniqueIPs) different IPs - possible account compromise"
                    }
                    
                    if ($userActivity.FailedSignIns -gt 5) {
                        $enrichmentResults.RiskScore += 15
                        $enrichmentResults.Recommendations += "Multiple failed sign-in attempts detected - possible brute force attack"
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
        if ($riskyUsers.Count -gt 5) {
            $enrichmentResults.Recommendations += "Multiple risky users detected in tenant - review identity protection policies"
        }
        
        return $enrichmentResults
    }
    catch {
        Write-Error "Entra ID enrichment failed: $_"
        throw
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Get-EntraIDRiskyUsers',
    'Get-EntraIDRiskySignIns',
    'Get-EntraIDRiskDetections',
    'Get-EntraIDConditionalAccessViolations',
    'Get-EntraIDMFAStatus',
    'Get-EntraIDUserActivity',
    'Start-EntraIDEnrichment'
)
