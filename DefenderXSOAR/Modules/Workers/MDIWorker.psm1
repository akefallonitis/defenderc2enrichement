<#
.SYNOPSIS
    Microsoft Defender for Identity Worker module
.DESCRIPTION
    Provides MDI-specific enrichment, identity compromise detection, and lateral movement analysis
#>

# Import common modules
$CommonPath = Join-Path $PSScriptRoot "..\Common"
Import-Module (Join-Path $CommonPath "AuthenticationHelper.psm1") -Force
Import-Module (Join-Path $CommonPath "EntityNormalizer.psm1") -Force

function Get-MDISecurityAlerts {
    <#
    .SYNOPSIS
        Gets security alerts from MDI using Graph Security API
    .PARAMETER AccessToken
        Graph API access token
    .PARAMETER Filter
        Optional OData filter
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory = $false)]
        [string]$Filter
    )
    
    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        $uri = "https://graph.microsoft.com/v1.0/security/alerts"
        if ($Filter) {
            $uri += "?`$filter=$Filter"
        }
        
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        
        # Filter for MDI alerts
        $mdiAlerts = $response.value | Where-Object { $_.vendorInformation.provider -eq 'IPC' -or $_.vendorInformation.provider -eq 'AATP' }
        
        return $mdiAlerts
    }
    catch {
        Write-Error "Failed to get MDI security alerts: $_"
        return @()
    }
}

function Get-MDIUserRiskEvents {
    <#
    .SYNOPSIS
        Gets risk events for a user
    .PARAMETER UserId
        User object ID or UPN
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
        
        # Try to get user risk detections
        $uri = "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?`$filter=userPrincipalName eq '$UserId'"
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        
        return $response.value
    }
    catch {
        Write-Error "Failed to get user risk events: $_"
        return @()
    }
}

function Get-MDILateralMovementPaths {
    <#
    .SYNOPSIS
        Simulates lateral movement path detection based on security alerts
    .PARAMETER UserId
        User identifier
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
        # Get alerts related to lateral movement for this user
        $filter = "userStates/any(u: u/userPrincipalName eq '$UserId')"
        $alerts = Get-MDISecurityAlerts -AccessToken $AccessToken -Filter $filter
        
        $lateralMovementAlerts = $alerts | Where-Object { 
            $_.title -like "*lateral*" -or 
            $_.title -like "*privilege*" -or 
            $_.title -like "*credential*" 
        }
        
        return $lateralMovementAlerts
    }
    catch {
        Write-Error "Failed to get lateral movement paths: $_"
        return @()
    }
}

function Get-MDIPrivilegeEscalation {
    <#
    .SYNOPSIS
        Detects potential privilege escalation attempts
    .PARAMETER UserId
        User identifier
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
        
        # Get user's directory roles
        $uri = "https://graph.microsoft.com/v1.0/users/$UserId/memberOf"
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        
        $privilegedRoles = $response.value | Where-Object { 
            $_.'@odata.type' -eq '#microsoft.graph.directoryRole' -and
            ($_.displayName -like "*Admin*" -or $_.displayName -like "*Global*")
        }
        
        return @{
            HasPrivilegedRoles = $privilegedRoles.Count -gt 0
            PrivilegedRoles = $privilegedRoles
            RoleCount = $privilegedRoles.Count
        }
    }
    catch {
        Write-Error "Failed to check privilege escalation: $_"
        return @{
            HasPrivilegedRoles = $false
            PrivilegedRoles = @()
            RoleCount = 0
        }
    }
}

function Get-MDIKerberosAttacks {
    <#
    .SYNOPSIS
        Detects Kerberos-related attacks
    .PARAMETER AccessToken
        Graph API access token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )
    
    try {
        $alerts = Get-MDISecurityAlerts -AccessToken $AccessToken
        
        $kerberosAlerts = $alerts | Where-Object { 
            $_.title -like "*kerberos*" -or 
            $_.title -like "*golden ticket*" -or 
            $_.title -like "*silver ticket*" -or
            $_.title -like "*pass-the-ticket*"
        }
        
        return $kerberosAlerts
    }
    catch {
        Write-Error "Failed to detect Kerberos attacks: $_"
        return @()
    }
}

function Start-MDIEnrichment {
    <#
    .SYNOPSIS
        Performs comprehensive MDI enrichment
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
        # Get all MDI security alerts
        $mdiAlerts = Get-MDISecurityAlerts -AccessToken $AccessToken
        $enrichmentResults.RelatedAlerts = $mdiAlerts
        
        # Check for Kerberos attacks
        $kerberosAttacks = Get-MDIKerberosAttacks -AccessToken $AccessToken
        if ($kerberosAttacks.Count -gt 0) {
            $enrichmentResults.ThreatIntel += @{
                Type = "KerberosAttack"
                Count = $kerberosAttacks.Count
                Attacks = $kerberosAttacks
            }
            $enrichmentResults.RiskScore += ($kerberosAttacks.Count * 30)
            $enrichmentResults.Recommendations += "Kerberos attack detected - immediate investigation required"
        }
        
        foreach ($entity in $Entities) {
            Write-Verbose "Processing MDI entity: $($entity.Type)"
            
            if ($entity.Type -eq 'User') {
                $userId = $entity.Name ?? $entity.UserPrincipalName ?? $entity.ObjectId
                
                if ($userId) {
                    # Get risk events
                    $riskEvents = Get-MDIUserRiskEvents -UserId $userId -AccessToken $AccessToken
                    
                    if ($riskEvents.Count -gt 0) {
                        $enrichmentResults.UEBAInsights += @{
                            Type = "UserRiskEvents"
                            User = $userId
                            Count = $riskEvents.Count
                            Events = $riskEvents
                        }
                        
                        $highRiskEvents = ($riskEvents | Where-Object { $_.riskLevel -eq 'high' }).Count
                        $enrichmentResults.RiskScore += ($highRiskEvents * 20) + ($riskEvents.Count * 5)
                        
                        if ($highRiskEvents -gt 0) {
                            $enrichmentResults.Recommendations += "User $userId has $highRiskEvents high-risk events"
                        }
                    }
                    
                    # Check for lateral movement
                    $lateralMovement = Get-MDILateralMovementPaths -UserId $userId -AccessToken $AccessToken
                    if ($lateralMovement.Count -gt 0) {
                        $enrichmentResults.ThreatIntel += @{
                            Type = "LateralMovement"
                            User = $userId
                            PathCount = $lateralMovement.Count
                            Paths = $lateralMovement
                        }
                        $enrichmentResults.RiskScore += 40
                        $enrichmentResults.Recommendations += "Lateral movement detected for user $userId - potential breach"
                    }
                    
                    # Check for privilege escalation
                    $privEscalation = Get-MDIPrivilegeEscalation -UserId $userId -AccessToken $AccessToken
                    if ($privEscalation.HasPrivilegedRoles) {
                        $enrichmentResults.ThreatIntel += @{
                            Type = "PrivilegedAccess"
                            User = $userId
                            RoleCount = $privEscalation.RoleCount
                            Roles = $privEscalation.PrivilegedRoles
                        }
                        
                        if ($riskEvents.Count -gt 0) {
                            $enrichmentResults.RiskScore += 30
                            $enrichmentResults.Recommendations += "Privileged user $userId has active risk events - critical priority"
                        }
                    }
                    
                    # Normalize user entity
                    $normalizedUser = ConvertTo-NormalizedEntity -EntityData $entity -EntityType 'User' -Source 'MDI'
                    $enrichmentResults.Entities += $normalizedUser
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
        if ($mdiAlerts.Count -gt 5) {
            $enrichmentResults.Recommendations += "Multiple MDI alerts detected - review identity security posture"
        }
        
        return $enrichmentResults
    }
    catch {
        Write-Error "MDI enrichment failed: $_"
        throw
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Get-MDISecurityAlerts',
    'Get-MDIUserRiskEvents',
    'Get-MDILateralMovementPaths',
    'Get-MDIPrivilegeEscalation',
    'Get-MDIKerberosAttacks',
    'Start-MDIEnrichment'
)
