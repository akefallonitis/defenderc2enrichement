<#
.SYNOPSIS
    Entra ID Hunting Playbooks with real KQL queries
.DESCRIPTION
    Provides Entra ID-specific hunting playbooks for identity protection
#>

function Invoke-EntraIDRiskySignInAnalysis {
    <#
    .SYNOPSIS
        Analyzes risky sign-ins
    .PARAMETER UserPrincipalName
        User to analyze
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$UserPrincipalName
    )
    
    $userFilter = if ($UserPrincipalName) { "| where UserPrincipalName == '$UserPrincipalName'" } else { "" }
    
    $query = @"
// Risky Sign-In Analysis
SigninLogs
| where TimeGenerated > ago(7d)
| where RiskLevelDuringSignIn != "none"
$userFilter
| summarize 
    SignInCount = count(),
    HighRiskSignIns = countif(RiskLevelDuringSignIn == "high"),
    MediumRiskSignIns = countif(RiskLevelDuringSignIn == "medium"),
    UniqueLocations = dcount(Location),
    UniqueIPs = dcount(IPAddress),
    Locations = make_set(Location),
    RiskDetails = make_set(RiskDetail)
    by UserPrincipalName, bin(TimeGenerated, 1h)
| extend RiskScore = (HighRiskSignIns * 20) + (MediumRiskSignIns * 10) + (UniqueLocations * 5)
| where RiskScore > 30
| order by RiskScore desc
"@
    
    return @{
        PlaybookName = "RiskySignInAnalysis"
        Query = $query
        Description = "Analyzes risky sign-in patterns and calculates risk scores"
    }
}

function Invoke-EntraIDConditionalAccessViolations {
    <#
    .SYNOPSIS
        Detects conditional access policy violations
    #>
    [CmdletBinding()]
    param()
    
    $query = @"
// Conditional Access Violations
SigninLogs
| where TimeGenerated > ago(7d)
| where ConditionalAccessStatus == "failure"
| summarize 
    ViolationCount = count(),
    UniqueUsers = dcount(UserPrincipalName),
    Users = make_set(UserPrincipalName),
    Policies = make_set(ConditionalAccessPolicies),
    Locations = make_set(Location)
    by AppDisplayName, bin(TimeGenerated, 1h)
| extend RiskLevel = case(
    ViolationCount > 50, "Critical",
    ViolationCount > 20, "High",
    ViolationCount > 10, "Medium",
    "Low")
| order by ViolationCount desc
"@
    
    return @{
        PlaybookName = "ConditionalAccessViolations"
        Query = $query
        Description = "Identifies and categorizes conditional access policy violations"
    }
}

function Invoke-EntraIDIdentityProtectionAlerts {
    <#
    .SYNOPSIS
        Analyzes identity protection alerts
    #>
    [CmdletBinding()]
    param()
    
    $query = @"
// Identity Protection Alerts
AADRiskDetections
| where TimeGenerated > ago(7d)
| summarize 
    DetectionCount = count(),
    HighRiskDetections = countif(RiskLevel == "high"),
    MediumRiskDetections = countif(RiskLevel == "medium"),
    DetectionTypes = make_set(DetectionType),
    Sources = make_set(Source)
    by UserPrincipalName
| extend TotalRiskScore = (HighRiskDetections * 25) + (MediumRiskDetections * 10)
| where TotalRiskScore > 20
| order by TotalRiskScore desc
"@
    
    return @{
        PlaybookName = "IdentityProtectionAlerts"
        Query = $query
        Description = "Aggregates and prioritizes identity protection risk detections"
    }
}

function Invoke-EntraIDMFABypassAttempts {
    <#
    .SYNOPSIS
        Detects MFA bypass attempts
    #>
    [CmdletBinding()]
    param()
    
    $query = @"
// MFA Bypass Attempts
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType != "0"  // Failed sign-ins
| where AuthenticationRequirement == "multiFactorAuthentication"
| summarize 
    FailedMFACount = count(),
    UniqueIPs = dcount(IPAddress),
    IPs = make_set(IPAddress),
    Locations = make_set(Location),
    UserAgents = make_set(UserAgent),
    FailureReasons = make_set(ResultDescription)
    by UserPrincipalName, AppDisplayName
| where FailedMFACount > 5
| extend SuspicionLevel = case(
    FailedMFACount > 20, "Critical",
    FailedMFACount > 10, "High",
    UniqueIPs > 5, "High",
    "Medium")
| order by FailedMFACount desc
"@
    
    return @{
        PlaybookName = "MFABypassAttempts"
        Query = $query
        Description = "Identifies potential MFA bypass and brute force attempts"
    }
}

function Invoke-EntraIDAnomalousSignInPatterns {
    <#
    .SYNOPSIS
        Detects anomalous sign-in patterns
    .PARAMETER UserPrincipalName
        User to analyze
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )
    
    $query = @"
// Anomalous Sign-In Patterns
let targetUser = '$UserPrincipalName';
let baseline = SigninLogs
| where TimeGenerated between (ago(30d) .. ago(7d))
| where UserPrincipalName == targetUser
| where ResultType == "0"
| summarize 
    AvgDailySignIns = count() / 23,
    BaselineLocations = dcount(Location),
    BaselineIPs = dcount(IPAddress),
    BaselineApps = dcount(AppDisplayName);
let recent = SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == targetUser
| where ResultType == "0"
| summarize 
    RecentSignIns = count(),
    RecentLocations = dcount(Location),
    RecentIPs = dcount(IPAddress),
    RecentApps = dcount(AppDisplayName),
    LocationList = make_set(Location),
    IPList = make_set(IPAddress)
    by bin(TimeGenerated, 1d);
recent
| extend baseline
| extend 
    SignInAnomaly = (RecentSignIns - AvgDailySignIns) / AvgDailySignIns * 100,
    LocationAnomaly = (RecentLocations - BaselineLocations) / BaselineLocations * 100,
    IPAnomaly = (RecentIPs - BaselineIPs) / BaselineIPs * 100
| where SignInAnomaly > 200 or LocationAnomaly > 150 or IPAnomaly > 150
| extend AnomalyScore = abs(SignInAnomaly) + abs(LocationAnomaly) + abs(IPAnomaly)
| order by AnomalyScore desc
"@
    
    return @{
        PlaybookName = "AnomalousSignInPatterns"
        Query = $query
        Description = "Detects sign-in patterns that deviate significantly from baseline behavior"
    }
}

function Get-EntraIDPlaybooks {
    <#
    .SYNOPSIS
        Returns all available Entra ID playbooks
    #>
    [CmdletBinding()]
    param()
    
    return @(
        @{ Name = "RiskySignInAnalysis"; Function = "Invoke-EntraIDRiskySignInAnalysis" }
        @{ Name = "ConditionalAccessViolations"; Function = "Invoke-EntraIDConditionalAccessViolations" }
        @{ Name = "IdentityProtectionAlerts"; Function = "Invoke-EntraIDIdentityProtectionAlerts" }
        @{ Name = "MFABypassAttempts"; Function = "Invoke-EntraIDMFABypassAttempts" }
        @{ Name = "AnomalousSignInPatterns"; Function = "Invoke-EntraIDAnomalousSignInPatterns" }
    )
}

# Export module members
Export-ModuleMember -Function @(
    'Invoke-EntraIDRiskySignInAnalysis',
    'Invoke-EntraIDConditionalAccessViolations',
    'Invoke-EntraIDIdentityProtectionAlerts',
    'Invoke-EntraIDMFABypassAttempts',
    'Invoke-EntraIDAnomalousSignInPatterns',
    'Get-EntraIDPlaybooks'
)
