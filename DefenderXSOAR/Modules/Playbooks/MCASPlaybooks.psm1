<#
.SYNOPSIS
    MCAS Hunting Playbooks with real KQL queries
.DESCRIPTION
    Provides MCAS-specific hunting playbooks for cloud app security
#>

function Invoke-MCASCloudAppRiskAssessment {
    <#
    .SYNOPSIS
        Assesses cloud app usage risks
    .PARAMETER Days
        Number of days to analyze
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$Days = 30
    )
    
    $query = @"
// Cloud App Risk Assessment
CloudAppEvents
| where Timestamp > ago($($Days)d)
| summarize 
    ActivityCount = count(),
    UniqueUsers = dcount(AccountObjectId),
    UniqueApps = dcount(ApplicationId),
    HighRiskActivities = countif(RiskScore > 70),
    MediumRiskActivities = countif(RiskScore between (40 .. 70))
    by ApplicationDisplayName
| extend RiskLevel = case(
    HighRiskActivities > 10, "Critical",
    HighRiskActivities > 5, "High",
    MediumRiskActivities > 20, "Medium",
    "Low")
| order by HighRiskActivities desc
"@
    
    return @{
        PlaybookName = "CloudAppRiskAssessment"
        Query = $query
        Description = "Assesses risks associated with cloud app usage patterns"
    }
}

function Invoke-MCASDataExfiltrationDetection {
    <#
    .SYNOPSIS
        Detects potential data exfiltration
    .PARAMETER UserPrincipalName
        User to investigate
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$UserPrincipalName
    )
    
    $userFilter = if ($UserPrincipalName) { "| where AccountUpn == '$UserPrincipalName'" } else { "" }
    
    $query = @"
// Data Exfiltration Detection
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileDownloaded", "FileUploaded", "FileSyncDownloaded")
$userFilter
| summarize 
    TotalFiles = count(),
    TotalSize = sum(FileSizeBytes),
    UniqueLocations = dcount(IPAddress),
    Locations = make_set(IPAddress),
    Apps = make_set(Application)
    by AccountUpn, bin(Timestamp, 1h)
| where TotalFiles > 50 or TotalSize > 1000000000  // 1GB threshold
| extend RiskScore = (TotalFiles * 2) + (TotalSize / 100000000)
| order by RiskScore desc
"@
    
    return @{
        PlaybookName = "DataExfiltrationDetection"
        Query = $query
        Description = "Detects unusual data download or upload patterns indicating exfiltration"
    }
}

function Invoke-MCASUserBehaviorAnalytics {
    <#
    .SYNOPSIS
        Analyzes user behavior patterns
    .PARAMETER UserPrincipalName
        User to analyze
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )
    
    $query = @"
// User Behavior Analytics
let targetUser = '$UserPrincipalName';
let userBaseline = CloudAppEvents
| where Timestamp between (ago(30d) .. ago(7d))
| where AccountUpn == targetUser
| summarize 
    BaselineActivityCount = count(),
    BaselineApps = dcount(Application),
    BaselineLocations = dcount(IPAddress)
    by bin(Timestamp, 1d)
| summarize 
    AvgDailyActivity = avg(BaselineActivityCount),
    AvgDailyApps = avg(BaselineApps),
    AvgDailyLocations = avg(BaselineLocations);
let recentActivity = CloudAppEvents
| where Timestamp > ago(7d)
| where AccountUpn == targetUser
| summarize 
    ActivityCount = count(),
    UniqueApps = dcount(Application),
    UniqueLocations = dcount(IPAddress),
    UniqueCountries = dcount(CountryCode),
    Activities = make_set(ActionType)
    by bin(Timestamp, 1d);
recentActivity
| extend userBaseline
| extend 
    ActivityAnomaly = (ActivityCount - AvgDailyActivity) / AvgDailyActivity * 100,
    AppsAnomaly = (UniqueApps - AvgDailyApps) / AvgDailyApps * 100,
    LocationAnomaly = (UniqueLocations - AvgDailyLocations) / AvgDailyLocations * 100
| extend IsAnomalous = ActivityAnomaly > 200 or AppsAnomaly > 150 or LocationAnomaly > 150
| where IsAnomalous
"@
    
    return @{
        PlaybookName = "UserBehaviorAnalytics"
        Query = $query
        Description = "Identifies anomalous user behavior based on historical patterns"
    }
}

function Invoke-MCASMASAppAnalysis {
    <#
    .SYNOPSIS
        Analyzes OAuth app permissions and usage
    #>
    [CmdletBinding()]
    param()
    
    $query = @"
// OAuth App Analysis
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType has "Consent"
| summarize 
    ConsentCount = count(),
    UniqueUsers = dcount(AccountObjectId),
    Users = make_set(AccountUpn),
    Permissions = make_set(RawEventData.Scope)
    by ApplicationId, ApplicationDisplayName
| extend RiskLevel = case(
    ConsentCount > 20 and UniqueUsers < 5, "High",  // Many consents by few users
    Permissions has_any ("Mail.Read", "Files.ReadWrite.All", "Directory.ReadWrite.All"), "High",
    ConsentCount > 10, "Medium",
    "Low")
| order by RiskLevel, ConsentCount desc
"@
    
    return @{
        PlaybookName = "OAuthAppAnalysis"
        Query = $query
        Description = "Analyzes OAuth applications for risky permissions and consent patterns"
    }
}

function Get-MCASPlaybooks {
    <#
    .SYNOPSIS
        Returns all available MCAS playbooks
    #>
    [CmdletBinding()]
    param()
    
    return @(
        @{ Name = "CloudAppRiskAssessment"; Function = "Invoke-MCASCloudAppRiskAssessment" }
        @{ Name = "DataExfiltrationDetection"; Function = "Invoke-MCASDataExfiltrationDetection" }
        @{ Name = "UserBehaviorAnalytics"; Function = "Invoke-MCASUserBehaviorAnalytics" }
        @{ Name = "OAuthAppAnalysis"; Function = "Invoke-MCASMASAppAnalysis" }
    )
}

# Export module members
Export-ModuleMember -Function @(
    'Invoke-MCASCloudAppRiskAssessment',
    'Invoke-MCASDataExfiltrationDetection',
    'Invoke-MCASUserBehaviorAnalytics',
    'Invoke-MCASMASAppAnalysis',
    'Get-MCASPlaybooks'
)
