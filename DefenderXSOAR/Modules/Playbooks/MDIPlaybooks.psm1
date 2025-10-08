<#
.SYNOPSIS
    MDI Hunting Playbooks with real KQL queries
.DESCRIPTION
    Provides MDI-specific hunting playbooks for identity security
#>

function Invoke-MDIIdentityCompromiseDetection {
    <#
    .SYNOPSIS
        Detects identity compromise indicators
    .PARAMETER UserPrincipalName
        User to investigate
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )
    
    $query = @"
// Identity Compromise Detection
let targetUser = '$UserPrincipalName';
IdentityLogonEvents
| where Timestamp > ago(7d)
| where AccountUpn == targetUser
| summarize 
    LogonCount = count(),
    SuccessfulLogons = countif(LogonResult == "Success"),
    FailedLogons = countif(LogonResult == "Failed"),
    UniqueDevices = dcount(DeviceName),
    UniqueIPs = dcount(IPAddress),
    UniqueLocations = dcount(Location),
    Devices = make_set(DeviceName),
    IPs = make_set(IPAddress)
    by bin(Timestamp, 1h)
| extend RiskScore = (FailedLogons * 5) + (UniqueIPs * 10) + (UniqueLocations * 15)
| where RiskScore > 30 or FailedLogons > 10
| order by RiskScore desc
"@
    
    return @{
        PlaybookName = "IdentityCompromiseDetection"
        Query = $query
        Description = "Detects indicators of identity compromise through logon analysis"
    }
}

function Invoke-MDILateralMovementAnalysis {
    <#
    .SYNOPSIS
        Analyzes lateral movement patterns
    .PARAMETER AccountName
        Account to investigate
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName
    )
    
    $query = @"
// Lateral Movement Analysis
let targetAccount = '$AccountName';
let logonActivity = IdentityLogonEvents
| where Timestamp > ago(24h)
| where AccountName =~ targetAccount
| where LogonType in ("Network", "RemoteInteractive")
| project Timestamp, AccountName, DeviceName, IPAddress, LogonType;
let directoryActivity = IdentityDirectoryEvents
| where Timestamp > ago(24h)
| where AccountName =~ targetAccount
| where ActionType in ("LDAP query", "SMB connection", "Directory Service Access")
| project Timestamp, AccountName, DestinationDeviceName, ActionType;
logonActivity
| summarize 
    DeviceCount = dcount(DeviceName),
    Devices = make_set(DeviceName),
    FirstLogon = min(Timestamp),
    LastLogon = max(Timestamp),
    TimeSpan = datetime_diff('minute', max(Timestamp), min(Timestamp))
    by AccountName
| join kind=inner (
    directoryActivity
    | summarize DirectoryActions = count() by AccountName
) on AccountName
| where DeviceCount > 3 or (DeviceCount > 1 and TimeSpan < 60)
| extend LateralMovementIndicator = case(
    DeviceCount > 5, "High",
    DeviceCount > 3, "Medium",
    "Low")
"@
    
    return @{
        PlaybookName = "LateralMovementAnalysis"
        Query = $query
        Description = "Identifies lateral movement patterns across devices and systems"
    }
}

function Invoke-MDIPrivilegeEscalationDetection {
    <#
    .SYNOPSIS
        Detects privilege escalation attempts
    #>
    [CmdletBinding()]
    param()
    
    $query = @"
// Privilege Escalation Detection
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType has_any ("Add member to role", "Role assignment added", "User account control changed")
| where TargetAccountUpn != ""
| summarize 
    EscalationAttempts = count(),
    Actions = make_set(ActionType),
    Targets = make_set(TargetAccountUpn),
    Actors = make_set(AccountUpn)
    by bin(Timestamp, 1h), ActionType
| where EscalationAttempts > 3
| extend RiskLevel = case(
    ActionType has "role", "Critical",
    EscalationAttempts > 10, "High",
    "Medium")
| order by Timestamp desc
"@
    
    return @{
        PlaybookName = "PrivilegeEscalationDetection"
        Query = $query
        Description = "Detects suspicious privilege escalation activities"
    }
}

function Invoke-MDIKerberosAttackDetection {
    <#
    .SYNOPSIS
        Detects Kerberos-based attacks
    #>
    [CmdletBinding()]
    param()
    
    $query = @"
// Kerberos Attack Detection
IdentityLogonEvents
| where Timestamp > ago(7d)
| where Protocol == "Kerberos"
| where LogonResult == "Success"
| summarize 
    LogonCount = count(),
    UniqueAccounts = dcount(AccountName),
    Accounts = make_set(AccountName),
    TicketTypes = make_set(TicketType),
    EncryptionTypes = make_set(EncryptionType)
    by IPAddress, DeviceName
| where EncryptionTypes has_any ("RC4", "DES")  // Weak encryption
| extend SuspiciousActivity = case(
    EncryptionTypes has "RC4" and LogonCount > 10, "GoldenTicket",
    UniqueAccounts > 20, "Enumeration",
    "Suspicious")
| where SuspiciousActivity != ""
"@
    
    return @{
        PlaybookName = "KerberosAttackDetection"
        Query = $query
        Description = "Detects Kerberos-based attacks including Golden/Silver Ticket"
    }
}

function Get-MDIPlaybooks {
    <#
    .SYNOPSIS
        Returns all available MDI playbooks
    #>
    [CmdletBinding()]
    param()
    
    return @(
        @{ Name = "IdentityCompromiseDetection"; Function = "Invoke-MDIIdentityCompromiseDetection" }
        @{ Name = "LateralMovementAnalysis"; Function = "Invoke-MDILateralMovementAnalysis" }
        @{ Name = "PrivilegeEscalationDetection"; Function = "Invoke-MDIPrivilegeEscalationDetection" }
        @{ Name = "KerberosAttackDetection"; Function = "Invoke-MDIKerberosAttackDetection" }
    )
}

# Export module members
Export-ModuleMember -Function @(
    'Invoke-MDIIdentityCompromiseDetection',
    'Invoke-MDILateralMovementAnalysis',
    'Invoke-MDIPrivilegeEscalationDetection',
    'Invoke-MDIKerberosAttackDetection',
    'Get-MDIPlaybooks'
)
