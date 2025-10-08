<#
.SYNOPSIS
    MDE Hunting Playbooks with real KQL queries
.DESCRIPTION
    Provides MDE-specific hunting playbooks with production-ready KQL queries
#>

function Invoke-MDEDeviceCompromiseDetection {
    <#
    .SYNOPSIS
        Detects device compromise indicators
    .PARAMETER DeviceName
        Device name to investigate
    .PARAMETER Days
        Number of days to look back
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeviceName,
        
        [Parameter(Mandatory = $false)]
        [int]$Days = 7
    )
    
    $query = @"
// Device Compromise Detection
let lookback = $($Days)d;
let suspiciousProcesses = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where DeviceName == '$DeviceName'
| where ProcessCommandLine has_any ("powershell -enc", "cmd /c", "wscript", "cscript", "certutil", "bitsadmin")
| project Timestamp, DeviceName, ProcessCommandLine, AccountName, InitiatingProcessCommandLine;
let suspiciousNetworkConnections = DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where DeviceName == '$DeviceName'
| where RemotePort in (4444, 5555, 8080, 8888, 1337)
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName;
let suspiciousFileCreations = DeviceFileEvents
| where Timestamp > ago(lookback)
| where DeviceName == '$DeviceName'
| where FolderPath has_any ("\\Windows\\Temp", "\\AppData\\Local\\Temp", "\\Users\\Public")
| where FileName endswith_any (".exe", ".dll", ".ps1", ".bat", ".vbs")
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessFileName;
union suspiciousProcesses, suspiciousNetworkConnections, suspiciousFileCreations
| summarize Count = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName
| extend RiskScore = Count * 10
"@
    
    return @{
        PlaybookName = "DeviceCompromiseDetection"
        Query = $query
        Description = "Detects indicators of device compromise including suspicious processes, network connections, and file creations"
    }
}

function Invoke-MDEMalwareAnalysis {
    <#
    .SYNOPSIS
        Analyzes malware activity on a device
    .PARAMETER FileHash
        File hash to investigate
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileHash
    )
    
    $query = @"
// Malware Analysis
let targetHash = '$FileHash';
let fileInfo = DeviceFileEvents
| where SHA256 == targetHash or SHA1 == targetHash
| summarize 
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    DeviceCount = dcount(DeviceName),
    Devices = make_set(DeviceName),
    Paths = make_set(FolderPath)
    by SHA256, FileName;
let processExecution = DeviceProcessEvents
| where SHA256 == targetHash or SHA1 == targetHash
| summarize 
    ExecutionCount = count(),
    UniqueDevices = dcount(DeviceName),
    CommandLines = make_set(ProcessCommandLine)
    by SHA256, FileName;
let networkActivity = DeviceNetworkEvents
| where InitiatingProcessSHA256 == targetHash or InitiatingProcessSHA1 == targetHash
| summarize 
    ConnectionCount = count(),
    RemoteIPs = make_set(RemoteIP),
    RemoteURLs = make_set(RemoteUrl)
    by InitiatingProcessSHA256, InitiatingProcessFileName;
fileInfo
| join kind=leftouter (processExecution) on SHA256
| join kind=leftouter (networkActivity) on `$left.SHA256 == `$right.InitiatingProcessSHA256
| project-away SHA256*, FileName*
"@
    
    return @{
        PlaybookName = "MalwareAnalysis"
        Query = $query
        Description = "Comprehensive malware analysis including file activity, process execution, and network connections"
    }
}

function Invoke-MDEProcessTreeAnalysis {
    <#
    .SYNOPSIS
        Analyzes process tree for suspicious behavior
    .PARAMETER DeviceName
        Device name
    .PARAMETER ProcessId
        Process ID to investigate
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeviceName,
        
        [Parameter(Mandatory = $true)]
        [int]$ProcessId
    )
    
    $query = @"
// Process Tree Analysis
let targetDevice = '$DeviceName';
let targetPid = $ProcessId;
let rootProcess = DeviceProcessEvents
| where DeviceName == targetDevice
| where ProcessId == targetPid
| project Timestamp, DeviceName, ProcessId, FileName, ProcessCommandLine, 
          AccountName, InitiatingProcessId, InitiatingProcessFileName;
let childProcesses = DeviceProcessEvents
| where DeviceName == targetDevice
| where InitiatingProcessId == targetPid
| project Timestamp, DeviceName, ProcessId, FileName, ProcessCommandLine, 
          AccountName, InitiatingProcessId, InitiatingProcessFileName, Level = 1;
let grandChildProcesses = DeviceProcessEvents
| where DeviceName == targetDevice
| join kind=inner (childProcesses) on `$left.InitiatingProcessId == `$right.ProcessId
| project Timestamp, DeviceName, ProcessId = ProcessId, FileName = FileName, 
          ProcessCommandLine = ProcessCommandLine, AccountName = AccountName, 
          InitiatingProcessId = InitiatingProcessId, 
          InitiatingProcessFileName = InitiatingProcessFileName, Level = 2;
union rootProcess, childProcesses, grandChildProcesses
| order by Timestamp asc
| extend IsSuspicious = case(
    ProcessCommandLine has_any ("powershell -enc", "certutil", "bitsadmin"), "High",
    ProcessCommandLine has_any ("cmd /c", "wscript"), "Medium",
    "Low")
"@
    
    return @{
        PlaybookName = "ProcessTreeAnalysis"
        Query = $query
        Description = "Analyzes process tree hierarchy to detect suspicious parent-child relationships"
    }
}

function Invoke-MDENetworkConnectionAnalysis {
    <#
    .SYNOPSIS
        Analyzes network connections from a device
    .PARAMETER DeviceName
        Device name
    .PARAMETER Days
        Number of days to look back
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeviceName,
        
        [Parameter(Mandatory = $false)]
        [int]$Days = 7
    )
    
    $query = @"
// Network Connection Analysis
let lookback = $($Days)d;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where DeviceName == '$DeviceName'
| summarize 
    ConnectionCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    UniqueProcesses = dcount(InitiatingProcessFileName),
    Processes = make_set(InitiatingProcessFileName),
    RemoteURLs = make_set(RemoteUrl)
    by RemoteIP, RemotePort
| extend 
    IsCommonPort = RemotePort in (80, 443, 53, 22, 3389),
    IsSuspiciousPort = RemotePort in (4444, 5555, 8080, 8888, 1337, 31337)
| extend RiskLevel = case(
    IsSuspiciousPort, "High",
    not(IsCommonPort) and ConnectionCount < 5, "Medium",
    "Low")
| order by RiskLevel desc, ConnectionCount desc
"@
    
    return @{
        PlaybookName = "NetworkConnectionAnalysis"
        Query = $query
        Description = "Analyzes network connections to detect suspicious communication patterns"
    }
}

function Invoke-MDEFileReputationCheck {
    <#
    .SYNOPSIS
        Checks file reputation across the organization
    .PARAMETER FileHash
        File hash to check
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileHash
    )
    
    $query = @"
// File Reputation Check
let targetHash = '$FileHash';
let fileActivity = DeviceFileEvents
| where SHA256 == targetHash or SHA1 == targetHash
| summarize 
    TotalOccurrences = count(),
    UniqueDevices = dcount(DeviceName),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Devices = make_set(DeviceName),
    Paths = make_set(FolderPath),
    Actions = make_set(ActionType)
    by SHA256, FileName;
let processActivity = DeviceProcessEvents
| where SHA256 == targetHash or SHA1 == targetHash
| summarize 
    ExecutionCount = count(),
    UniqueAccounts = dcount(AccountName),
    Accounts = make_set(AccountName),
    CommandLines = make_set(ProcessCommandLine)
    by SHA256, FileName;
fileActivity
| join kind=leftouter (processActivity) on SHA256, FileName
| extend ReputationScore = case(
    UniqueDevices == 1, 25,  // Only on one device - suspicious
    UniqueDevices <= 5, 50,  // On few devices - potentially malicious
    UniqueDevices <= 20, 75, // Moderate deployment
    100)                      // Widespread - likely legitimate
| extend Verdict = case(
    ReputationScore <= 25, "Highly Suspicious",
    ReputationScore <= 50, "Suspicious",
    ReputationScore <= 75, "Potentially Legitimate",
    "Likely Legitimate")
"@
    
    return @{
        PlaybookName = "FileReputationCheck"
        Query = $query
        Description = "Assesses file reputation based on prevalence and behavior across the organization"
    }
}

function Invoke-MDELateralMovementDetection {
    <#
    .SYNOPSIS
        Detects lateral movement activity
    .PARAMETER AccountName
        Account to investigate
    .PARAMETER Days
        Number of days to look back
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName,
        
        [Parameter(Mandatory = $false)]
        [int]$Days = 7
    )
    
    $query = @"
// Lateral Movement Detection
let lookback = $($Days)d;
let targetAccount = '$AccountName';
let logonEvents = DeviceLogonEvents
| where Timestamp > ago(lookback)
| where AccountName =~ targetAccount
| where LogonType in ("RemoteInteractive", "Network", "Batch")
| summarize 
    LogonCount = count(),
    UniqueDevices = dcount(DeviceName),
    Devices = make_set(DeviceName),
    LogonTypes = make_set(LogonType)
    by AccountName, bin(Timestamp, 1h);
let remoteExecution = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where AccountName =~ targetAccount
| where InitiatingProcessFileName in~ ("psexec.exe", "wmiprvse.exe", "svchost.exe")
| summarize 
    RemoteExecutions = count(),
    Commands = make_set(ProcessCommandLine)
    by DeviceName, AccountName;
logonEvents
| where UniqueDevices > 3  // Logged into multiple devices
| join kind=leftouter (remoteExecution) on AccountName
| extend RiskScore = (UniqueDevices * 10) + (RemoteExecutions * 20)
| where RiskScore > 30
| order by RiskScore desc
"@
    
    return @{
        PlaybookName = "LateralMovementDetection"
        Query = $query
        Description = "Detects lateral movement indicators including remote logons and remote code execution"
    }
}

function Get-MDEPlaybooks {
    <#
    .SYNOPSIS
        Returns all available MDE playbooks
    #>
    [CmdletBinding()]
    param()
    
    return @(
        @{ Name = "DeviceCompromiseDetection"; Function = "Invoke-MDEDeviceCompromiseDetection" }
        @{ Name = "MalwareAnalysis"; Function = "Invoke-MDEMalwareAnalysis" }
        @{ Name = "ProcessTreeAnalysis"; Function = "Invoke-MDEProcessTreeAnalysis" }
        @{ Name = "NetworkConnectionAnalysis"; Function = "Invoke-MDENetworkConnectionAnalysis" }
        @{ Name = "FileReputationCheck"; Function = "Invoke-MDEFileReputationCheck" }
        @{ Name = "LateralMovementDetection"; Function = "Invoke-MDELateralMovementDetection" }
    )
}

# Export module members
Export-ModuleMember -Function @(
    'Invoke-MDEDeviceCompromiseDetection',
    'Invoke-MDEMalwareAnalysis',
    'Invoke-MDEProcessTreeAnalysis',
    'Invoke-MDENetworkConnectionAnalysis',
    'Invoke-MDEFileReputationCheck',
    'Invoke-MDELateralMovementDetection',
    'Get-MDEPlaybooks'
)
