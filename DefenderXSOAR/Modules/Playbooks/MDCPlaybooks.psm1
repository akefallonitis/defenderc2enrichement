<#
.SYNOPSIS
    MDC Hunting Playbooks with real KQL queries
.DESCRIPTION
    Provides MDC-specific hunting playbooks for cloud security posture
#>

function Invoke-MDCSecurityPostureAnalysis {
    <#
    .SYNOPSIS
        Analyzes cloud resource security posture
    .PARAMETER SubscriptionId
        Subscription ID to analyze
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId
    )
    
    $query = @"
// Cloud Security Posture Analysis
SecurityAlert
| where TimeGenerated > ago(30d)
| where ProviderName == "Azure Security Center"
| where SubscriptionId == '$SubscriptionId'
| summarize 
    AlertCount = count(),
    HighSeverity = countif(Severity == "High"),
    MediumSeverity = countif(Severity == "Medium"),
    LowSeverity = countif(Severity == "Low"),
    UniqueAlerts = dcount(AlertName),
    Resources = make_set(ResourceId)
    by AlertName
| extend RiskScore = (HighSeverity * 20) + (MediumSeverity * 10) + (LowSeverity * 5)
| order by RiskScore desc
"@
    
    return @{
        PlaybookName = "SecurityPostureAnalysis"
        Query = $query
        Description = "Analyzes overall security posture of cloud resources"
    }
}

function Invoke-MDCVulnerabilityAssessment {
    <#
    .SYNOPSIS
        Assesses vulnerabilities across resources
    .PARAMETER ResourceGroup
        Resource group to assess
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ResourceGroup
    )
    
    $filter = if ($ResourceGroup) { "| where ResourceGroup == '$ResourceGroup'" } else { "" }
    
    $query = @"
// Vulnerability Assessment
SecurityAssessment
| where TimeGenerated > ago(7d)
$filter
| where AssessmentStatus == "Unhealthy"
| summarize 
    VulnerabilityCount = count(),
    HighSeverity = countif(Severity == "High"),
    CriticalSeverity = countif(Severity == "Critical"),
    Resources = make_set(ResourceName)
    by Category, AssessmentName
| extend Priority = case(
    CriticalSeverity > 0, 1,
    HighSeverity > 0, 2,
    3)
| order by Priority asc, VulnerabilityCount desc
"@
    
    return @{
        PlaybookName = "VulnerabilityAssessment"
        Query = $query
        Description = "Identifies and prioritizes vulnerabilities across cloud resources"
    }
}

function Invoke-MDCComplianceDeviation {
    <#
    .SYNOPSIS
        Detects compliance deviations
    .PARAMETER Standard
        Compliance standard to check
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Standard
    )
    
    $filter = if ($Standard) { "| where StandardName == '$Standard'" } else { "" }
    
    $query = @"
// Compliance Deviation Detection
SecurityRegulatoryCompliance
| where TimeGenerated > ago(7d)
$filter
| where ComplianceState == "Failed"
| summarize 
    FailedControls = count(),
    Resources = dcount(ResourceId),
    Controls = make_set(ControlName)
    by StandardName, AssessmentName
| extend ComplianceGap = (FailedControls * 100.0) / FailedControls
| order by FailedControls desc
"@
    
    return @{
        PlaybookName = "ComplianceDeviation"
        Query = $query
        Description = "Identifies compliance standard deviations and failed controls"
    }
}

function Invoke-MDCResourceConfigAnalysis {
    <#
    .SYNOPSIS
        Analyzes resource configuration changes
    .PARAMETER Days
        Number of days to analyze
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$Days = 7
    )
    
    $query = @"
// Resource Configuration Analysis
AzureActivity
| where TimeGenerated > ago($($Days)d)
| where OperationNameValue has_any ("Microsoft.Resources/deployments/write", 
                                     "Microsoft.Compute/virtualMachines/write",
                                     "Microsoft.Network/networkSecurityGroups/write")
| summarize 
    ChangeCount = count(),
    FirstChange = min(TimeGenerated),
    LastChange = max(TimeGenerated),
    Callers = make_set(Caller),
    Operations = make_set(OperationNameValue)
    by ResourceGroup, ResourceProvider
| extend RiskLevel = case(
    ChangeCount > 20, "High",
    ChangeCount > 10, "Medium",
    "Low")
| order by ChangeCount desc
"@
    
    return @{
        PlaybookName = "ResourceConfigAnalysis"
        Query = $query
        Description = "Analyzes resource configuration changes for security implications"
    }
}

function Get-MDCPlaybooks {
    <#
    .SYNOPSIS
        Returns all available MDC playbooks
    #>
    [CmdletBinding()]
    param()
    
    return @(
        @{ Name = "SecurityPostureAnalysis"; Function = "Invoke-MDCSecurityPostureAnalysis" }
        @{ Name = "VulnerabilityAssessment"; Function = "Invoke-MDCVulnerabilityAssessment" }
        @{ Name = "ComplianceDeviation"; Function = "Invoke-MDCComplianceDeviation" }
        @{ Name = "ResourceConfigAnalysis"; Function = "Invoke-MDCResourceConfigAnalysis" }
    )
}

# Export module members
Export-ModuleMember -Function @(
    'Invoke-MDCSecurityPostureAnalysis',
    'Invoke-MDCVulnerabilityAssessment',
    'Invoke-MDCComplianceDeviation',
    'Invoke-MDCResourceConfigAnalysis',
    'Get-MDCPlaybooks'
)
