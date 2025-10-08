<#
.SYNOPSIS
    MDO Hunting Playbooks with real KQL queries
.DESCRIPTION
    Provides MDO-specific hunting playbooks for email security
#>

function Invoke-MDOPhishingCampaignDetection {
    <#
    .SYNOPSIS
        Detects phishing campaigns
    .PARAMETER Days
        Number of days to analyze
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$Days = 7
    )
    
    $query = @"
// Phishing Campaign Detection
EmailEvents
| where Timestamp > ago($($Days)d)
| where ThreatTypes has_any ("Phish", "Malware")
| summarize 
    EmailCount = count(),
    UniqueRecipients = dcount(RecipientEmailAddress),
    Recipients = make_set(RecipientEmailAddress),
    Senders = make_set(SenderFromAddress),
    Subjects = make_set(Subject)
    by SenderFromDomain, bin(Timestamp, 1h)
| where EmailCount > 5 or UniqueRecipients > 3
| extend CampaignScore = (EmailCount * 2) + (UniqueRecipients * 5)
| order by CampaignScore desc
"@
    
    return @{
        PlaybookName = "PhishingCampaignDetection"
        Query = $query
        Description = "Identifies coordinated phishing campaigns targeting the organization"
    }
}

function Invoke-MDOSafeAttachmentsAnalysis {
    <#
    .SYNOPSIS
        Analyzes Safe Attachments detections
    #>
    [CmdletBinding()]
    param()
    
    $query = @"
// Safe Attachments Analysis
EmailAttachmentInfo
| where Timestamp > ago(7d)
| join kind=inner (
    EmailEvents
    | where ThreatTypes has "Malware"
) on NetworkMessageId
| summarize 
    MaliciousAttachments = count(),
    UniqueFiles = dcount(SHA256),
    FileNames = make_set(FileName),
    FileTypes = make_set(FileType),
    Recipients = make_set(RecipientEmailAddress)
    by SHA256
| extend RiskLevel = case(
    MaliciousAttachments > 10, "Critical",
    MaliciousAttachments > 5, "High",
    "Medium")
| order by MaliciousAttachments desc
"@
    
    return @{
        PlaybookName = "SafeAttachmentsAnalysis"
        Query = $query
        Description = "Analyzes malicious attachments detected by Safe Attachments"
    }
}

function Invoke-MDOEmailSecurityAnalysis {
    <#
    .SYNOPSIS
        Comprehensive email security analysis
    .PARAMETER RecipientEmail
        Specific recipient to analyze
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$RecipientEmail
    )
    
    $recipientFilter = if ($RecipientEmail) { "| where RecipientEmailAddress == '$RecipientEmail'" } else { "" }
    
    $query = @"
// Email Security Analysis
EmailEvents
| where Timestamp > ago(7d)
$recipientFilter
| summarize 
    TotalEmails = count(),
    MaliciousEmails = countif(ThreatTypes != ""),
    PhishingEmails = countif(ThreatTypes has "Phish"),
    MalwareEmails = countif(ThreatTypes has "Malware"),
    SpamEmails = countif(ThreatTypes has "Spam"),
    BlockedEmails = countif(DeliveryAction == "Blocked"),
    DeliveredThreatEmails = countif(ThreatTypes != "" and DeliveryAction == "Delivered"),
    UniqueSenders = dcount(SenderFromAddress)
    by RecipientEmailAddress
| extend RiskScore = (DeliveredThreatEmails * 30) + (MaliciousEmails * 10)
| where RiskScore > 0
| order by RiskScore desc
"@
    
    return @{
        PlaybookName = "EmailSecurityAnalysis"
        Query = $query
        Description = "Comprehensive analysis of email security posture per recipient"
    }
}

function Invoke-MDOCollaborationSecurity {
    <#
    .SYNOPSIS
        Analyzes Teams and SharePoint security
    #>
    [CmdletBinding()]
    param()
    
    $query = @"
// Collaboration Security
CloudAppEvents
| where Timestamp > ago(7d)
| where Application in ("Microsoft Teams", "Microsoft SharePoint Online")
| where ActionType has_any ("FileDownloaded", "FileUploaded", "FileSyncDownloaded", "ShareCreated")
| summarize 
    ActivityCount = count(),
    FileOperations = countif(ActionType has "File"),
    ShareOperations = countif(ActionType has "Share"),
    UniqueUsers = dcount(AccountObjectId),
    UniqueLocations = dcount(IPAddress)
    by Application, AccountUpn
| where FileOperations > 100 or ShareOperations > 20
| extend RiskScore = (FileOperations / 10) + (ShareOperations * 5)
| order by RiskScore desc
"@
    
    return @{
        PlaybookName = "CollaborationSecurity"
        Query = $query
        Description = "Analyzes security risks in Teams and SharePoint collaboration"
    }
}

function Get-MDOPlaybooks {
    <#
    .SYNOPSIS
        Returns all available MDO playbooks
    #>
    [CmdletBinding()]
    param()
    
    return @(
        @{ Name = "PhishingCampaignDetection"; Function = "Invoke-MDOPhishingCampaignDetection" }
        @{ Name = "SafeAttachmentsAnalysis"; Function = "Invoke-MDOSafeAttachmentsAnalysis" }
        @{ Name = "EmailSecurityAnalysis"; Function = "Invoke-MDOEmailSecurityAnalysis" }
        @{ Name = "CollaborationSecurity"; Function = "Invoke-MDOCollaborationSecurity" }
    )
}

# Export module members
Export-ModuleMember -Function @(
    'Invoke-MDOPhishingCampaignDetection',
    'Invoke-MDOSafeAttachmentsAnalysis',
    'Invoke-MDOEmailSecurityAnalysis',
    'Invoke-MDOCollaborationSecurity',
    'Get-MDOPlaybooks'
)
