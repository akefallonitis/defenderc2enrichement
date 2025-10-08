<#
.SYNOPSIS
    Microsoft Defender for Office 365 Worker module
.DESCRIPTION
    Provides MDO-specific enrichment, email security analysis, and phishing detection
#>

# Import common modules
$CommonPath = Join-Path $PSScriptRoot "..\Common"
Import-Module (Join-Path $CommonPath "AuthenticationHelper.psm1") -Force
Import-Module (Join-Path $CommonPath "EntityNormalizer.psm1") -Force

function Get-MDOEmailMessage {
    <#
    .SYNOPSIS
        Gets email message details
    .PARAMETER MessageId
        Network message ID or Internet message ID
    .PARAMETER AccessToken
        Graph API access token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MessageId,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )
    
    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        # Search for message using Graph API
        $uri = "https://graph.microsoft.com/v1.0/security/messages/$MessageId"
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction SilentlyContinue
        
        return $response
    }
    catch {
        Write-Verbose "Message not found or access denied: $_"
        return $null
    }
}

function Get-MDOThreatIntelligence {
    <#
    .SYNOPSIS
        Gets threat intelligence for URLs or files
    .PARAMETER Indicator
        URL or file hash
    .PARAMETER IndicatorType
        Type of indicator (URL, FileHash)
    .PARAMETER AccessToken
        Graph API access token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Indicator,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('URL', 'FileHash')]
        [string]$IndicatorType,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )
    
    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        $uri = "https://graph.microsoft.com/v1.0/security/threatIntelligence/articles"
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        
        return $response.value
    }
    catch {
        Write-Error "Failed to get threat intelligence: $_"
        return @()
    }
}

function Get-MDOPhishingCampaigns {
    <#
    .SYNOPSIS
        Gets phishing campaigns
    .PARAMETER AccessToken
        Graph API access token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )
    
    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        # Get security incidents related to phishing
        $uri = "https://graph.microsoft.com/v1.0/security/incidents?`$filter=classification eq 'truePositive' and determination eq 'phishing'"
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        
        return $response.value
    }
    catch {
        Write-Error "Failed to get phishing campaigns: $_"
        return @()
    }
}

function Get-MDOSafeAttachmentsResults {
    <#
    .SYNOPSIS
        Gets Safe Attachments scan results
    .PARAMETER MessageId
        Message identifier
    .PARAMETER AccessToken
        Graph API access token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MessageId,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )
    
    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        # Query for message with attachment scan results
        $uri = "https://graph.microsoft.com/v1.0/security/messages?`$filter=networkMessageId eq '$MessageId'"
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        
        if ($response.value -and $response.value.Count -gt 0) {
            $message = $response.value[0]
            return @{
                HasAttachments = $message.attachments.Count -gt 0
                AttachmentCount = $message.attachments.Count
                ThreatTypes = $message.threatTypes
                DeliveryAction = $message.deliveryAction
            }
        }
        
        return $null
    }
    catch {
        Write-Error "Failed to get Safe Attachments results: $_"
        return $null
    }
}

function Get-MDOUserSubmissions {
    <#
    .SYNOPSIS
        Gets user-reported messages
    .PARAMETER UserEmail
        User email address
    .PARAMETER AccessToken
        Graph API access token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserEmail,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )
    
    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        # Get threat submissions
        $uri = "https://graph.microsoft.com/v1.0/security/threatSubmission/emailThreats?`$filter=sender/emailAddress eq '$UserEmail'"
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        
        return $response.value
    }
    catch {
        Write-Error "Failed to get user submissions: $_"
        return @()
    }
}

function Start-MDOEnrichment {
    <#
    .SYNOPSIS
        Performs comprehensive MDO enrichment
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
        # Get active phishing campaigns
        $phishingCampaigns = Get-MDOPhishingCampaigns -AccessToken $AccessToken
        if ($phishingCampaigns.Count -gt 0) {
            $enrichmentResults.ThreatIntel += @{
                Type = "PhishingCampaigns"
                Count = $phishingCampaigns.Count
                Campaigns = $phishingCampaigns
            }
            $enrichmentResults.RiskScore += ($phishingCampaigns.Count * 10)
        }
        
        foreach ($entity in $Entities) {
            Write-Verbose "Processing MDO entity: $($entity.Type)"
            
            switch ($entity.Type) {
                'MailMessage' {
                    $messageId = $entity.NetworkMessageId ?? $entity.InternetMessageId
                    
                    if ($messageId) {
                        $messageDetails = Get-MDOEmailMessage -MessageId $messageId -AccessToken $AccessToken
                        
                        if ($messageDetails) {
                            $normalizedMessage = ConvertTo-NormalizedEntity -EntityData $messageDetails -EntityType 'MailMessage' -Source 'MDO'
                            $enrichmentResults.Entities += $normalizedMessage
                            
                            # Check Safe Attachments results
                            $safeAttachments = Get-MDOSafeAttachmentsResults -MessageId $messageId -AccessToken $AccessToken
                            if ($safeAttachments -and $safeAttachments.ThreatTypes) {
                                $enrichmentResults.ThreatIntel += @{
                                    Type = "EmailThreat"
                                    MessageId = $messageId
                                    ThreatTypes = $safeAttachments.ThreatTypes
                                    DeliveryAction = $safeAttachments.DeliveryAction
                                }
                                
                                $threatCount = $safeAttachments.ThreatTypes.Count
                                $enrichmentResults.RiskScore += ($threatCount * 20)
                                
                                if ($safeAttachments.DeliveryAction -eq 'Delivered') {
                                    $enrichmentResults.RiskScore += 15
                                    $enrichmentResults.Recommendations += "Malicious email was delivered - consider mailbox remediation"
                                }
                            }
                        }
                    }
                }
                
                'User' {
                    $userEmail = $entity.UserPrincipalName ?? $entity.Name
                    
                    if ($userEmail) {
                        # Get user submissions
                        $submissions = Get-MDOUserSubmissions -UserEmail $userEmail -AccessToken $AccessToken
                        
                        if ($submissions.Count -gt 0) {
                            $enrichmentResults.UEBAInsights += @{
                                Type = "UserReportedThreats"
                                User = $userEmail
                                SubmissionCount = $submissions.Count
                                Submissions = $submissions
                            }
                            
                            # High submission count might indicate targeted attack
                            if ($submissions.Count -gt 5) {
                                $enrichmentResults.RiskScore += 25
                                $enrichmentResults.Recommendations += "User $userEmail reported $($submissions.Count) suspicious emails - possible targeted attack"
                            }
                        }
                    }
                }
                
                'URL' {
                    $urlThreatIntel = Get-MDOThreatIntelligence -Indicator $entity.Url -IndicatorType 'URL' -AccessToken $AccessToken
                    
                    if ($urlThreatIntel -and $urlThreatIntel.Count -gt 0) {
                        $enrichmentResults.ThreatIntel += @{
                            Type = "URLThreat"
                            URL = $entity.Url
                            ThreatIntelligence = $urlThreatIntel
                        }
                        $enrichmentResults.RiskScore += 30
                        $enrichmentResults.Recommendations += "URL $($entity.Url) found in threat intelligence - block and investigate"
                    }
                }
                
                'File' {
                    if ($entity.FileHashes -and $entity.FileHashes.SHA256) {
                        $fileThreatIntel = Get-MDOThreatIntelligence -Indicator $entity.FileHashes.SHA256 -IndicatorType 'FileHash' -AccessToken $AccessToken
                        
                        if ($fileThreatIntel -and $fileThreatIntel.Count -gt 0) {
                            $enrichmentResults.ThreatIntel += @{
                                Type = "FileThreat"
                                Hash = $entity.FileHashes.SHA256
                                ThreatIntelligence = $fileThreatIntel
                            }
                            $enrichmentResults.RiskScore += 30
                        }
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
        if ($phishingCampaigns.Count -gt 3) {
            $enrichmentResults.Recommendations += "Multiple active phishing campaigns detected - increase user awareness"
        }
        
        return $enrichmentResults
    }
    catch {
        Write-Error "MDO enrichment failed: $_"
        throw
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Get-MDOEmailMessage',
    'Get-MDOThreatIntelligence',
    'Get-MDOPhishingCampaigns',
    'Get-MDOSafeAttachmentsResults',
    'Get-MDOUserSubmissions',
    'Start-MDOEnrichment'
)
