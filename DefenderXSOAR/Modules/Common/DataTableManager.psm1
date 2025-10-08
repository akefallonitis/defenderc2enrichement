<#
.SYNOPSIS
    Data Table Manager module for DefenderXSOAR
.DESCRIPTION
    Manages data output to Log Analytics custom tables and incident comments
#>

function Send-ToLogAnalytics {
    <#
    .SYNOPSIS
        Sends data to Log Analytics custom table
    .PARAMETER WorkspaceId
        Log Analytics Workspace ID
    .PARAMETER SharedKey
        Log Analytics Shared Key
    .PARAMETER LogType
        Custom log table name (without _CL suffix)
    .PARAMETER JsonBody
        JSON data to send
    .PARAMETER TimeStampField
        Optional timestamp field name
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkspaceId,
        
        [Parameter(Mandatory = $true)]
        [string]$SharedKey,
        
        [Parameter(Mandatory = $true)]
        [string]$LogType,
        
        [Parameter(Mandatory = $true)]
        [string]$JsonBody,
        
        [Parameter(Mandatory = $false)]
        [string]$TimeStampField = ""
    )
    
    try {
        $method = "POST"
        $contentType = "application/json"
        $resource = "/api/logs"
        $rfc1123date = [DateTime]::UtcNow.ToString("r")
        $contentLength = $JsonBody.Length
        
        $xHeaders = "x-ms-date:" + $rfc1123date
        $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
        
        $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
        $keyBytes = [Convert]::FromBase64String($SharedKey)
        
        $sha256 = New-Object System.Security.Cryptography.HMACSHA256
        $sha256.Key = $keyBytes
        $calculatedHash = $sha256.ComputeHash($bytesToHash)
        $encodedHash = [Convert]::ToBase64String($calculatedHash)
        $authorization = 'SharedKey {0}:{1}' -f $WorkspaceId, $encodedHash
        
        $uri = "https://" + $WorkspaceId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
        
        $headers = @{
            "Authorization"        = $authorization
            "Log-Type"             = $LogType
            "x-ms-date"            = $rfc1123date
            "time-generated-field" = $TimeStampField
        }
        
        $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $JsonBody -UseBasicParsing
        
        if ($response.StatusCode -eq 200) {
            Write-Verbose "Data successfully sent to Log Analytics table: $LogType"
            return $true
        }
        else {
            Write-Error "Failed to send data to Log Analytics. Status: $($response.StatusCode)"
            return $false
        }
    }
    catch {
        Write-Error "Error sending data to Log Analytics: $_"
        throw
    }
}

function Add-IncidentComment {
    <#
    .SYNOPSIS
        Adds a comment to a Sentinel incident
    .PARAMETER IncidentId
        Incident ARM resource ID
    .PARAMETER Comment
        Comment text to add
    .PARAMETER AccessToken
        Azure Management access token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$IncidentId,
        
        [Parameter(Mandatory = $true)]
        [string]$Comment,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )
    
    try {
        $commentId = [guid]::NewGuid().ToString()
        $uri = "https://management.azure.com$IncidentId/comments/$($commentId)?api-version=2023-02-01"
        
        $body = @{
            properties = @{
                message = $Comment
            }
        } | ConvertTo-Json -Depth 10
        
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }
        
        $response = Invoke-RestMethod -Uri $uri -Method Put -Headers $headers -Body $body
        
        Write-Verbose "Comment added to incident: $IncidentId"
        return $response
    }
    catch {
        Write-Error "Failed to add incident comment: $_"
        throw
    }
}

function Format-EnrichmentResult {
    <#
    .SYNOPSIS
        Formats enrichment results for output
    .PARAMETER EnrichmentData
        Hashtable containing enrichment data
    .PARAMETER IncidentId
        Incident identifier
    .PARAMETER Product
        Product that generated the enrichment
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$EnrichmentData,
        
        [Parameter(Mandatory = $true)]
        [string]$IncidentId,
        
        [Parameter(Mandatory = $true)]
        [string]$Product
    )
    
    $formattedData = @{
        IncidentId        = $IncidentId
        Product           = $Product
        EnrichmentTime    = Get-Date -Format "o"
        Entities          = $EnrichmentData.Entities ?? @()
        RelatedAlerts     = $EnrichmentData.RelatedAlerts ?? @()
        ThreatIntel       = $EnrichmentData.ThreatIntel ?? @()
        RiskScore         = $EnrichmentData.RiskScore ?? 0
        Severity          = $EnrichmentData.Severity ?? "Informational"
        Recommendations   = $EnrichmentData.Recommendations ?? @()
        WatchlistMatches  = $EnrichmentData.WatchlistMatches ?? @()
        UEBAInsights      = $EnrichmentData.UEBAInsights ?? @()
        KQLQueryResults   = $EnrichmentData.KQLQueryResults ?? @()
    }
    
    return $formattedData
}

function ConvertTo-IncidentComment {
    <#
    .SYNOPSIS
        Converts enrichment data to a formatted incident comment
    .PARAMETER EnrichmentData
        Formatted enrichment data
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$EnrichmentData
    )
    
    $comment = @"
## DefenderXSOAR Enrichment Results
**Product:** $($EnrichmentData.Product)
**Enrichment Time:** $($EnrichmentData.EnrichmentTime)
**Risk Score:** $($EnrichmentData.RiskScore)
**Severity:** $($EnrichmentData.Severity)

### Entities Analyzed
$($EnrichmentData.Entities.Count) entities processed

### Related Alerts
$($EnrichmentData.RelatedAlerts.Count) related alerts found

### Threat Intelligence
$($EnrichmentData.ThreatIntel.Count) threat indicators identified

### Watchlist Matches
$($EnrichmentData.WatchlistMatches.Count) watchlist matches found

### UEBA Insights
$($EnrichmentData.UEBAInsights.Count) behavioral insights identified

### Recommendations
$(if ($EnrichmentData.Recommendations.Count -gt 0) { 
    ($EnrichmentData.Recommendations | ForEach-Object { "- $_" }) -join "`n"
} else { 
    "No specific recommendations at this time." 
})

---
*Generated by DefenderXSOAR*
"@
    
    return $comment
}

function New-DefenderXSOARRecord {
    <#
    .SYNOPSIS
        Creates a DefenderXSOAR custom log record
    .PARAMETER IncidentId
        Incident identifier
    .PARAMETER Product
        Source product
    .PARAMETER EnrichmentData
        Enrichment data to include
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$IncidentId,
        
        [Parameter(Mandatory = $true)]
        [string]$Product,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$EnrichmentData
    )
    
    $record = @{
        TimeGenerated     = Get-Date -Format "o"
        IncidentId        = $IncidentId
        Product           = $Product
        RiskScore         = $EnrichmentData.RiskScore ?? 0
        Severity          = $EnrichmentData.Severity ?? "Informational"
        EntitiesCount     = ($EnrichmentData.Entities ?? @()).Count
        RelatedAlertsCount = ($EnrichmentData.RelatedAlerts ?? @()).Count
        ThreatIntelCount  = ($EnrichmentData.ThreatIntel ?? @()).Count
        WatchlistMatches  = ($EnrichmentData.WatchlistMatches ?? @()).Count
        UEBAInsights      = ($EnrichmentData.UEBAInsights ?? @()).Count
        Recommendations   = ($EnrichmentData.Recommendations ?? @()) -join "; "
        EnrichmentData    = ($EnrichmentData | ConvertTo-Json -Depth 10 -Compress)
    }
    
    return $record
}

function Send-DefenderXSOARData {
    <#
    .SYNOPSIS
        Sends DefenderXSOAR enrichment data to Log Analytics and adds incident comment
    .PARAMETER WorkspaceId
        Log Analytics Workspace ID
    .PARAMETER SharedKey
        Log Analytics Shared Key
    .PARAMETER IncidentId
        Incident identifier
    .PARAMETER IncidentArmId
        Incident ARM resource ID (for comments)
    .PARAMETER Product
        Source product
    .PARAMETER EnrichmentData
        Enrichment data
    .PARAMETER AccessToken
        Azure Management access token (for incident comments)
    .PARAMETER AddComment
        Whether to add incident comment
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkspaceId,
        
        [Parameter(Mandatory = $true)]
        [string]$SharedKey,
        
        [Parameter(Mandatory = $true)]
        [string]$IncidentId,
        
        [Parameter(Mandatory = $false)]
        [string]$IncidentArmId,
        
        [Parameter(Mandatory = $true)]
        [string]$Product,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$EnrichmentData,
        
        [Parameter(Mandatory = $false)]
        [string]$AccessToken,
        
        [Parameter(Mandatory = $false)]
        [bool]$AddComment = $true
    )
    
    try {
        # Format enrichment data
        $formattedData = Format-EnrichmentResult -EnrichmentData $EnrichmentData -IncidentId $IncidentId -Product $Product
        
        # Create custom log record
        $logRecord = New-DefenderXSOARRecord -IncidentId $IncidentId -Product $Product -EnrichmentData $formattedData
        
        # Send to Log Analytics
        $jsonBody = $logRecord | ConvertTo-Json -Depth 10
        $logResult = Send-ToLogAnalytics -WorkspaceId $WorkspaceId -SharedKey $SharedKey -LogType "DefenderXSOAR" -JsonBody $jsonBody -TimeStampField "TimeGenerated"
        
        # Add incident comment if requested
        if ($AddComment -and $IncidentArmId -and $AccessToken) {
            $comment = ConvertTo-IncidentComment -EnrichmentData $formattedData
            $commentResult = Add-IncidentComment -IncidentId $IncidentArmId -Comment $comment -AccessToken $AccessToken
        }
        
        return @{
            Success         = $logResult
            LogRecord       = $logRecord
            FormattedData   = $formattedData
        }
    }
    catch {
        Write-Error "Failed to send DefenderXSOAR data: $_"
        throw
    }
}

function Send-EntityData {
    <#
    .SYNOPSIS
        Sends entity enrichment data to DefenderXSOAR_Entities_CL table
    #>
    [CmdletBinding()]
    param(
        [string]$WorkspaceId,
        [string]$SharedKey,
        [string]$IncidentId,
        [array]$Entities
    )
    
    $records = @()
    foreach ($entity in $Entities) {
        $records += @{
            TimeGenerated   = Get-Date -Format "o"
            IncidentId      = $IncidentId
            EntityType      = $entity.EntityType
            EntityValue     = ($entity.NormalizedData | ConvertTo-Json -Compress)
            Source          = $entity.Source
            CorrelationId   = $entity.CorrelationId
            RawData         = ($entity.RawData | ConvertTo-Json -Compress)
        }
    }
    
    if ($records.Count -gt 0) {
        $jsonBody = $records | ConvertTo-Json -Depth 10
        Send-ToLogAnalytics -WorkspaceId $WorkspaceId -SharedKey $SharedKey -LogType "DefenderXSOAR_Entities" -JsonBody $jsonBody
    }
}

function Send-CorrelationData {
    <#
    .SYNOPSIS
        Sends correlation data to DefenderXSOAR_Correlations_CL table
    #>
    [CmdletBinding()]
    param(
        [string]$WorkspaceId,
        [string]$SharedKey,
        [string]$IncidentId,
        [hashtable]$Correlations
    )
    
    $records = @()
    
    # Email to Endpoint correlations
    foreach ($corr in $Correlations.EmailToEndpoint) {
        $records += @{
            TimeGenerated   = Get-Date -Format "o"
            IncidentId      = $IncidentId
            CorrelationType = 'EmailToEndpoint'
            Description     = $corr.Description
            RiskScore       = $corr.RiskScore
            Severity        = $corr.Severity
            Details         = ($corr | ConvertTo-Json -Compress)
        }
    }
    
    # Identity to Endpoint correlations
    foreach ($corr in $Correlations.IdentityToEndpoint) {
        $records += @{
            TimeGenerated   = Get-Date -Format "o"
            IncidentId      = $IncidentId
            CorrelationType = 'IdentityToEndpoint'
            Description     = $corr.Description
            RiskScore       = $corr.RiskScore
            Severity        = $corr.Severity
            Details         = ($corr | ConvertTo-Json -Compress)
        }
    }
    
    # Add other correlation types...
    foreach ($corr in ($Correlations.CloudToIdentity + $Correlations.EndpointToNetwork + $Correlations.FullKillChain)) {
        if ($corr) {
            $records += @{
                TimeGenerated   = Get-Date -Format "o"
                IncidentId      = $IncidentId
                CorrelationType = $corr.Type
                Description     = $corr.Description
                RiskScore       = $corr.RiskScore
                Severity        = $corr.Severity
                Details         = ($corr | ConvertTo-Json -Compress)
            }
        }
    }
    
    if ($records.Count -gt 0) {
        $jsonBody = $records | ConvertTo-Json -Depth 10
        Send-ToLogAnalytics -WorkspaceId $WorkspaceId -SharedKey $SharedKey -LogType "DefenderXSOAR_Correlations" -JsonBody $jsonBody
    }
}

function Send-DecisionData {
    <#
    .SYNOPSIS
        Sends incident decision data to DefenderXSOAR_Decisions_CL table
    #>
    [CmdletBinding()]
    param(
        [string]$WorkspaceId,
        [string]$SharedKey,
        [string]$IncidentId,
        [hashtable]$Decision
    )
    
    $record = @{
        TimeGenerated   = Get-Date -Format "o"
        IncidentId      = $IncidentId
        Action          = $Decision.Action
        Priority        = $Decision.Priority
        Confidence      = $Decision.Confidence
        Reasoning       = $Decision.Reasoning
        AutomatedAction = $Decision.AutomatedAction
        DecisionFactors = ($Decision.Factors | ConvertTo-Json -Compress)
    }
    
    $jsonBody = @($record) | ConvertTo-Json -Depth 10
    Send-ToLogAnalytics -WorkspaceId $WorkspaceId -SharedKey $SharedKey -LogType "DefenderXSOAR_Decisions" -JsonBody $jsonBody
}

function Send-PlaybookData {
    <#
    .SYNOPSIS
        Sends playbook execution data to DefenderXSOAR_Playbooks_CL table
    #>
    [CmdletBinding()]
    param(
        [string]$WorkspaceId,
        [string]$SharedKey,
        [string]$IncidentId,
        [string]$Product,
        [array]$PlaybookResults
    )
    
    $records = @()
    foreach ($result in $PlaybookResults) {
        $records += @{
            TimeGenerated   = Get-Date -Format "o"
            IncidentId      = $IncidentId
            Product         = $Product
            PlaybookName    = $result.PlaybookName
            ExecutionStatus = $result.Status ?? 'Completed'
            ResultCount     = $result.ResultCount ?? 0
            QueryExecuted   = $result.Query ?? ''
            Results         = ($result.Results | ConvertTo-Json -Compress)
        }
    }
    
    if ($records.Count -gt 0) {
        $jsonBody = $records | ConvertTo-Json -Depth 10
        Send-ToLogAnalytics -WorkspaceId $WorkspaceId -SharedKey $SharedKey -LogType "DefenderXSOAR_Playbooks" -JsonBody $jsonBody
    }
}

function Send-AllDefenderXSOARData {
    <#
    .SYNOPSIS
        Sends all DefenderXSOAR data to multiple custom tables
    #>
    [CmdletBinding()]
    param(
        [string]$WorkspaceId,
        [string]$SharedKey,
        [string]$IncidentId,
        [string]$IncidentArmId,
        [hashtable]$EnrichmentResults,
        [string]$AccessToken,
        [bool]$AddComment = $true
    )
    
    try {
        # Send main enrichment data
        Send-DefenderXSOARData `
            -WorkspaceId $WorkspaceId `
            -SharedKey $SharedKey `
            -IncidentId $IncidentId `
            -IncidentArmId $IncidentArmId `
            -Product 'All' `
            -EnrichmentData $EnrichmentResults `
            -AccessToken $AccessToken `
            -AddComment $AddComment
        
        # Send entity data
        if ($EnrichmentResults.Entities -and $EnrichmentResults.Entities.Count -gt 0) {
            Send-EntityData `
                -WorkspaceId $WorkspaceId `
                -SharedKey $SharedKey `
                -IncidentId $IncidentId `
                -Entities $EnrichmentResults.Entities
        }
        
        # Send correlation data
        if ($EnrichmentResults.Correlations) {
            Send-CorrelationData `
                -WorkspaceId $WorkspaceId `
                -SharedKey $SharedKey `
                -IncidentId $IncidentId `
                -Correlations $EnrichmentResults.Correlations
        }
        
        # Send decision data
        if ($EnrichmentResults.Decision) {
            Send-DecisionData `
                -WorkspaceId $WorkspaceId `
                -SharedKey $SharedKey `
                -IncidentId $IncidentId `
                -Decision $EnrichmentResults.Decision
        }
        
        # Send playbook data
        if ($EnrichmentResults.KQLQueryResults -and $EnrichmentResults.KQLQueryResults.Count -gt 0) {
            Send-PlaybookData `
                -WorkspaceId $WorkspaceId `
                -SharedKey $SharedKey `
                -IncidentId $IncidentId `
                -Product 'All' `
                -PlaybookResults $EnrichmentResults.KQLQueryResults
        }
        
        Write-Host "All DefenderXSOAR data sent to custom tables" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to send all DefenderXSOAR data: $_"
        return $false
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Send-ToLogAnalytics',
    'Add-IncidentComment',
    'Format-EnrichmentResult',
    'ConvertTo-IncidentComment',
    'New-DefenderXSOARRecord',
    'Send-DefenderXSOARData',
    'Send-EntityData',
    'Send-CorrelationData',
    'Send-DecisionData',
    'Send-PlaybookData',
    'Send-AllDefenderXSOARData'
)
