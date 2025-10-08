<#
.SYNOPSIS
    DefenderXSOAR Brain - Central Orchestration Module
.DESCRIPTION
    Central orchestrator that controls all workers, makes decisions, and manages multi-tenant operations
#>

# Import all modules
$ModulePath = $PSScriptRoot
$CommonPath = Join-Path $ModulePath "Common"
$WorkersPath = Join-Path $ModulePath "Workers"
$PlaybooksPath = Join-Path $ModulePath "Playbooks"
$EnrichmentPath = Join-Path $ModulePath "Enrichment"

# Import Common modules
Import-Module (Join-Path $CommonPath "AuthenticationHelper.psm1") -Force
Import-Module (Join-Path $CommonPath "EntityNormalizer.psm1") -Force
Import-Module (Join-Path $CommonPath "DataTableManager.psm1") -Force
Import-Module (Join-Path $CommonPath "CrossCorrelationEngine.psm1") -Force

# Import Enrichment modules
Import-Module (Join-Path $EnrichmentPath "ThreatIntelEnrichment.psm1") -Force
Import-Module (Join-Path $EnrichmentPath "GeoLocationEnrichment.psm1") -Force
Import-Module (Join-Path $EnrichmentPath "ReputationEnrichment.psm1") -Force
Import-Module (Join-Path $EnrichmentPath "BehaviorAnalytics.psm1") -Force

# Import Worker modules
Import-Module (Join-Path $WorkersPath "MDEWorker.psm1") -Force
Import-Module (Join-Path $WorkersPath "MDCWorker.psm1") -Force
Import-Module (Join-Path $WorkersPath "MCASWorker.psm1") -Force
Import-Module (Join-Path $WorkersPath "MDIWorker.psm1") -Force
Import-Module (Join-Path $WorkersPath "MDOWorker.psm1") -Force
Import-Module (Join-Path $WorkersPath "EntraIDWorker.psm1") -Force

# Import Playbook modules
Import-Module (Join-Path $PlaybooksPath "MDEPlaybooks.psm1") -Force
Import-Module (Join-Path $PlaybooksPath "MDCPlaybooks.psm1") -Force
Import-Module (Join-Path $PlaybooksPath "MCASPlaybooks.psm1") -Force
Import-Module (Join-Path $PlaybooksPath "MDIPlaybooks.psm1") -Force
Import-Module (Join-Path $PlaybooksPath "MDOPlaybooks.psm1") -Force
Import-Module (Join-Path $PlaybooksPath "EntraIDPlaybooks.psm1") -Force

# Module-level variables
$script:Config = $null
$script:TenantTokens = @{}

function Initialize-DefenderXSOARBrain {
    <#
    .SYNOPSIS
        Initializes the DefenderXSOAR Brain with configuration
    .PARAMETER ConfigPath
        Path to configuration file
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath
    )
    
    try {
        Write-Host "Initializing DefenderXSOAR Brain..." -ForegroundColor Cyan
        
        if (-not (Test-Path $ConfigPath)) {
            throw "Configuration file not found: $ConfigPath"
        }
        
        $script:Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        
        Write-Host "Configuration loaded successfully" -ForegroundColor Green
        
        # Initialize authentication for each tenant
        foreach ($tenant in $script:Config.Tenants) {
            Write-Host "Initializing tenant: $($tenant.TenantName)" -ForegroundColor Yellow
            
            $tenantConfig = @{
                TenantId     = $tenant.TenantId
                ClientId     = $tenant.ClientId
                ClientSecret = $tenant.ClientSecret
                TenantName   = $tenant.TenantName
            }
            
            $initResult = Initialize-DefenderXSOARAuth -TenantConfig $tenantConfig
            
            if ($initResult) {
                Write-Host "  ✓ Tenant initialized" -ForegroundColor Green
            }
            else {
                Write-Warning "  ✗ Failed to initialize tenant: $($tenant.TenantName)"
            }
        }
        
        Write-Host "DefenderXSOAR Brain initialized successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to initialize DefenderXSOAR Brain: $_"
        return $false
    }
}

function Start-DefenderXSOAREnrichment {
    <#
    .SYNOPSIS
        Orchestrates enrichment across all products
    .PARAMETER IncidentId
        Incident identifier
    .PARAMETER IncidentArmId
        Incident ARM resource ID
    .PARAMETER Entities
        Array of entities from the incident
    .PARAMETER TenantId
        Tenant ID to use
    .PARAMETER Products
        Array of products to query (MDE, MDC, MCAS, MDI, MDO, EntraID)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$IncidentId,
        
        [Parameter(Mandatory = $false)]
        [string]$IncidentArmId,
        
        [Parameter(Mandatory = $true)]
        [array]$Entities,
        
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Products = @('MDE', 'MDC', 'MCAS', 'MDI', 'MDO', 'EntraID')
    )
    
    try {
        Write-Host "`n=== Starting DefenderXSOAR Enrichment ===" -ForegroundColor Cyan
        Write-Host "Incident ID: $IncidentId" -ForegroundColor Yellow
        Write-Host "Entities: $($Entities.Count)" -ForegroundColor Yellow
        Write-Host "Products: $($Products -join ', ')" -ForegroundColor Yellow
        
        # Get tenant configuration
        $tenant = $script:Config.Tenants | Where-Object { $_.TenantId -eq $TenantId } | Select-Object -First 1
        
        if (-not $tenant) {
            throw "Tenant configuration not found for: $TenantId"
        }
        
        # Initialize consolidated results
        $consolidatedResults = @{
            IncidentId        = $IncidentId
            Entities          = @()
            RelatedAlerts     = @()
            ThreatIntel       = @()
            RiskScore         = 0
            Severity          = "Informational"
            Recommendations   = @()
            WatchlistMatches  = @()
            UEBAInsights      = @()
            KQLQueryResults   = @()
            ProductResults    = @{}
        }
        
        # Process each product
        foreach ($product in $Products) {
            Write-Host "`nEnriching with $product..." -ForegroundColor Cyan
            
            try {
                $productResult = Invoke-ProductEnrichment -Product $product -Entities $Entities -Tenant $tenant -IncidentId $IncidentId
                
                if ($productResult) {
                    $consolidatedResults.ProductResults[$product] = $productResult
                    
                    # Merge results
                    $consolidatedResults.Entities += $productResult.Entities
                    $consolidatedResults.RelatedAlerts += $productResult.RelatedAlerts
                    $consolidatedResults.ThreatIntel += $productResult.ThreatIntel
                    $consolidatedResults.RiskScore += $productResult.RiskScore
                    $consolidatedResults.Recommendations += $productResult.Recommendations
                    $consolidatedResults.WatchlistMatches += $productResult.WatchlistMatches
                    $consolidatedResults.UEBAInsights += $productResult.UEBAInsights
                    $consolidatedResults.KQLQueryResults += $productResult.KQLQueryResults
                    
                    Write-Host "  ✓ $product enrichment completed" -ForegroundColor Green
                }
            }
            catch {
                Write-Warning "  ✗ $product enrichment failed: $_"
            }
        }
        
        # Perform advanced enrichments
        Write-Host "`n=== Performing Advanced Enrichment ===" -ForegroundColor Cyan
        
        # Threat Intelligence Enrichment
        Write-Host "Running Threat Intelligence enrichment..." -ForegroundColor Cyan
        try {
            $graphToken = Get-GraphToken -TenantId $tenant.TenantId -ClientId $tenant.ClientId -ClientSecret $tenant.ClientSecret
            $threatIntelResults = Invoke-ThreatIntelEnrichment -Entities $consolidatedResults.Entities -AccessToken $graphToken
            $consolidatedResults.ThreatIntel += $threatIntelResults.ThreatIndicators
            $consolidatedResults.RiskScore += $threatIntelResults.OverallRiskScore
            Write-Host "  ✓ Threat Intel enrichment completed" -ForegroundColor Green
        }
        catch {
            Write-Warning "  ✗ Threat Intel enrichment failed: $_"
        }
        
        # GeoLocation Enrichment
        Write-Host "Running GeoLocation enrichment..." -ForegroundColor Cyan
        try {
            $geoResults = Invoke-GeoLocationEnrichment -Entities $consolidatedResults.Entities
            $consolidatedResults.RiskScore += $geoResults.RiskScore
            if ($geoResults.AnomalousLocations.Count -gt 0) {
                $consolidatedResults.Recommendations += "Anomalous geographic locations detected: $($geoResults.AnomalousLocations.Count) instances"
            }
            Write-Host "  ✓ GeoLocation enrichment completed" -ForegroundColor Green
        }
        catch {
            Write-Warning "  ✗ GeoLocation enrichment failed: $_"
        }
        
        # Reputation Enrichment
        Write-Host "Running Reputation enrichment..." -ForegroundColor Cyan
        try {
            $mdeToken = Get-MDEToken -TenantId $tenant.TenantId -ClientId $tenant.ClientId -ClientSecret $tenant.ClientSecret
            $repResults = Invoke-ReputationEnrichment -Entities $consolidatedResults.Entities -AccessToken $mdeToken
            $consolidatedResults.RiskScore += $repResults.OverallRiskScore
            if ($repResults.LowReputationItems.Count -gt 0) {
                $consolidatedResults.Recommendations += "Low reputation items detected: $($repResults.LowReputationItems.Count) instances"
            }
            Write-Host "  ✓ Reputation enrichment completed" -ForegroundColor Green
        }
        catch {
            Write-Warning "  ✗ Reputation enrichment failed: $_"
        }
        
        # Behavior Analytics
        Write-Host "Running Behavior Analytics..." -ForegroundColor Cyan
        try {
            $behaviorResults = Invoke-BehaviorAnalytics -Entities $consolidatedResults.Entities -BaselinePeriodDays 30
            $consolidatedResults.UEBAInsights += $behaviorResults.BehavioralAnomalies
            $consolidatedResults.RiskScore += $behaviorResults.RiskScore
            Write-Host "  ✓ Behavior Analytics completed" -ForegroundColor Green
        }
        catch {
            Write-Warning "  ✗ Behavior Analytics failed: $_"
        }
        
        # Cross-Product Correlation
        Write-Host "`n=== Running Cross-Product Correlation ===" -ForegroundColor Cyan
        try {
            $correlationResults = Invoke-CrossProductCorrelation -ProductResults $consolidatedResults.ProductResults -TimeWindow 60
            $consolidatedResults.Correlations = $correlationResults
            $consolidatedResults.RiskScore += $correlationResults.CorrelationScore
            
            Write-Host "Correlation Results:" -ForegroundColor Yellow
            Write-Host "  Email→Endpoint: $($correlationResults.EmailToEndpoint.Count)"
            Write-Host "  Identity→Endpoint: $($correlationResults.IdentityToEndpoint.Count)"
            Write-Host "  Cloud→Identity: $($correlationResults.CloudToIdentity.Count)"
            Write-Host "  Endpoint→Network: $($correlationResults.EndpointToNetwork.Count)"
            Write-Host "  Full Kill Chain: $($correlationResults.FullKillChain.Count)"
            Write-Host "  Correlation Score: $($correlationResults.CorrelationScore)"
            Write-Host "  Risk Level: $($correlationResults.RiskLevel)"
            
            if ($correlationResults.CorrelationScore -gt 0) {
                $consolidatedResults.Recommendations += "Multi-product attack correlation detected with risk level: $($correlationResults.RiskLevel)"
            }
            
            Write-Host "  ✓ Cross-product correlation completed" -ForegroundColor Green
        }
        catch {
            Write-Warning "  ✗ Cross-product correlation failed: $_"
        }
        
        # Calculate final risk score and severity
        $consolidatedResults = Invoke-RiskScoring -Results $consolidatedResults
        
        # Make incident decision
        $decision = Invoke-IncidentDecision -Results $consolidatedResults
        Write-Host "`nIncident Decision: $($decision.Action)" -ForegroundColor Magenta
        Write-Host "Recommended Priority: $($decision.Priority)" -ForegroundColor Magenta
        
        # Send data to Log Analytics
        if ($script:Config.LogAnalytics.Enabled) {
            Write-Host "`nSending data to Log Analytics custom tables..." -ForegroundColor Cyan
            
            $mgmtToken = $null
            if ($IncidentArmId) {
                $mgmtToken = Get-AzureManagementToken -TenantId $tenant.TenantId -ClientId $tenant.ClientId -ClientSecret $tenant.ClientSecret
            }
            
            # Add decision to consolidated results
            $consolidatedResults.Decision = $decision
            
            # Send to all custom tables
            $allDataResult = Send-AllDefenderXSOARData `
                -WorkspaceId $script:Config.LogAnalytics.WorkspaceId `
                -SharedKey $script:Config.LogAnalytics.SharedKey `
                -IncidentId $IncidentId `
                -IncidentArmId $IncidentArmId `
                -EnrichmentResults $consolidatedResults `
                -AccessToken $mgmtToken `
                -AddComment $true
            
            if ($allDataResult) {
                Write-Host "  ✓ Data sent to all custom tables:" -ForegroundColor Green
                Write-Host "    • DefenderXSOAR_CL (Main enrichment data)" -ForegroundColor Gray
                Write-Host "    • DefenderXSOAR_Entities_CL (Entity details)" -ForegroundColor Gray
                Write-Host "    • DefenderXSOAR_Correlations_CL (Cross-product correlations)" -ForegroundColor Gray
                Write-Host "    • DefenderXSOAR_Decisions_CL (Incident decisions)" -ForegroundColor Gray
                Write-Host "    • DefenderXSOAR_Playbooks_CL (Playbook results)" -ForegroundColor Gray
            }
        }
        
        # Execute external workflows if configured
        if ($decision.ExecuteWorkflow -and $script:Config.ExternalWorkflows.Enabled) {
            Write-Host "`nExecuting external workflow..." -ForegroundColor Cyan
            Invoke-ExternalWorkflow -Decision $decision -Results $consolidatedResults
        }
        
        Write-Host "`n=== DefenderXSOAR Enrichment Completed ===" -ForegroundColor Green
        
        return @{
            Success = $true
            Results = $consolidatedResults
            Decision = $decision
        }
    }
    catch {
        Write-Error "DefenderXSOAR enrichment failed: $_"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Invoke-ProductEnrichment {
    <#
    .SYNOPSIS
        Invokes enrichment for a specific product
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Product,
        
        [Parameter(Mandatory = $true)]
        [array]$Entities,
        
        [Parameter(Mandatory = $true)]
        [object]$Tenant,
        
        [Parameter(Mandatory = $true)]
        [string]$IncidentId
    )
    
    switch ($Product) {
        'MDE' {
            $token = Get-SecurityCenterToken -TenantId $Tenant.TenantId -ClientId $Tenant.ClientId -ClientSecret $Tenant.ClientSecret
            return Start-MDEEnrichment -Entities $Entities -AccessToken $token -IncidentId $IncidentId
        }
        
        'MDC' {
            $token = Get-AzureManagementToken -TenantId $Tenant.TenantId -ClientId $Tenant.ClientId -ClientSecret $Tenant.ClientSecret
            $subscriptionId = $Tenant.SubscriptionId ?? $script:Config.Azure.DefaultSubscriptionId
            return Start-MDCEnrichment -Entities $Entities -SubscriptionId $subscriptionId -AccessToken $token -IncidentId $IncidentId
        }
        
        'MCAS' {
            $tenantUrl = $Tenant.MCASUrl ?? $script:Config.MCAS.TenantUrl
            $apiToken = $Tenant.MCASToken ?? $script:Config.MCAS.APIToken
            return Start-MCASEnrichment -Entities $Entities -TenantUrl $tenantUrl -AccessToken $apiToken -IncidentId $IncidentId
        }
        
        'MDI' {
            $token = Get-GraphAPIToken -TenantId $Tenant.TenantId -ClientId $Tenant.ClientId -ClientSecret $Tenant.ClientSecret
            return Start-MDIEnrichment -Entities $Entities -AccessToken $token -IncidentId $IncidentId
        }
        
        'MDO' {
            $token = Get-GraphAPIToken -TenantId $Tenant.TenantId -ClientId $Tenant.ClientId -ClientSecret $Tenant.ClientSecret
            return Start-MDOEnrichment -Entities $Entities -AccessToken $token -IncidentId $IncidentId
        }
        
        'EntraID' {
            $token = Get-GraphAPIToken -TenantId $Tenant.TenantId -ClientId $Tenant.ClientId -ClientSecret $Tenant.ClientSecret
            return Start-EntraIDEnrichment -Entities $Entities -AccessToken $token -IncidentId $IncidentId
        }
        
        default {
            Write-Warning "Unknown product: $Product"
            return $null
        }
    }
}

function Invoke-RiskScoring {
    <#
    .SYNOPSIS
        Calculates consolidated risk score and adjusts severity
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Results
    )
    
    # Normalize risk score (0-100)
    $maxScore = 500
    $normalizedScore = [Math]::Min(100, ($Results.RiskScore / $maxScore) * 100)
    $Results.RiskScore = [int]$normalizedScore
    
    # Determine severity based on risk score and threat intel
    $criticalThreatIntel = ($Results.ThreatIntel | Where-Object { $_.Type -in @("KerberosAttack", "LateralMovement", "PhishingCampaigns") }).Count
    
    if ($Results.RiskScore -ge 80 -or $criticalThreatIntel -gt 3) {
        $Results.Severity = "Critical"
    }
    elseif ($Results.RiskScore -ge 60 -or $criticalThreatIntel -gt 1) {
        $Results.Severity = "High"
    }
    elseif ($Results.RiskScore -ge 40) {
        $Results.Severity = "Medium"
    }
    elseif ($Results.RiskScore -ge 20) {
        $Results.Severity = "Low"
    }
    else {
        $Results.Severity = "Informational"
    }
    
    return $Results
}

function Invoke-IncidentDecision {
    <#
    .SYNOPSIS
        Makes decision on incident handling
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Results
    )
    
    $decision = @{
        Action = "Investigate"
        Priority = "Medium"
        ExecuteWorkflow = $false
        Reasoning = @()
    }
    
    # Decision logic based on severity and findings
    switch ($Results.Severity) {
        'Critical' {
            $decision.Action = "Escalate"
            $decision.Priority = "Critical"
            $decision.ExecuteWorkflow = $true
            $decision.Reasoning += "Critical severity detected - immediate escalation required"
        }
        
        'High' {
            $decision.Action = "Investigate"
            $decision.Priority = "High"
            $decision.ExecuteWorkflow = $true
            $decision.Reasoning += "High severity requires immediate investigation"
        }
        
        'Medium' {
            $decision.Action = "Investigate"
            $decision.Priority = "Medium"
            $decision.Reasoning += "Medium severity - standard investigation process"
        }
        
        'Low' {
            $decision.Action = "Monitor"
            $decision.Priority = "Low"
            $decision.Reasoning += "Low severity - continue monitoring"
        }
        
        'Informational' {
            if ($Results.RelatedAlerts.Count -eq 0 -and $Results.ThreatIntel.Count -eq 0) {
                $decision.Action = "Close"
                $decision.Priority = "Informational"
                $decision.Reasoning += "No significant findings - consider false positive"
            }
            else {
                $decision.Action = "Monitor"
                $decision.Priority = "Low"
            }
        }
    }
    
    # Additional decision factors
    if ($Results.UEBAInsights.Count -gt 5) {
        $decision.Priority = "High"
        $decision.Reasoning += "Multiple behavioral anomalies detected"
    }
    
    if ($Results.RelatedAlerts.Count -gt 10) {
        $decision.Action = "Escalate"
        $decision.Priority = "High"
        $decision.Reasoning += "High volume of related alerts indicates potential campaign"
    }
    
    return $decision
}

function Invoke-ExternalWorkflow {
    <#
    .SYNOPSIS
        Triggers external Logic App or Function App
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Decision,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Results
    )
    
    try {
        $workflowUrl = $script:Config.ExternalWorkflows.WorkflowUrl
        
        if (-not $workflowUrl) {
            Write-Warning "External workflow URL not configured"
            return
        }
        
        $body = @{
            Decision = $Decision
            Results = $Results
            Timestamp = Get-Date -Format "o"
        } | ConvertTo-Json -Depth 10
        
        $response = Invoke-RestMethod -Uri $workflowUrl -Method Post -Body $body -ContentType "application/json"
        
        Write-Host "  ✓ External workflow executed successfully" -ForegroundColor Green
        return $response
    }
    catch {
        Write-Error "Failed to execute external workflow: $_"
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Initialize-DefenderXSOARBrain',
    'Start-DefenderXSOAREnrichment',
    'Invoke-ProductEnrichment',
    'Invoke-RiskScoring',
    'Invoke-IncidentDecision',
    'Invoke-ExternalWorkflow'
)
