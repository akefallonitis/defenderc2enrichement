<#
.SYNOPSIS
    Unified Risk Scoring Engine for DefenderXSOAR
.DESCRIPTION
    Combines Microsoft native scores, STAT analytics, and custom scoring into a unified risk score
    with confidence levels, explainability, and actionable recommendations
#>

# CacheManager class for API response caching
class CacheManager {
    [hashtable]$Cache = @{}
    [int]$DefaultTTLSeconds = 300
    
    [object] Get([string]$Key) {
        if ($this.Cache.ContainsKey($Key)) {
            $entry = $this.Cache[$Key]
            if ((Get-Date) -lt $entry.Expiration) {
                return $entry.Value
            }
            else {
                $this.Cache.Remove($Key)
            }
        }
        return $null
    }
    
    [void] Set([string]$Key, [object]$Value, [int]$TTLSeconds = -1) {
        $ttl = if ($TTLSeconds -gt 0) { $TTLSeconds } else { $this.DefaultTTLSeconds }
        $this.Cache[$Key] = @{
            Value = $Value
            Expiration = (Get-Date).AddSeconds($ttl)
        }
    }
    
    [void] Clear() {
        $this.Cache.Clear()
    }
    
    [void] Remove([string]$Key) {
        if ($this.Cache.ContainsKey($Key)) {
            $this.Cache.Remove($Key)
        }
    }
}

# CircuitBreaker pattern for resilience
class CircuitBreaker {
    [int]$FailureThreshold = 5
    [int]$TimeoutSeconds = 60
    [string]$State = 'Closed'
    [int]$FailureCount = 0
    [datetime]$LastFailureTime = [datetime]::MinValue
    
    [object] Execute([scriptblock]$Action) {
        if ($this.State -eq 'Open') {
            if ((Get-Date) -gt $this.LastFailureTime.AddSeconds($this.TimeoutSeconds)) {
                Write-Verbose "Circuit breaker: Transitioning to Half-Open state"
                $this.State = 'Half-Open'
            }
            else {
                throw "Circuit breaker is OPEN - too many failures"
            }
        }
        
        try {
            $result = & $Action
            
            if ($this.State -eq 'Half-Open') {
                Write-Verbose "Circuit breaker: Success in Half-Open state, closing circuit"
                $this.State = 'Closed'
                $this.FailureCount = 0
            }
            
            return $result
        }
        catch {
            $this.FailureCount++
            $this.LastFailureTime = Get-Date
            
            if ($this.FailureCount -ge $this.FailureThreshold) {
                Write-Warning "Circuit breaker: Threshold reached ($($this.FailureCount) failures), opening circuit"
                $this.State = 'Open'
            }
            
            throw $_
        }
    }
    
    [void] Reset() {
        $this.State = 'Closed'
        $this.FailureCount = 0
        $this.LastFailureTime = [datetime]::MinValue
    }
}

# KQL Query Builder
class KQLBuilder {
    [string]$BaseTable
    [System.Collections.Generic.List[string]]$WhereConditions = [System.Collections.Generic.List[string]]::new()
    [System.Collections.Generic.List[string]]$ProjectFields = [System.Collections.Generic.List[string]]::new()
    [string]$SummarizeClause = ""
    [string]$OrderByClause = ""
    [int]$LimitValue = 0
    
    KQLBuilder([string]$table) {
        $this.BaseTable = $table
    }
    
    [KQLBuilder] Where([string]$Condition) {
        $this.WhereConditions.Add($Condition)
        return $this
    }
    
    [KQLBuilder] Project([string[]]$Fields) {
        foreach ($field in $Fields) {
            $this.ProjectFields.Add($field)
        }
        return $this
    }
    
    [KQLBuilder] Summarize([string]$Clause) {
        $this.SummarizeClause = $Clause
        return $this
    }
    
    [KQLBuilder] OrderBy([string]$Field, [string]$Direction = "asc") {
        $this.OrderByClause = "$Field $Direction"
        return $this
    }
    
    [KQLBuilder] Limit([int]$Count) {
        $this.LimitValue = $Count
        return $this
    }
    
    [string] Build() {
        $query = $this.BaseTable
        
        if ($this.WhereConditions.Count -gt 0) {
            $query += "`n| where " + ($this.WhereConditions -join " and ")
        }
        
        if ($this.ProjectFields.Count -gt 0) {
            $query += "`n| project " + ($this.ProjectFields -join ", ")
        }
        
        if ($this.SummarizeClause) {
            $query += "`n| summarize $($this.SummarizeClause)"
        }
        
        if ($this.OrderByClause) {
            $query += "`n| order by $($this.OrderByClause)"
        }
        
        if ($this.LimitValue -gt 0) {
            $query += "`n| limit $($this.LimitValue)"
        }
        
        return $query
    }
}

# Query Optimizer
class QueryOptimizer {
    [string] OptimizeKQL([string]$Query) {
        # Remove redundant whitespace
        $optimized = $Query -replace '\s+', ' '
        $optimized = $optimized.Trim()
        
        # Add performance hints for common patterns
        if ($optimized -match 'where.*TimeGenerated') {
            # Already has time filter - good
        }
        else {
            Write-Verbose "Query Optimizer: Query missing TimeGenerated filter, may be slow"
        }
        
        return $optimized
    }
    
    [array] BatchQueries([array]$Queries) {
        $batches = @()
        $currentBatch = @()
        $batchSize = 5
        
        foreach ($query in $Queries) {
            $currentBatch += $query
            if ($currentBatch.Count -ge $batchSize) {
                $batches += ,@($currentBatch)
                $currentBatch = @()
            }
        }
        
        if ($currentBatch.Count -gt 0) {
            $batches += ,@($currentBatch)
        }
        
        return $batches
    }
}

# Enhanced Risk Scorer with ML-like features
class EnhancedRiskScorer {
    [hashtable]$FeatureWeights = @{
        AlertCount = 0.15
        AlertSeverity = 0.20
        EntityRisk = 0.15
        ThreatIntel = 0.20
        BehavioralAnomaly = 0.15
        TemporalPattern = 0.10
        GeographicAnomaly = 0.05
    }
    
    [double] CalculateScore([object[]]$Alerts, [object[]]$Entities, [object[]]$ThreatIntel) {
        $features = @{
            AlertCount = $this.ExtractAlertCountFeature($Alerts)
            AlertSeverity = $this.ExtractAlertSeverityFeature($Alerts)
            EntityRisk = $this.ExtractEntityRiskFeature($Entities)
            ThreatIntel = $this.ExtractThreatIntelFeature($ThreatIntel)
            BehavioralAnomaly = $this.ExtractBehavioralFeature($Alerts)
            TemporalPattern = $this.ExtractTemporalFeature($Alerts)
            GeographicAnomaly = $this.ExtractGeographicFeature($Entities)
        }
        
        $score = 0
        foreach ($feature in $features.Keys) {
            $score += $features[$feature] * $this.FeatureWeights[$feature]
        }
        
        return [Math]::Min(100, [Math]::Max(0, $score))
    }
    
    [double] ExtractAlertCountFeature([object[]]$Alerts) {
        if (-not $Alerts) { return 0 }
        # Logarithmic scale for alert count
        return [Math]::Min(100, [Math]::Log($Alerts.Count + 1, 2) * 20)
    }
    
    [double] ExtractAlertSeverityFeature([object[]]$Alerts) {
        if (-not $Alerts) { return 0 }
        $severityMap = @{ Critical = 100; High = 75; Medium = 50; Low = 25; Informational = 10 }
        $avgSeverity = ($Alerts | ForEach-Object { $severityMap[$_.Severity] ?? 25 } | Measure-Object -Average).Average
        return $avgSeverity ?? 0
    }
    
    [double] ExtractEntityRiskFeature([object[]]$Entities) {
        if (-not $Entities) { return 0 }
        return [Math]::Min(100, $Entities.Count * 10)
    }
    
    [double] ExtractThreatIntelFeature([object[]]$ThreatIntel) {
        if (-not $ThreatIntel) { return 0 }
        $criticalIntel = ($ThreatIntel | Where-Object { $_.Type -in @("KerberosAttack", "LateralMovement", "PhishingCampaigns") }).Count
        return [Math]::Min(100, $criticalIntel * 25)
    }
    
    [double] ExtractBehavioralFeature([object[]]$Alerts) {
        if (-not $Alerts) { return 0 }
        # Check for behavioral indicators in alerts
        $behavioralCount = ($Alerts | Where-Object { $_.Category -match 'Behavior|UEBA|Anomaly' }).Count
        return [Math]::Min(100, $behavioralCount * 15)
    }
    
    [double] ExtractTemporalFeature([object[]]$Alerts) {
        if (-not $Alerts -or $Alerts.Count -lt 2) { return 0 }
        # Calculate time concentration (alerts in short time window)
        $timestamps = $Alerts | Where-Object { $_.Timestamp } | Select-Object -ExpandProperty Timestamp
        if ($timestamps.Count -lt 2) { return 0 }
        
        $timeSpan = ([datetime]$timestamps[0] - [datetime]$timestamps[-1]).TotalHours
        if ($timeSpan -lt 1) { return 75 }  # High concentration
        elseif ($timeSpan -lt 6) { return 50 }
        else { return 25 }
    }
    
    [double] ExtractGeographicFeature([object[]]$Entities) {
        if (-not $Entities) { return 0 }
        $uniqueLocations = ($Entities | Where-Object { $_.Location } | Select-Object -ExpandProperty Location -Unique).Count
        if ($uniqueLocations -gt 10) { return 75 }
        elseif ($uniqueLocations -gt 5) { return 50 }
        elseif ($uniqueLocations -gt 2) { return 25 }
        else { return 0 }
    }
}

# Progressive Enrichment Manager
class ProgressiveEnrichmentManager {
    [int]$DefaultTimeLimit = 30
    
    [hashtable] ExecuteProgressive([object[]]$Entities, [int]$TimeLimit, [hashtable]$Config) {
        if ($TimeLimit -le 0) { $TimeLimit = $this.DefaultTimeLimit }
        
        $startTime = Get-Date
        $results = @{
            Completed = @()
            Partial = @()
            Skipped = @()
            TimeElapsed = 0
        }
        
        # Priority order for enrichment
        $priorities = @('Critical', 'High', 'Medium', 'Low')
        
        foreach ($priority in $priorities) {
            $elapsed = ((Get-Date) - $startTime).TotalSeconds
            if ($elapsed -ge $TimeLimit) {
                Write-Warning "Progressive enrichment: Time limit reached at priority $priority"
                break
            }
            
            $entitiesAtPriority = $Entities | Where-Object { $_.Priority -eq $priority }
            foreach ($entity in $entitiesAtPriority) {
                $elapsed = ((Get-Date) - $startTime).TotalSeconds
                if ($elapsed -ge $TimeLimit) {
                    $results.Skipped += $entity
                    continue
                }
                
                try {
                    # Adaptive timeout based on remaining time
                    $remainingTime = $TimeLimit - $elapsed
                    $entityTimeout = [Math]::Min(5, $remainingTime / 2)
                    
                    # Simulate enrichment with timeout
                    $enriched = $this.EnrichWithTimeout($entity, $entityTimeout)
                    $results.Completed += $enriched
                }
                catch {
                    Write-Warning "Progressive enrichment: Failed to enrich entity $($entity.Name)"
                    $results.Partial += $entity
                }
            }
        }
        
        $results.TimeElapsed = ((Get-Date) - $startTime).TotalSeconds
        return $results
    }
    
    [object] EnrichWithTimeout([object]$Entity, [double]$TimeoutSeconds) {
        # Placeholder for actual enrichment logic with timeout
        return $Entity
    }
}

# Unified Risk Scorer - Main class
class UnifiedRiskScorer {
    [hashtable]$Config
    [CacheManager]$Cache
    [EnhancedRiskScorer]$EnhancedScorer
    
    UnifiedRiskScorer([hashtable]$Configuration) {
        $this.Config = $Configuration
        $this.Cache = [CacheManager]::new()
        $this.EnhancedScorer = [EnhancedRiskScorer]::new()
    }
    
    [hashtable] CalculateUnifiedRiskScore([object]$IncidentData, [object[]]$Entities, [hashtable]$EnrichmentResults) {
        $cacheKey = "RiskScore_$($IncidentData.IncidentId)"
        $cached = $this.Cache.Get($cacheKey)
        if ($cached) {
            Write-Verbose "Unified Risk Scorer: Returning cached result"
            return $cached
        }
        
        # Extract scoring configuration
        $scoringConfig = $this.Config.UnifiedRiskScoring ?? @{
            Enabled = $true
            ScoringWeights = @{ Microsoft = 0.35; STAT = 0.35; Custom = 0.30 }
            DynamicWeightAdjustment = @{ Enabled = $false }
            ConfidenceThresholds = @{ High = 0.8; Medium = 0.6; Low = 0.4 }
            ContextualAdjustments = @{ AfterHoursBoost = 1.15; CriticalAssetBoost = 1.25 }
        }
        
        # Calculate individual scores
        $microsoftScore = $this.CalculateMicrosoftNativeScore($IncidentData, $EnrichmentResults)
        $statScore = $this.CalculateSTATScore($Entities, $EnrichmentResults)
        $customScore = $this.CalculateCustomScore($EnrichmentResults)
        
        # Apply weights
        $weights = $scoringConfig.ScoringWeights
        $weightedScore = (
            ($microsoftScore * $weights.Microsoft) +
            ($statScore * $weights.STAT) +
            ($customScore * $weights.Custom)
        )
        
        # Apply contextual adjustments
        $adjustedScore = $this.ApplyContextualAdjustments($weightedScore, $IncidentData, $scoringConfig.ContextualAdjustments)
        
        # Calculate confidence
        $confidence = $this.CalculateConfidence($microsoftScore, $statScore, $customScore, $EnrichmentResults)
        
        # Determine severity
        $severity = $this.DetermineSeverity($adjustedScore, $confidence)
        
        # Generate explainability
        $explainability = $this.GenerateExplainability($microsoftScore, $statScore, $customScore, $weights)
        
        # Generate recommendations
        $recommendations = $this.GenerateRecommendations($adjustedScore, $severity, $EnrichmentResults)
        
        $result = @{
            FinalScore = [Math]::Round($adjustedScore, 2)
            Severity = $severity
            Confidence = [Math]::Round($confidence, 2)
            ComponentScores = @{
                Microsoft = [Math]::Round($microsoftScore, 2)
                STAT = [Math]::Round($statScore, 2)
                Custom = [Math]::Round($customScore, 2)
            }
            Explainability = $explainability
            Recommendations = $recommendations
        }
        
        # Cache result
        $this.Cache.Set($cacheKey, $result, 300)
        
        return $result
    }
    
    [double] CalculateMicrosoftNativeScore([object]$IncidentData, [hashtable]$EnrichmentResults) {
        $score = 0
        $count = 0
        
        # Defender for Endpoint alerts
        if ($EnrichmentResults.ProductResults.MDE) {
            $mdeScore = $EnrichmentResults.ProductResults.MDE.RiskScore ?? 0
            $score += $mdeScore
            $count++
        }
        
        # Microsoft Defender for Cloud (Secure Score)
        if ($EnrichmentResults.ProductResults.MDC) {
            $mdcScore = $EnrichmentResults.ProductResults.MDC.RiskScore ?? 0
            $score += $mdcScore
            $count++
        }
        
        # Identity Protection
        if ($EnrichmentResults.ProductResults.EntraID) {
            $identityScore = $EnrichmentResults.ProductResults.EntraID.RiskScore ?? 0
            $score += $identityScore
            $count++
        }
        
        # Sentinel native severity
        if ($IncidentData.Severity) {
            $severityScore = switch ($IncidentData.Severity) {
                'Critical' { 90 }
                'High' { 70 }
                'Medium' { 50 }
                'Low' { 30 }
                default { 20 }
            }
            $score += $severityScore
            $count++
        }
        
        if ($count -gt 0) {
            return $score / $count
        }
        else {
            return 0
        }
    }
    
    [double] CalculateSTATScore([object[]]$Entities, [hashtable]$EnrichmentResults) {
        # STAT-like analytics using ML features
        $alerts = $EnrichmentResults.RelatedAlerts ?? @()
        $threatIntel = $EnrichmentResults.ThreatIntel ?? @()
        
        $statScore = $this.EnhancedScorer.CalculateScore($alerts, $Entities, $threatIntel)
        
        # Add behavioral analytics
        $uebaInsights = $EnrichmentResults.UEBAInsights ?? @()
        if ($uebaInsights.Count -gt 0) {
            $behaviorBoost = [Math]::Min(20, $uebaInsights.Count * 5)
            $statScore += $behaviorBoost
        }
        
        return [Math]::Min(100, $statScore)
    }
    
    [double] CalculateCustomScore([hashtable]$EnrichmentResults) {
        # Existing custom scoring logic (weighted/correlated)
        $customScore = $EnrichmentResults.RiskScore ?? 0
        
        # Add correlation boost
        if ($EnrichmentResults.Correlations) {
            $correlationScore = $EnrichmentResults.Correlations.CorrelationScore ?? 0
            $customScore += $correlationScore
        }
        
        return [Math]::Min(100, $customScore)
    }
    
    [double] ApplyContextualAdjustments([double]$Score, [object]$IncidentData, [hashtable]$Adjustments) {
        $adjustedScore = $Score
        
        # After-hours boost
        $currentHour = (Get-Date).Hour
        if ($currentHour -lt 6 -or $currentHour -gt 20) {
            $boost = $Adjustments.AfterHoursBoost ?? 1.15
            $adjustedScore *= $boost
            Write-Verbose "Applied after-hours boost: $boost"
        }
        
        # Critical asset boost (placeholder - would check asset criticality)
        if ($IncidentData.CriticalAsset -eq $true) {
            $boost = $Adjustments.CriticalAssetBoost ?? 1.25
            $adjustedScore *= $boost
            Write-Verbose "Applied critical asset boost: $boost"
        }
        
        return [Math]::Min(100, $adjustedScore)
    }
    
    [double] CalculateConfidence([double]$MicrosoftScore, [double]$STATScore, [double]$CustomScore, [hashtable]$EnrichmentResults) {
        # Confidence based on score agreement and data completeness
        $scores = @($MicrosoftScore, $STATScore, $CustomScore) | Where-Object { $_ -gt 0 }
        if ($scores.Count -eq 0) { return 0.1 }
        
        $mean = ($scores | Measure-Object -Average).Average
        $variance = ($scores | ForEach-Object { [Math]::Pow($_ - $mean, 2) } | Measure-Object -Average).Average
        $stdDev = [Math]::Sqrt($variance)
        
        # Lower standard deviation = higher confidence
        $agreement = 1 - ([Math]::Min($stdDev / 50, 1))
        
        # Data completeness factor
        $dataCompleteness = 0.5
        if ($EnrichmentResults.RelatedAlerts.Count -gt 0) { $dataCompleteness += 0.2 }
        if ($EnrichmentResults.ThreatIntel.Count -gt 0) { $dataCompleteness += 0.2 }
        if ($EnrichmentResults.UEBAInsights.Count -gt 0) { $dataCompleteness += 0.1 }
        
        $confidence = ($agreement * 0.6 + $dataCompleteness * 0.4)
        return [Math]::Min(1.0, $confidence)
    }
    
    [string] DetermineSeverity([double]$Score, [double]$Confidence) {
        # Severity thresholds adjusted by confidence
        $threshold = if ($Confidence -ge 0.8) { 0.9 } else { 1.0 }
        
        if ($Score -ge 80 * $threshold) { return "Critical" }
        elseif ($Score -ge 60 * $threshold) { return "High" }
        elseif ($Score -ge 40 * $threshold) { return "Medium" }
        elseif ($Score -ge 20 * $threshold) { return "Low" }
        else { return "Informational" }
    }
    
    [hashtable] GenerateExplainability([double]$MicrosoftScore, [double]$STATScore, [double]$CustomScore, [hashtable]$Weights) {
        return @{
            Summary = "Risk score calculated from multiple sources"
            ComponentBreakdown = @{
                "Microsoft Native (35%)" = [Math]::Round($MicrosoftScore, 2)
                "STAT Analytics (35%)" = [Math]::Round($STATScore, 2)
                "Custom Scoring (30%)" = [Math]::Round($CustomScore, 2)
            }
            TopContributors = @(
                @{ Component = "Microsoft Native"; Score = $MicrosoftScore; Weight = $Weights.Microsoft }
                @{ Component = "STAT Analytics"; Score = $STATScore; Weight = $Weights.STAT }
                @{ Component = "Custom Scoring"; Score = $CustomScore; Weight = $Weights.Custom }
            ) | Sort-Object { $_.Score * $_.Weight } -Descending | Select-Object -First 2
        }
    }
    
    [array] GenerateRecommendations([double]$Score, [string]$Severity, [hashtable]$EnrichmentResults) {
        $recommendations = @()
        
        if ($Severity -in @("Critical", "High")) {
            $recommendations += "Immediate investigation required - risk score $([Math]::Round($Score, 0))/100"
        }
        
        if ($EnrichmentResults.ThreatIntel.Count -gt 3) {
            $recommendations += "Multiple threat intelligence matches detected - review IoCs"
        }
        
        if ($EnrichmentResults.UEBAInsights.Count -gt 5) {
            $recommendations += "Significant behavioral anomalies detected - review user activity"
        }
        
        if ($EnrichmentResults.Correlations -and $EnrichmentResults.Correlations.CorrelationScore -gt 50) {
            $recommendations += "Cross-product attack correlation detected - review attack chain"
        }
        
        if ($Score -gt 70) {
            $recommendations += "Consider isolating affected assets and resetting credentials"
        }
        
        return $recommendations
    }
}

# Module-level functions
function New-UnifiedRiskScorer {
    <#
    .SYNOPSIS
        Creates a new UnifiedRiskScorer instance
    .PARAMETER Configuration
        Configuration hashtable with scoring settings
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Configuration
    )
    
    return [UnifiedRiskScorer]::new($Configuration)
}

function New-CacheManager {
    <#
    .SYNOPSIS
        Creates a new CacheManager instance
    #>
    [CmdletBinding()]
    param()
    
    return [CacheManager]::new()
}

function New-CircuitBreaker {
    <#
    .SYNOPSIS
        Creates a new CircuitBreaker instance
    .PARAMETER FailureThreshold
        Number of failures before opening circuit
    .PARAMETER TimeoutSeconds
        Timeout before attempting to close circuit
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$FailureThreshold = 5,
        
        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 60
    )
    
    $breaker = [CircuitBreaker]::new()
    $breaker.FailureThreshold = $FailureThreshold
    $breaker.TimeoutSeconds = $TimeoutSeconds
    return $breaker
}

function New-KQLBuilder {
    <#
    .SYNOPSIS
        Creates a new KQL query builder
    .PARAMETER BaseTable
        Base KQL table name
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaseTable
    )
    
    return [KQLBuilder]::new($BaseTable)
}

function New-QueryOptimizer {
    <#
    .SYNOPSIS
        Creates a new QueryOptimizer instance
    #>
    [CmdletBinding()]
    param()
    
    return [QueryOptimizer]::new()
}

function New-EnhancedRiskScorer {
    <#
    .SYNOPSIS
        Creates a new EnhancedRiskScorer instance
    #>
    [CmdletBinding()]
    param()
    
    return [EnhancedRiskScorer]::new()
}

function New-ProgressiveEnrichmentManager {
    <#
    .SYNOPSIS
        Creates a new ProgressiveEnrichmentManager instance
    #>
    [CmdletBinding()]
    param()
    
    return [ProgressiveEnrichmentManager]::new()
}

# Export module members
Export-ModuleMember -Function @(
    'New-UnifiedRiskScorer',
    'New-CacheManager',
    'New-CircuitBreaker',
    'New-KQLBuilder',
    'New-QueryOptimizer',
    'New-EnhancedRiskScorer',
    'New-ProgressiveEnrichmentManager'
)
