<#
.SYNOPSIS
    Example demonstrating the Unified Risk Scoring Engine and new features
.DESCRIPTION
    This example shows how to use the new unified risk scoring engine, utility classes,
    and parallel worker execution in DefenderXSOAR
#>

# Import required modules
$ModulePath = Join-Path $PSScriptRoot ".." "Modules"
Import-Module (Join-Path $ModulePath "Common" "UnifiedRiskScorer.psm1") -Force

Write-Host @"
╔═══════════════════════════════════════════════════════════════════╗
║      DefenderXSOAR Unified Risk Scoring Example                  ║
╚═══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# ============================================================================
# 1. CACHE MANAGER EXAMPLE
# ============================================================================
Write-Host "`n=== CacheManager Example ===" -ForegroundColor Yellow
$cache = New-CacheManager
Write-Host "Created CacheManager with default TTL: $($cache.DefaultTTLSeconds) seconds" -ForegroundColor Gray

# Cache some data
$cache.Set("user-risk-score", 75, 300)
$cache.Set("device-status", "compromised", 600)

# Retrieve from cache
$score = $cache.Get("user-risk-score")
Write-Host "Retrieved cached risk score: $score" -ForegroundColor Green

# ============================================================================
# 2. CIRCUIT BREAKER EXAMPLE
# ============================================================================
Write-Host "`n=== CircuitBreaker Example ===" -ForegroundColor Yellow
$breaker = New-CircuitBreaker -FailureThreshold 3 -TimeoutSeconds 30
Write-Host "Created CircuitBreaker with threshold: $($breaker.FailureThreshold)" -ForegroundColor Gray

# Execute protected operation
try {
    $result = $breaker.Execute({
        # Simulate API call
        return "API call successful"
    })
    Write-Host "Circuit breaker result: $result" -ForegroundColor Green
}
catch {
    Write-Host "Operation failed: $_" -ForegroundColor Red
}

# ============================================================================
# 3. KQL BUILDER EXAMPLE
# ============================================================================
Write-Host "`n=== KQLBuilder Example ===" -ForegroundColor Yellow
$builder = New-KQLBuilder -BaseTable "SecurityAlert"

$query = ($builder.Where("TimeGenerated > ago(24h)")).Where("AlertSeverity in ('High', 'Critical')").Project(@('AlertName', 'Computer', 'TimeGenerated', 'AlertSeverity')).OrderBy('TimeGenerated', 'desc').Limit(100).Build()

Write-Host "Generated KQL Query:" -ForegroundColor Green
Write-Host $query -ForegroundColor Gray

# ============================================================================
# 4. QUERY OPTIMIZER EXAMPLE
# ============================================================================
Write-Host "`n=== QueryOptimizer Example ===" -ForegroundColor Yellow
$optimizer = New-QueryOptimizer

$unoptimized = @"
  SecurityEvent  
  |   where   Computer   ==   "server1"  
  |  project  Computer,  Account,  TimeGenerated  
"@

$optimized = $optimizer.OptimizeKQL($unoptimized)
Write-Host "Original query (with extra whitespace):" -ForegroundColor Gray
Write-Host $unoptimized -ForegroundColor DarkGray
Write-Host "`nOptimized query:" -ForegroundColor Green
Write-Host $optimized -ForegroundColor Gray

# ============================================================================
# 5. ENHANCED RISK SCORER EXAMPLE
# ============================================================================
Write-Host "`n=== EnhancedRiskScorer Example ===" -ForegroundColor Yellow
$enhancedScorer = New-EnhancedRiskScorer

# Create sample data
$alerts = @(
    @{ Severity = "High"; Category = "BehaviorAnomaly"; Timestamp = (Get-Date).AddHours(-1) }
    @{ Severity = "Critical"; Category = "Malware"; Timestamp = (Get-Date).AddMinutes(-30) }
    @{ Severity = "Medium"; Category = "UEBA"; Timestamp = (Get-Date).AddMinutes(-45) }
)

$entities = @(
    @{ Name = "user1@contoso.com"; Type = "Account"; Location = "US" }
    @{ Name = "device1.contoso.com"; Type = "Host"; Location = "EU" }
    @{ Name = "device2.contoso.com"; Type = "Host"; Location = "APAC" }
)

$threatIntel = @(
    @{ Type = "KerberosAttack" }
    @{ Type = "LateralMovement" }
)

$mlScore = $enhancedScorer.CalculateScore($alerts, $entities, $threatIntel)
Write-Host "ML-based risk score: $([Math]::Round($mlScore, 2))/100" -ForegroundColor Green

# ============================================================================
# 6. UNIFIED RISK SCORER EXAMPLE (MAIN FEATURE)
# ============================================================================
Write-Host "`n=== UnifiedRiskScorer Example ===" -ForegroundColor Yellow

# Create configuration
$config = @{
    UnifiedRiskScoring = @{
        Enabled = $true
        ScoringWeights = @{
            Microsoft = 0.35
            STAT = 0.35
            Custom = 0.30
        }
        DynamicWeightAdjustment = @{
            Enabled = $true
        }
        ConfidenceThresholds = @{
            High = 0.8
            Medium = 0.6
            Low = 0.4
        }
        ContextualAdjustments = @{
            AfterHoursBoost = 1.15
            CriticalAssetBoost = 1.25
        }
    }
}

# Create unified scorer
$unifiedScorer = New-UnifiedRiskScorer -Configuration $config
Write-Host "Created UnifiedRiskScorer with weights:" -ForegroundColor Gray
Write-Host "  Microsoft: 35%, STAT: 35%, Custom: 30%" -ForegroundColor Gray

# Create incident data
$incidentData = @{
    IncidentId = "INC-2024-001"
    IncidentArmId = "/subscriptions/12345/incidents/001"
    Severity = "High"
    CriticalAsset = $false
}

# Create enrichment results (simulating real enrichment)
$enrichmentResults = @{
    ProductResults = @{
        MDE = @{
            RiskScore = 75
            Alerts = 5
            Severity = "High"
        }
        MDC = @{
            RiskScore = 60
            SecureScore = 65
        }
        EntraID = @{
            RiskScore = 70
            RiskySignIns = 3
        }
        MCAS = @{
            RiskScore = 55
            CloudAppRisk = "Medium"
        }
        MDI = @{
            RiskScore = 80
            IdentityAlerts = 4
        }
        MDO = @{
            RiskScore = 50
            PhishingAttempts = 2
        }
    }
    RelatedAlerts = @(
        @{ Severity = "High"; Category = "BehaviorAnomaly"; Timestamp = (Get-Date).AddHours(-1) }
        @{ Severity = "Critical"; Category = "Malware"; Timestamp = (Get-Date).AddMinutes(-30) }
        @{ Severity = "High"; Category = "UEBA"; Timestamp = (Get-Date).AddMinutes(-45) }
        @{ Severity = "Medium"; Category = "ThreatIntel"; Timestamp = (Get-Date).AddHours(-2) }
        @{ Severity = "High"; Category = "NetworkAnomaly"; Timestamp = (Get-Date).AddMinutes(-20) }
    )
    ThreatIntel = @(
        @{ Type = "KerberosAttack"; Severity = "Critical" }
        @{ Type = "LateralMovement"; Severity = "High" }
        @{ Type = "PhishingCampaigns"; Severity = "Medium" }
    )
    UEBAInsights = @(
        @{ Type = "UnusualLogin"; Risk = "High" }
        @{ Type = "AnomalousAccess"; Risk = "Medium" }
        @{ Type = "ImpossibleTravel"; Risk = "High" }
        @{ Type = "SuspiciousFileAccess"; Risk = "Medium" }
        @{ Type = "PrivilegeEscalation"; Risk = "Critical" }
        @{ Type = "DataExfiltration"; Risk = "High" }
    )
    RiskScore = 65
    Correlations = @{
        CorrelationScore = 30
        EmailToEndpoint = @(@{})
        IdentityToEndpoint = @(@{}, @{})
        FullKillChain = @()
    }
}

# Calculate unified risk score
Write-Host "`nCalculating unified risk score..." -ForegroundColor Cyan
$riskAssessment = $unifiedScorer.CalculateUnifiedRiskScore($incidentData, $entities, $enrichmentResults)

# Display results
Write-Host "`n╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                  UNIFIED RISK ASSESSMENT RESULTS                  ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Write-Host "`nOverall Assessment:" -ForegroundColor Yellow
Write-Host "  Final Risk Score:  $($riskAssessment.FinalScore)/100" -ForegroundColor $(if ($riskAssessment.FinalScore -ge 70) { "Red" } else { "Yellow" })
Write-Host "  Severity:          $($riskAssessment.Severity)" -ForegroundColor $(switch ($riskAssessment.Severity) { "Critical" { "Red" } "High" { "Yellow" } default { "Green" } })
Write-Host "  Confidence:        $([Math]::Round($riskAssessment.Confidence * 100, 0))%" -ForegroundColor Green

Write-Host "`nComponent Breakdown:" -ForegroundColor Yellow
Write-Host "  Microsoft Native:  $($riskAssessment.ComponentScores.Microsoft) (weight: 35%)" -ForegroundColor Gray
Write-Host "  STAT Analytics:    $($riskAssessment.ComponentScores.STAT) (weight: 35%)" -ForegroundColor Gray
Write-Host "  Custom Scoring:    $($riskAssessment.ComponentScores.Custom) (weight: 30%)" -ForegroundColor Gray

Write-Host "`nExplainability:" -ForegroundColor Yellow
Write-Host "  Summary: $($riskAssessment.Explainability.Summary)" -ForegroundColor Gray
Write-Host "  Top Contributors:" -ForegroundColor Gray
foreach ($contributor in $riskAssessment.Explainability.TopContributors) {
    $weightedScore = [Math]::Round($contributor.Score * $contributor.Weight, 2)
    Write-Host "    - $($contributor.Component): Score=$($contributor.Score), Weighted=$weightedScore" -ForegroundColor DarkGray
}

Write-Host "`nRecommendations:" -ForegroundColor Yellow
foreach ($recommendation in $riskAssessment.Recommendations) {
    Write-Host "  • $recommendation" -ForegroundColor Gray
}

# ============================================================================
# 7. PROGRESSIVE ENRICHMENT EXAMPLE
# ============================================================================
Write-Host "`n=== ProgressiveEnrichmentManager Example ===" -ForegroundColor Yellow
$progressiveManager = New-ProgressiveEnrichmentManager

$entitiesForEnrichment = @(
    @{ Name = "entity1"; Type = "Account"; Priority = "Critical" }
    @{ Name = "entity2"; Type = "Host"; Priority = "High" }
    @{ Name = "entity3"; Type = "IP"; Priority = "Medium" }
    @{ Name = "entity4"; Type = "File"; Priority = "Low" }
    @{ Name = "entity5"; Type = "URL"; Priority = "Low" }
)

Write-Host "Executing progressive enrichment with 30 second time limit..." -ForegroundColor Gray
$progressiveConfig = @{
    TimeLimit = 30
    PriorityOrder = @("Critical", "High", "Medium", "Low")
}

$progressiveResults = $progressiveManager.ExecuteProgressive($entitiesForEnrichment, 30, $progressiveConfig)
Write-Host "Progressive enrichment completed in $([Math]::Round($progressiveResults.TimeElapsed, 2)) seconds" -ForegroundColor Green
Write-Host "  Completed: $($progressiveResults.Completed.Count)" -ForegroundColor Green
Write-Host "  Partial:   $($progressiveResults.Partial.Count)" -ForegroundColor Yellow
Write-Host "  Skipped:   $($progressiveResults.Skipped.Count)" -ForegroundColor DarkGray

# ============================================================================
# SUMMARY
# ============================================================================
Write-Host "`n╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                    EXAMPLE COMPLETED SUCCESSFULLY                 ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Green

Write-Host @"

Key Features Demonstrated:
✓ CacheManager - API response caching with TTL
✓ CircuitBreaker - Resilience pattern for API calls
✓ KQLBuilder - Dynamic KQL query construction
✓ QueryOptimizer - KQL query optimization
✓ EnhancedRiskScorer - ML-like feature extraction
✓ UnifiedRiskScorer - Multi-source risk scoring with explainability
✓ ProgressiveEnrichmentManager - Time-bounded enrichment

Next Steps:
1. Configure DefenderXSOAR with UnifiedRiskScoring enabled
2. Deploy to Azure Function App
3. Test with real incident data
4. Review risk assessments in Log Analytics

"@ -ForegroundColor Cyan
