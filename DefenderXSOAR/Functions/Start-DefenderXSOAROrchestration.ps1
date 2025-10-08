<#
.SYNOPSIS
    Start DefenderXSOAR Orchestration - Main Entry Point
.DESCRIPTION
    Main function to orchestrate DefenderXSOAR enrichment across all Defender products
.PARAMETER ConfigPath
    Path to DefenderXSOAR configuration file
.PARAMETER IncidentId
    Sentinel incident ID
.PARAMETER IncidentArmId
    Sentinel incident ARM resource ID (for comments)
.PARAMETER Entities
    Array of entities from the incident
.PARAMETER TenantId
    Azure AD Tenant ID
.PARAMETER Products
    Array of products to query (MDE, MDC, MCAS, MDI, MDO, EntraID)
.EXAMPLE
    .\Start-DefenderXSOAROrchestration.ps1 -ConfigPath ".\Config\DefenderXSOAR.json" -IncidentId "12345" -Entities $entities -TenantId "tenant-guid"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "..\Config\DefenderXSOAR.json",
    
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

# Set strict mode
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Import DefenderXSOAR Brain module
$ModulePath = Join-Path $PSScriptRoot "..\Modules"
Import-Module (Join-Path $ModulePath "DefenderXSOARBrain.psm1") -Force

# Banner
Write-Host @"
╔═══════════════════════════════════════════════════════════════════╗
║                      DefenderXSOAR                                ║
║              Comprehensive Security Orchestration                 ║
║                   Automation & Response                           ║
╚═══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Host "`nVersion: 1.0.0" -ForegroundColor Gray
Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host ""

try {
    # Resolve config path
    $configFullPath = if ([System.IO.Path]::IsPathRooted($ConfigPath)) {
        $ConfigPath
    } else {
        Join-Path $PSScriptRoot $ConfigPath | Resolve-Path | Select-Object -ExpandProperty Path
    }
    
    # Initialize DefenderXSOAR Brain
    Write-Host "Step 1: Initializing DefenderXSOAR Brain..." -ForegroundColor Cyan
    $initResult = Initialize-DefenderXSOARBrain -ConfigPath $configFullPath
    
    if (-not $initResult) {
        throw "Failed to initialize DefenderXSOAR Brain"
    }
    
    Write-Host "`nStep 2: Starting enrichment orchestration..." -ForegroundColor Cyan
    
    # Start enrichment
    $result = Start-DefenderXSOAREnrichment `
        -IncidentId $IncidentId `
        -IncidentArmId $IncidentArmId `
        -Entities $Entities `
        -TenantId $TenantId `
        -Products $Products
    
    if ($result.Success) {
        Write-Host "`n╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║                    ENRICHMENT SUMMARY                             ║" -ForegroundColor Green
        Write-Host "╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
        
        Write-Host "`nIncident ID: " -NoNewline -ForegroundColor Yellow
        Write-Host $IncidentId -ForegroundColor White
        
        Write-Host "Risk Score: " -NoNewline -ForegroundColor Yellow
        Write-Host "$($result.Results.RiskScore)/100" -ForegroundColor White
        
        Write-Host "Severity: " -NoNewline -ForegroundColor Yellow
        $severityColor = switch ($result.Results.Severity) {
            'Critical' { 'Red' }
            'High' { 'Red' }
            'Medium' { 'Yellow' }
            'Low' { 'Green' }
            default { 'Gray' }
        }
        Write-Host $result.Results.Severity -ForegroundColor $severityColor
        
        Write-Host "Decision: " -NoNewline -ForegroundColor Yellow
        Write-Host $result.Decision.Action -ForegroundColor Magenta
        
        Write-Host "Priority: " -NoNewline -ForegroundColor Yellow
        Write-Host $result.Decision.Priority -ForegroundColor Magenta
        
        Write-Host "`nEnrichment Details:" -ForegroundColor Yellow
        Write-Host "  Entities Analyzed: $($result.Results.Entities.Count)" -ForegroundColor White
        Write-Host "  Related Alerts: $($result.Results.RelatedAlerts.Count)" -ForegroundColor White
        Write-Host "  Threat Intel Indicators: $($result.Results.ThreatIntel.Count)" -ForegroundColor White
        Write-Host "  UEBA Insights: $($result.Results.UEBAInsights.Count)" -ForegroundColor White
        Write-Host "  Watchlist Matches: $($result.Results.WatchlistMatches.Count)" -ForegroundColor White
        
        if ($result.Results.Recommendations.Count -gt 0) {
            Write-Host "`nRecommendations:" -ForegroundColor Yellow
            foreach ($recommendation in $result.Results.Recommendations | Select-Object -First 5) {
                Write-Host "  • $recommendation" -ForegroundColor White
            }
            
            if ($result.Results.Recommendations.Count -gt 5) {
                Write-Host "  ... and $($result.Results.Recommendations.Count - 5) more" -ForegroundColor Gray
            }
        }
        
        if ($result.Decision.Reasoning.Count -gt 0) {
            Write-Host "`nDecision Reasoning:" -ForegroundColor Yellow
            foreach ($reason in $result.Decision.Reasoning) {
                Write-Host "  • $reason" -ForegroundColor White
            }
        }
        
        Write-Host "`n╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║                  ORCHESTRATION COMPLETED                          ║" -ForegroundColor Green
        Write-Host "╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
        
        return $result
    }
    else {
        Write-Host "`nEnrichment failed: $($result.Error)" -ForegroundColor Red
        return $result
    }
}
catch {
    Write-Host "`n╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║                        ERROR                                       ║" -ForegroundColor Red
    Write-Host "╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    
    Write-Host "`nError: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack Trace:" -ForegroundColor Gray
    Write-Host $_.ScriptStackTrace -ForegroundColor Gray
    
    throw
}
