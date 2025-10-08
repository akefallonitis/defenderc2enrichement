<#
.SYNOPSIS
    Microsoft 365 Defender Alert Polling Trigger for DefenderXSOAR
.DESCRIPTION
    Polls Microsoft 365 Defender for new high-priority alerts and triggers enrichment
.PARAMETER ConfigPath
    Path to DefenderXSOAR configuration file
.PARAMETER PollingIntervalMinutes
    Polling interval in minutes (default: 5)
.PARAMETER MinimumSeverity
    Minimum alert severity to process (default: Medium)
.EXAMPLE
    .\DefenderPolling.ps1 -ConfigPath "..\Config\DefenderXSOAR.json" -PollingIntervalMinutes 5
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "..\Config\DefenderXSOAR.json",
    
    [Parameter(Mandatory = $false)]
    [int]$PollingIntervalMinutes = 5,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('Informational', 'Low', 'Medium', 'High')]
    [string]$MinimumSeverity = 'Medium',
    
    [Parameter(Mandatory = $false)]
    [switch]$RunOnce
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Import modules
$ModulePath = Join-Path $PSScriptRoot "..\Modules"
Import-Module (Join-Path $ModulePath "DefenderXSOARBrain.psm1") -Force
Import-Module (Join-Path $ModulePath "Common\AuthenticationHelper.psm1") -Force

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║         DefenderXSOAR - Defender Alert Polling Service          ║
║                    Continuous Monitoring Mode                    ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Host "`nConfiguration:" -ForegroundColor Yellow
Write-Host "  Config Path: $ConfigPath"
Write-Host "  Polling Interval: $PollingIntervalMinutes minutes"
Write-Host "  Minimum Severity: $MinimumSeverity"
Write-Host "  Mode: $(if ($RunOnce) { 'Single Run' } else { 'Continuous' })"

# Load configuration
$configFullPath = Resolve-Path $ConfigPath
Write-Host "`nLoading configuration from: $configFullPath"
$config = Get-Content $configFullPath -Raw | ConvertFrom-Json

# Initialize tracking file for processed alerts
$trackingFile = Join-Path $PSScriptRoot "processed_alerts.json"
if (-not (Test-Path $trackingFile)) {
    @{
        ProcessedAlerts = @()
        LastCheck = (Get-Date).ToString("o")
    } | ConvertTo-Json | Out-File $trackingFile
}

function Get-ProcessedAlerts {
    $tracking = Get-Content $trackingFile -Raw | ConvertFrom-Json
    return $tracking.ProcessedAlerts
}

function Add-ProcessedAlert {
    param([string]$AlertId)
    
    $tracking = Get-Content $trackingFile -Raw | ConvertFrom-Json
    $tracking.ProcessedAlerts += $AlertId
    $tracking.LastCheck = (Get-Date).ToString("o")
    
    # Keep only last 1000 alerts to prevent file from growing indefinitely
    if ($tracking.ProcessedAlerts.Count -gt 1000) {
        $tracking.ProcessedAlerts = $tracking.ProcessedAlerts[-1000..-1]
    }
    
    $tracking | ConvertTo-Json | Out-File $trackingFile
}

function Get-NewDefenderAlerts {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$MinimumSeverity
    )
    
    try {
        # Get access token for Microsoft 365 Defender
        $token = Get-AccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -Resource "https://api.security.microsoft.com"
        
        $headers = @{
            "Authorization" = "Bearer $token"
            "Content-Type" = "application/json"
        }
        
        # Query for recent high-priority alerts
        $timeFilter = (Get-Date).AddMinutes(-($PollingIntervalMinutes * 2)).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        $severityFilter = switch ($MinimumSeverity) {
            'High' { "severity eq 'High'" }
            'Medium' { "(severity eq 'High' or severity eq 'Medium')" }
            'Low' { "(severity eq 'High' or severity eq 'Medium' or severity eq 'Low')" }
            default { "severity ne 'Informational'" }
        }
        
        $filter = "createdDateTime ge $timeFilter and $severityFilter"
        $uri = "https://api.security.microsoft.com/api/alerts?`$filter=$filter&`$top=100"
        
        Write-Verbose "Querying alerts with filter: $filter"
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        
        return $response.value
    }
    catch {
        Write-Error "Failed to query Defender alerts: $_"
        return @()
    }
}

function Process-DefenderAlert {
    param(
        $Alert,
        $TenantConfig
    )
    
    try {
        Write-Host "`n[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Processing alert: $($Alert.id)" -ForegroundColor Yellow
        Write-Host "  Title: $($Alert.title)"
        Write-Host "  Severity: $($Alert.severity)"
        Write-Host "  Category: $($Alert.category)"
        
        # Create synthetic incident from alert
        $incidentId = "MDE-$($Alert.id.Substring(0, 8))"
        
        # Extract entities from alert
        $entities = @()
        
        if ($Alert.machineId) {
            $entities += @{
                Type = 'Device'
                DeviceId = $Alert.machineId
            }
        }
        
        if ($Alert.userPrincipalName) {
            $entities += @{
                Type = 'User'
                UserPrincipalName = $Alert.userPrincipalName
            }
        }
        
        if ($Alert.sha256) {
            $entities += @{
                Type = 'File'
                FileHash = @{ SHA256 = $Alert.sha256 }
            }
        }
        
        if ($Alert.remoteIp) {
            $entities += @{
                Type = 'IP'
                Address = $Alert.remoteIp
            }
        }
        
        Write-Host "  Extracted entities: $($entities.Count)"
        
        # Start DefenderXSOAR enrichment
        $enrichmentResult = Start-DefenderXSOAREnrichment `
            -IncidentId $incidentId `
            -Entities $entities `
            -TenantId $TenantConfig.TenantId `
            -Products @('MDE', 'EntraID')
        
        if ($enrichmentResult.Success) {
            Write-Host "  ✓ Enrichment completed" -ForegroundColor Green
            Write-Host "    Risk Score: $($enrichmentResult.RiskScore)"
            Write-Host "    Decision: $($enrichmentResult.Decision.Action)"
            
            # Mark alert as processed
            Add-ProcessedAlert -AlertId $Alert.id
        }
        else {
            Write-Host "  ✗ Enrichment failed: $($enrichmentResult.Error)" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "  ✗ Error processing alert: $_" -ForegroundColor Red
    }
}

# Main polling loop
$iteration = 0
do {
    $iteration++
    Write-Host "`n═══════════════════════════════════════════════════════════════════"
    Write-Host "Polling iteration #$iteration - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════"
    
    try {
        # Initialize DefenderXSOAR Brain
        $initResult = Initialize-DefenderXSOARBrain -ConfigPath $configFullPath
        
        if (-not $initResult) {
            Write-Host "Failed to initialize DefenderXSOAR Brain" -ForegroundColor Red
            continue
        }
        
        # Get processed alerts list
        $processedAlerts = Get-ProcessedAlerts
        Write-Host "Previously processed alerts: $($processedAlerts.Count)"
        
        # Poll each tenant
        foreach ($tenant in $config.Tenants) {
            if (-not $tenant.Enabled) {
                continue
            }
            
            Write-Host "`nChecking tenant: $($tenant.TenantName)" -ForegroundColor Yellow
            
            # Get new alerts
            $alerts = Get-NewDefenderAlerts `
                -TenantId $tenant.TenantId `
                -ClientId $tenant.ClientId `
                -ClientSecret $tenant.ClientSecret `
                -MinimumSeverity $MinimumSeverity
            
            Write-Host "Found $($alerts.Count) total alerts"
            
            # Filter out already processed alerts
            $newAlerts = $alerts | Where-Object { $processedAlerts -notcontains $_.id }
            Write-Host "New alerts to process: $($newAlerts.Count)" -ForegroundColor Green
            
            # Process each new alert
            foreach ($alert in $newAlerts) {
                Process-DefenderAlert -Alert $alert -TenantConfig $tenant
            }
        }
        
        Write-Host "`nIteration completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "`nError in polling iteration: $_" -ForegroundColor Red
        Write-Host $_.ScriptStackTrace
    }
    
    # Sleep before next iteration (unless RunOnce)
    if (-not $RunOnce) {
        Write-Host "`nSleeping for $PollingIntervalMinutes minutes..." -ForegroundColor Gray
        Start-Sleep -Seconds ($PollingIntervalMinutes * 60)
    }
    
} while (-not $RunOnce)

Write-Host "`n╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║              Defender Polling Service Completed                 ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
