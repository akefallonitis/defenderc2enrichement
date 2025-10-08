<#
.SYNOPSIS
    Invoke DefenderXSOAR Analysis - Flexible Analysis Function
.DESCRIPTION
    Flexible function for triggering DefenderXSOAR enrichment with various input methods
.PARAMETER ConfigPath
    Path to DefenderXSOAR configuration file
.PARAMETER IncidentId
    Sentinel incident ID or custom identifier
.PARAMETER IncidentArmId
    Sentinel incident ARM resource ID (optional)
.PARAMETER Entity
    Single entity to analyze
.PARAMETER Entities
    Array of entities to analyze
.PARAMETER EntityType
    Type of entity (if providing simple values)
.PARAMETER EntityValue
    Value of entity (IP, User, Device name, etc.)
.PARAMETER TenantId
    Azure AD Tenant ID
.PARAMETER Products
    Array of products to query (default: all)
.PARAMETER OutputFormat
    Output format: JSON, Summary, Full (default: Summary)
.EXAMPLE
    # Analyze a single IP address
    Invoke-DefenderXSOARAnalysis -EntityType 'IP' -EntityValue '1.2.3.4' -TenantId $tenantId
.EXAMPLE
    # Analyze multiple entities
    $entities = @(
        @{ Type = 'User'; UserPrincipalName = 'user@domain.com' },
        @{ Type = 'Device'; HostName = 'DESKTOP-001' }
    )
    Invoke-DefenderXSOARAnalysis -Entities $entities -TenantId $tenantId
.EXAMPLE
    # Analyze with specific products only
    Invoke-DefenderXSOARAnalysis -EntityType 'User' -EntityValue 'user@domain.com' -TenantId $tenantId -Products @('EntraID', 'MDO')
#>

[CmdletBinding(DefaultParameterSetName = 'MultipleEntities')]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "..\Config\DefenderXSOAR.json",
    
    [Parameter(Mandatory = $false)]
    [string]$IncidentId,
    
    [Parameter(Mandatory = $false)]
    [string]$IncidentArmId,
    
    [Parameter(Mandatory = $true, ParameterSetName = 'SingleEntity')]
    [ValidateSet('User', 'Account', 'Device', 'Host', 'IP', 'File', 'URL', 'DNS', 'Process', 'MailMessage', 'Mailbox', 'CloudApp')]
    [string]$EntityType,
    
    [Parameter(Mandatory = $true, ParameterSetName = 'SingleEntity')]
    [string]$EntityValue,
    
    [Parameter(Mandatory = $true, ParameterSetName = 'MultipleEntities')]
    [array]$Entities,
    
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('MDE', 'MDC', 'MCAS', 'MDI', 'MDO', 'EntraID')]
    [string[]]$Products = @('MDE', 'MDC', 'MCAS', 'MDI', 'MDO', 'EntraID'),
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('JSON', 'Summary', 'Full')]
    [string]$OutputFormat = 'Summary'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Import DefenderXSOAR Brain module
$ModulePath = Join-Path $PSScriptRoot "..\Modules"
Import-Module (Join-Path $ModulePath "DefenderXSOARBrain.psm1") -Force

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              DefenderXSOAR - Flexible Analysis                   ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

try {
    # Resolve config path
    $configFullPath = Resolve-Path $ConfigPath -ErrorAction Stop
    
    # Build entities array based on input
    if ($PSCmdlet.ParameterSetName -eq 'SingleEntity') {
        Write-Host "`nAnalyzing single entity:" -ForegroundColor Yellow
        Write-Host "  Type: $EntityType"
        Write-Host "  Value: $EntityValue"
        
        # Create entity object based on type
        $entityObj = @{
            Type = $EntityType
        }
        
        switch ($EntityType) {
            'User' { $entityObj['UserPrincipalName'] = $EntityValue }
            'Account' { $entityObj['UPN'] = $EntityValue }
            'Device' { $entityObj['HostName'] = $EntityValue }
            'Host' { $entityObj['Hostname'] = $EntityValue }
            'IP' { $entityObj['Address'] = $EntityValue }
            'File' { $entityObj['FileHash'] = @{ SHA256 = $EntityValue } }
            'URL' { $entityObj['URL'] = $EntityValue }
            'DNS' { $entityObj['DomainName'] = $EntityValue }
            'Mailbox' { $entityObj['UPN'] = $EntityValue }
        }
        
        $Entities = @($entityObj)
    }
    else {
        Write-Host "`nAnalyzing multiple entities: $($Entities.Count)" -ForegroundColor Yellow
    }
    
    # Generate incident ID if not provided
    if (-not $IncidentId) {
        $IncidentId = "ANALYSIS-$(Get-Date -Format 'yyyyMMdd-HHmmss')-$([guid]::NewGuid().ToString().Substring(0, 8))"
    }
    
    Write-Host "Incident ID: $IncidentId"
    Write-Host "Products: $($Products -join ', ')"
    
    # Initialize DefenderXSOAR Brain
    Write-Host "`nInitializing DefenderXSOAR..." -ForegroundColor Cyan
    $initResult = Initialize-DefenderXSOARBrain -ConfigPath $configFullPath
    
    if (-not $initResult) {
        throw "Failed to initialize DefenderXSOAR Brain"
    }
    
    # Start enrichment
    Write-Host "Starting enrichment analysis..." -ForegroundColor Cyan
    $result = Start-DefenderXSOAREnrichment `
        -IncidentId $IncidentId `
        -IncidentArmId $IncidentArmId `
        -Entities $Entities `
        -TenantId $TenantId `
        -Products $Products
    
    # Format output based on requested format
    Write-Host "`n╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                    Analysis Completed                            ║" -ForegroundColor Green
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    
    switch ($OutputFormat) {
        'JSON' {
            Write-Host "`nJSON Output:" -ForegroundColor Yellow
            $result | ConvertTo-Json -Depth 10
        }
        'Summary' {
            Write-Host "`n=== Analysis Summary ===" -ForegroundColor Cyan
            Write-Host "Risk Score: $($result.RiskScore)/100" -ForegroundColor $(if ($result.RiskScore -gt 70) { 'Red' } elseif ($result.RiskScore -gt 40) { 'Yellow' } else { 'Green' })
            Write-Host "Severity: $($result.Severity)"
            Write-Host "Entities Analyzed: $($result.Entities.Count)"
            Write-Host "Related Alerts: $($result.RelatedAlerts.Count)"
            Write-Host "Threat Intel Matches: $($result.ThreatIntel.Count)"
            
            if ($result.Decision) {
                Write-Host "`n=== Recommended Action ===" -ForegroundColor Cyan
                Write-Host "Action: $($result.Decision.Action)"
                Write-Host "Priority: $($result.Decision.Priority)"
                Write-Host "Reasoning: $($result.Decision.Reasoning)"
            }
            
            if ($result.Recommendations.Count -gt 0) {
                Write-Host "`n=== Recommendations ===" -ForegroundColor Cyan
                foreach ($rec in $result.Recommendations) {
                    Write-Host "  • $rec"
                }
            }
        }
        'Full' {
            Write-Host "`nFull Analysis Results:" -ForegroundColor Yellow
            $result | Format-List *
        }
    }
    
    return $result
}
catch {
    Write-Host "`n╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║                         ERROR                                    ║" -ForegroundColor Red
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host $_.ScriptStackTrace
    
    return @{
        Success = $false
        Error = $_.Exception.Message
    }
}
