# DefenderXSOAR - Upgrade Guide

This guide covers procedures for upgrading DefenderXSOAR deployments to newer versions.

## Table of Contents

- [Overview](#overview)
- [Pre-Upgrade Checklist](#pre-upgrade-checklist)
- [Upgrade Procedures](#upgrade-procedures)
- [Version-Specific Upgrades](#version-specific-upgrades)
- [Rollback Procedures](#rollback-procedures)
- [Post-Upgrade Validation](#post-upgrade-validation)

## Overview

### Versioning Strategy

DefenderXSOAR follows semantic versioning (MAJOR.MINOR.PATCH):
- **MAJOR**: Breaking changes, architectural changes
- **MINOR**: New features, backward-compatible
- **PATCH**: Bug fixes, security patches

### Supported Upgrade Paths

| From Version | To Version | Direct Upgrade | Notes |
|--------------|------------|----------------|-------|
| 1.x | 2.0 | ✅ Yes | See V2 upgrade guide |
| 2.0 | 2.x | ✅ Yes | Simple update |
| 1.x | 2.x | ⚠️ Via 2.0 | Upgrade to 2.0 first |

### Upgrade Types

1. **In-Place Upgrade** (Recommended)
   - Updates existing deployment
   - Minimal downtime (5-10 minutes)
   - Preserves configuration
   - Risk: Minor service interruption

2. **Blue-Green Upgrade**
   - Deploys new environment alongside old
   - Zero downtime
   - Easy rollback
   - Cost: 2x resources temporarily

3. **Fresh Deployment**
   - New deployment from scratch
   - Clean slate
   - Requires reconfiguration
   - Risk: Data/config loss

## Pre-Upgrade Checklist

### 1. Review Release Notes

Check the release notes for:
- [ ] Breaking changes
- [ ] New prerequisites
- [ ] Configuration changes
- [ ] API permission changes
- [ ] Deprecated features

### 2. Backup Current Configuration

```powershell
# Export current configuration from Key Vault
$kvName = "defenderxsoar-kv-12345"
$config = Get-AzKeyVaultSecret -VaultName $kvName -Name "DefenderXSOAR-Configuration" -AsPlainText
$config | Out-File -FilePath ".\backup\config-$(Get-Date -Format 'yyyyMMdd').json"

# Export Function App settings
$appSettings = (Get-AzWebApp -ResourceGroupName "DefenderXSOAR-RG" -Name "defenderxsoar-func").SiteConfig.AppSettings
$appSettings | ConvertTo-Json | Out-File -FilePath ".\backup\appsettings-$(Get-Date -Format 'yyyyMMdd').json"

# Export ARM template parameters
$deployment = Get-AzResourceGroupDeployment -ResourceGroupName "DefenderXSOAR-RG" | Select-Object -First 1
$deployment.Parameters | ConvertTo-Json | Out-File -FilePath ".\backup\parameters-$(Get-Date -Format 'yyyyMMdd').json"
```

### 3. Document Current State

```powershell
# Get current version
$currentVersion = (Get-AzWebApp -ResourceGroupName "DefenderXSOAR-RG" -Name "defenderxsoar-func").SiteConfig.AppSettings | 
                  Where-Object { $_.Name -eq "DefenderXSOAR_ConfigVersion" } | 
                  Select-Object -ExpandProperty Value

Write-Host "Current Version: $currentVersion"

# Get deployment details
$app = Get-AzWebApp -ResourceGroupName "DefenderXSOAR-RG" -Name "defenderxsoar-func"
@{
    Version = $currentVersion
    SKU = $app.AppServicePlanId -split '/' | Select-Object -Last 1
    Location = $app.Location
    Runtime = ($app.SiteConfig.AppSettings | Where-Object { $_.Name -eq "FUNCTIONS_WORKER_RUNTIME_VERSION" }).Value
} | ConvertTo-Json | Out-File -FilePath ".\backup\current-state-$(Get-Date -Format 'yyyyMMdd').json"
```

### 4. Test in Non-Production

If possible:
- [ ] Deploy upgrade to dev/test environment first
- [ ] Run test scenarios
- [ ] Verify all workers function correctly
- [ ] Check performance metrics
- [ ] Validate Log Analytics ingestion

### 5. Schedule Maintenance Window

- [ ] Identify low-traffic period
- [ ] Notify stakeholders
- [ ] Estimate downtime (typically 10-15 minutes)
- [ ] Plan rollback window if needed

### 6. Verify Prerequisites

```powershell
# Check Azure PowerShell modules
$requiredModules = @{
    'Az.Accounts' = '2.10.0'
    'Az.Resources' = '6.0.0'
    'Az.Websites' = '3.0.0'
    'Az.KeyVault' = '4.9.0'
}

foreach ($module in $requiredModules.Keys) {
    $installed = Get-Module -ListAvailable -Name $module | Sort-Object Version -Descending | Select-Object -First 1
    if ($installed.Version -lt $requiredModules[$module]) {
        Write-Warning "$module needs update. Current: $($installed.Version), Required: $($requiredModules[$module])"
    } else {
        Write-Host "✓ $module OK" -ForegroundColor Green
    }
}
```

## Upgrade Procedures

### Method 1: In-Place Upgrade (Recommended)

#### Step 1: Stop Function App

```powershell
# Stop Function App to prevent processing during upgrade
Stop-AzWebApp -ResourceGroupName "DefenderXSOAR-RG" -Name "defenderxsoar-func"
Write-Host "Function App stopped at $(Get-Date)" -ForegroundColor Yellow
```

#### Step 2: Update ARM Template

```powershell
# Deploy updated ARM template
New-AzResourceGroupDeployment `
    -ResourceGroupName "DefenderXSOAR-RG" `
    -TemplateFile ".\defenderxsoar-deploy.json" `
    -TemplateParameterFile ".\parameters.json" `
    -Mode Incremental `
    -Verbose
```

#### Step 3: Update Function Code

```powershell
# Package new code
$sourceDir = ".\DefenderXSOAR"
$packagePath = ".\DefenderXSOAR-$(Get-Date -Format 'yyyyMMdd').zip"
Compress-Archive -Path "$sourceDir\*" -DestinationPath $packagePath -Force

# Deploy to Function App
Publish-AzWebApp `
    -ResourceGroupName "DefenderXSOAR-RG" `
    -Name "defenderxsoar-func" `
    -ArchivePath $packagePath `
    -Force
```

#### Step 4: Update Configuration

```powershell
# Run configuration update script
.\Configure-DefenderXSOAR.ps1 `
    -FunctionAppName "defenderxsoar-func" `
    -ResourceGroupName "DefenderXSOAR-RG" `
    -ConfigFilePath ".\Config\DefenderXSOAR.json"
```

#### Step 5: Update API Permissions (if needed)

```powershell
# Check release notes for new permissions
.\Grant-DefenderXSOARPermissions.ps1 `
    -FunctionAppName "defenderxsoar-func" `
    -ResourceGroupName "DefenderXSOAR-RG" `
    -TenantId "your-tenant-id"
```

#### Step 6: Start Function App

```powershell
# Start Function App
Start-AzWebApp -ResourceGroupName "DefenderXSOAR-RG" -Name "defenderxsoar-func"
Write-Host "Function App started at $(Get-Date)" -ForegroundColor Green

# Wait for warm-up
Start-Sleep -Seconds 30
```

#### Step 7: Validate Upgrade

```powershell
# Run validation tests
.\Test-DefenderXSOAR.ps1 `
    -FunctionAppName "defenderxsoar-func" `
    -ResourceGroupName "DefenderXSOAR-RG"
```

### Method 2: Blue-Green Upgrade

#### Step 1: Deploy New Environment

```powershell
# Deploy to new resource group
$newRgName = "DefenderXSOAR-V2-RG"
New-AzResourceGroup -Name $newRgName -Location "eastus"

New-AzResourceGroupDeployment `
    -ResourceGroupName $newRgName `
    -TemplateFile ".\defenderxsoar-deploy.json" `
    -DefenderXSOARName "DefenderXSOAR-V2" `
    -SentinelWorkspaceName "existing-sentinel-workspace" `
    -SentinelResourceGroupName "Sentinel-RG"
```

#### Step 2: Configure New Environment

```powershell
# Copy configuration from old environment
$oldKvName = "defenderxsoar-kv-old"
$newKvName = "defenderxsoar-kv-new"

$secrets = Get-AzKeyVaultSecret -VaultName $oldKvName
foreach ($secret in $secrets) {
    $secretValue = Get-AzKeyVaultSecret -VaultName $oldKvName -Name $secret.Name -AsPlainText
    Set-AzKeyVaultSecret -VaultName $newKvName -Name $secret.Name -SecretValue (ConvertTo-SecureString $secretValue -AsPlainText -Force)
}

# Configure new deployment
.\Configure-DefenderXSOAR.ps1 `
    -FunctionAppName "defenderxsoar-v2-func" `
    -ResourceGroupName $newRgName `
    -ConfigFilePath ".\Config\DefenderXSOAR.json"
```

#### Step 3: Test New Environment

```powershell
# Run comprehensive tests
.\Test-DefenderXSOAR.ps1 `
    -FunctionAppName "defenderxsoar-v2-func" `
    -ResourceGroupName $newRgName

# Test with sample incidents
# Verify all workers functioning
# Check Log Analytics ingestion
```

#### Step 4: Switch Traffic

```powershell
# Update Sentinel automation rules to point to new Function App
$newFunctionUrl = "https://defenderxsoar-v2-func.azurewebsites.net/api/Start-DefenderXSOAROrchestration"

# Update Logic Apps
# Update webhooks
# Update automation rules
```

#### Step 5: Monitor New Environment

- Watch Application Insights for errors
- Verify incident processing
- Check performance metrics
- Monitor for 24-48 hours

#### Step 6: Decommission Old Environment

```powershell
# After successful validation (wait 1 week)
Remove-AzResourceGroup -Name "DefenderXSOAR-RG" -Force
```

### Method 3: Automated Upgrade Script

```powershell
# Upgrade-DefenderXSOAR.ps1
<#
.SYNOPSIS
    Automated upgrade script for DefenderXSOAR
.PARAMETER Version
    Target version to upgrade to
.PARAMETER BackupBeforeUpgrade
    Create backup before upgrading (default: $true)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Version,
    
    [Parameter(Mandatory = $false)]
    [bool]$BackupBeforeUpgrade = $true,
    
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $true)]
    [string]$FunctionAppName
)

Write-Host "DefenderXSOAR Upgrade Script" -ForegroundColor Cyan
Write-Host "Target Version: $Version" -ForegroundColor Yellow

# Backup configuration
if ($BackupBeforeUpgrade) {
    Write-Host "Creating backup..." -ForegroundColor Yellow
    $backupDir = ".\backup\$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    
    # Backup Key Vault secrets
    $kvName = (Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName).SiteConfig.AppSettings | 
              Where-Object { $_.Name -eq "KeyVaultName" } | 
              Select-Object -ExpandProperty Value
    
    $config = Get-AzKeyVaultSecret -VaultName $kvName -Name "DefenderXSOAR-Configuration" -AsPlainText
    $config | Out-File -FilePath "$backupDir\configuration.json"
    
    Write-Host "✓ Backup completed: $backupDir" -ForegroundColor Green
}

# Stop Function App
Write-Host "Stopping Function App..." -ForegroundColor Yellow
Stop-AzWebApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName

# Download new version
Write-Host "Downloading version $Version..." -ForegroundColor Yellow
$releaseUrl = "https://github.com/akefallonitis/defenderc2enrichement/releases/download/v$Version/DefenderXSOAR-$Version.zip"
$packagePath = ".\DefenderXSOAR-$Version.zip"
Invoke-WebRequest -Uri $releaseUrl -OutFile $packagePath

# Deploy new version
Write-Host "Deploying new version..." -ForegroundColor Yellow
Publish-AzWebApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName -ArchivePath $packagePath -Force

# Start Function App
Write-Host "Starting Function App..." -ForegroundColor Yellow
Start-AzWebApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName

# Validate
Write-Host "Validating upgrade..." -ForegroundColor Yellow
Start-Sleep -Seconds 30
.\Test-DefenderXSOAR.ps1 -FunctionAppName $FunctionAppName -ResourceGroupName $ResourceGroupName

Write-Host "✓ Upgrade completed successfully!" -ForegroundColor Green
```

## Version-Specific Upgrades

### Upgrading from V1.x to V2.0

**Major Changes**:
- New entity types (Account, Host, Mailbox, etc.)
- Enhanced playbook system
- Custom table schemas updated
- Configuration structure changes

**Steps**:

1. **Update configuration format**
   ```powershell
   # V1 configuration
   $v1Config = Get-Content ".\Config\DefenderXSOAR-V1.json" | ConvertFrom-Json
   
   # Convert to V2 format
   $v2Config = @{
       Version = "2.0.0"
       Tenants = $v1Config.Tenants
       # Add new sections
       Playbooks = @{
           AutoExecute = $false
           DefaultPlaybooks = @{
               MDE = @("DeviceCompromiseDetection", "MalwareAnalysis")
               # ... other products
           }
       }
   }
   
   $v2Config | ConvertTo-Json -Depth 10 | Out-File ".\Config\DefenderXSOAR-V2.json"
   ```

2. **Migrate custom tables**
   - New tables created automatically
   - Old tables remain for historical data
   - No data loss

3. **Update API permissions**
   - No new permissions required
   - Existing permissions sufficient

### Upgrading from V2.0 to V2.x

Minor version updates are straightforward:

```powershell
# Simple code update
Publish-AzWebApp `
    -ResourceGroupName "DefenderXSOAR-RG" `
    -Name "defenderxsoar-func" `
    -ArchivePath ".\DefenderXSOAR-2.x.zip" `
    -Force
```

## Rollback Procedures

### When to Rollback

- Critical bugs discovered
- Performance degradation
- Data ingestion failures
- API compatibility issues

### Rollback Steps

#### Option 1: Redeploy Previous Version

```powershell
# Use backup package
Publish-AzWebApp `
    -ResourceGroupName "DefenderXSOAR-RG" `
    -Name "defenderxsoar-func" `
    -ArchivePath ".\backup\DefenderXSOAR-previous.zip" `
    -Force

# Restore configuration
$kvName = "defenderxsoar-kv-12345"
$backupConfig = Get-Content ".\backup\config-20240101.json" -Raw
$secureConfig = ConvertTo-SecureString -String $backupConfig -AsPlainText -Force
Set-AzKeyVaultSecret -VaultName $kvName -Name "DefenderXSOAR-Configuration" -SecretValue $secureConfig
```

#### Option 2: Restore from Deployment Slot

```powershell
# If using deployment slots
Switch-AzWebAppSlot `
    -ResourceGroupName "DefenderXSOAR-RG" `
    -Name "defenderxsoar-func" `
    -SourceSlotName "staging" `
    -DestinationSlotName "production"
```

#### Option 3: Restore Function App from Backup

```powershell
# Azure creates automatic backups
Restore-AzDeletedWebApp `
    -ResourceGroupName "DefenderXSOAR-RG" `
    -Name "defenderxsoar-func" `
    -TargetResourceGroupName "DefenderXSOAR-RG" `
    -TargetName "defenderxsoar-func-restored" `
    -TargetAppServicePlanName "defenderxsoar-plan"
```

### Rollback Validation

After rollback:

1. **Verify version**
   ```powershell
   $version = (Get-AzWebApp -ResourceGroupName "DefenderXSOAR-RG" -Name "defenderxsoar-func").SiteConfig.AppSettings | 
              Where-Object { $_.Name -eq "DefenderXSOAR_ConfigVersion" } | 
              Select-Object -ExpandProperty Value
   Write-Host "Current Version: $version"
   ```

2. **Test functionality**
   ```powershell
   .\Test-DefenderXSOAR.ps1 -FunctionAppName "defenderxsoar-func" -ResourceGroupName "DefenderXSOAR-RG"
   ```

3. **Monitor logs**
   - Check Application Insights for errors
   - Verify incident processing resumes

## Post-Upgrade Validation

### Automated Tests

```powershell
# Run test suite
.\Test-DefenderXSOAR.ps1 `
    -FunctionAppName "defenderxsoar-func" `
    -ResourceGroupName "DefenderXSOAR-RG"

# Expected: All tests pass
```

### Manual Validation

1. **Process test incident**
   ```powershell
   $testIncident = @{
       IncidentId = "UPGRADE-TEST-001"
       Entities = @(
           @{ Type = "Account"; Name = "test@domain.com" }
       )
       TenantId = "your-tenant-id"
   }
   
   # Trigger enrichment
   # Monitor in Application Insights
   # Verify results in Log Analytics
   ```

2. **Check all workers**
   ```kql
   // In Application Insights
   traces
   | where timestamp > ago(1h)
   | where message contains "Worker"
   | summarize count() by tostring(customDimensions.Worker)
   ```

3. **Verify Log Analytics ingestion**
   ```kql
   DefenderXSOAR_CL
   | where TimeGenerated > ago(1h)
   | summarize count() by bin(TimeGenerated, 5m)
   | render timechart
   ```

4. **Review performance**
   ```kql
   requests
   | where timestamp > ago(1h)
   | summarize 
       AvgDuration = avg(duration),
       P95 = percentile(duration, 95)
   ```

### Monitoring Period

- **Day 1**: Intensive monitoring, check every hour
- **Day 2-7**: Regular monitoring, check daily
- **Week 2+**: Normal monitoring cadence

### Success Criteria

✅ **Upgrade Successful If**:
- All validation tests pass
- No increase in error rate
- Performance within acceptable range
- All product workers functioning
- Log Analytics ingestion working
- No rollback required after 1 week

❌ **Consider Rollback If**:
- Error rate > 5%
- Performance degradation > 50%
- Critical functionality broken
- Data ingestion failures

## Best Practices

1. **Always test in non-production first**
2. **Create backups before upgrading**
3. **Read release notes thoroughly**
4. **Schedule during low-traffic periods**
5. **Have rollback plan ready**
6. **Monitor intensively post-upgrade**
7. **Keep stakeholders informed**
8. **Document any issues encountered**

## Support

For upgrade issues:
- Review [Troubleshooting Guide](Troubleshooting.md)
- Check GitHub releases for known issues
- Open GitHub issue with upgrade details
- Include version numbers (from and to)

## Upgrade History Tracking

Keep a log of upgrades:

```powershell
# Upgrade log template
$upgradeLog = @{
    Date = Get-Date
    FromVersion = "1.0.0"
    ToVersion = "2.0.0"
    Method = "In-Place"
    DowntimeMinutes = 15
    Issues = @()
    RollbackRequired = $false
    PerformedBy = $env:USERNAME
}

$upgradeLog | ConvertTo-Json | Add-Content -Path ".\upgrade-history.json"
```
