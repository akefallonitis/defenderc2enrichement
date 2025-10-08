# DefenderXSOAR - Troubleshooting Guide

This guide provides solutions to common issues encountered during deployment and operation of DefenderXSOAR.

## Table of Contents

- [Deployment Issues](#deployment-issues)
- [Authentication Issues](#authentication-issues)
- [API Connection Issues](#api-connection-issues)
- [Performance Issues](#performance-issues)
- [Data Ingestion Issues](#data-ingestion-issues)
- [Configuration Issues](#configuration-issues)
- [Monitoring and Logging](#monitoring-and-logging)

## Deployment Issues

### Issue: ARM Template Deployment Fails

**Symptoms**:
- Deployment fails in Azure Portal
- Error message: "Resource already exists" or "Quota exceeded"

**Causes & Solutions**:

1. **Resource name conflict**
   ```
   Error: Storage account name 'defxsoar123' is already taken
   ```
   - **Solution**: Use a different DefenderXSOAR name parameter
   - **Solution**: Deploy to a different resource group
   - **Workaround**: Add random suffix: `DefenderXSOAR-$(Get-Random)`

2. **Subscription quota exceeded**
   ```
   Error: Operation results in exceeding quota for resource type 'Storage Accounts'
   ```
   - **Solution**: Delete unused storage accounts
   - **Solution**: Request quota increase in Azure Portal
   - **Location**: Support → Service and subscription limits → Request increase

3. **Insufficient permissions**
   ```
   Error: Authorization failed for template resource
   ```
   - **Solution**: Verify you have Contributor role on subscription
   - **Solution**: Have subscription owner deploy
   - **Check**: `Get-AzRoleAssignment -SignInName your@email.com`

### Issue: Function App Won't Start

**Symptoms**:
- Function App shows "Stopped" state
- HTTP 503 errors when accessing functions
- Functions not loading in portal

**Diagnostics**:
```powershell
# Check Function App status
$app = Get-AzWebApp -ResourceGroupName "DefenderXSOAR-RG" -Name "defenderxsoar-func"
Write-Host "State: $($app.State)"
Write-Host "Enabled: $($app.Enabled)"

# Check app settings
$app.SiteConfig.AppSettings | Where-Object { $_.Name -like "*FUNCTIONS*" } | Format-Table
```

**Solutions**:

1. **Start the Function App**
   ```powershell
   Start-AzWebApp -ResourceGroupName "DefenderXSOAR-RG" -Name "defenderxsoar-func"
   ```

2. **Verify storage connection**
   ```powershell
   # Check if storage account exists
   $storageAccount = $app.SiteConfig.AppSettings | Where-Object { $_.Name -eq "AzureWebJobsStorage" }
   # Test connection string
   ```

3. **Check runtime version**
   - Ensure `FUNCTIONS_WORKER_RUNTIME` = "powershell"
   - Ensure `FUNCTIONS_WORKER_RUNTIME_VERSION` = "7.2"

### Issue: Key Vault Access Denied

**Symptoms**:
```
Error: The user, group or application 'appid=...' does not have secrets get permission
```

**Solutions**:

1. **Grant Key Vault Secrets User role**
   ```powershell
   $kvName = "defenderxsoar-kv-12345"
   $functionApp = Get-AzWebApp -ResourceGroupName "DefenderXSOAR-RG" -Name "defenderxsoar-func"
   $principalId = $functionApp.Identity.PrincipalId
   
   $kvResourceId = (Get-AzKeyVault -VaultName $kvName).ResourceId
   New-AzRoleAssignment -ObjectId $principalId -RoleDefinitionName "Key Vault Secrets User" -Scope $kvResourceId
   ```

2. **Verify managed identity is enabled**
   ```powershell
   if ($functionApp.Identity.Type -ne "SystemAssigned") {
       Set-AzWebApp -ResourceGroupName "DefenderXSOAR-RG" -Name "defenderxsoar-func" -AssignIdentity $true
   }
   ```

3. **Check firewall rules**
   - Ensure Key Vault allows Function App subnet (if using VNet)
   - Or allow "Trusted Microsoft Services"

## Authentication Issues

### Issue: "Failed to acquire token" Error

**Symptoms**:
```
Failed to acquire token for resource 'https://graph.microsoft.com'
AADSTS700016: Application not found in the directory
```

**Diagnostics**:
```powershell
# Test token acquisition
try {
    $token = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com"
    Write-Host "✓ Token acquired successfully" -ForegroundColor Green
} catch {
    Write-Host "✗ Token acquisition failed: $($_.Exception.Message)" -ForegroundColor Red
}
```

**Solutions**:

1. **Service principal not created**
   ```powershell
   $appId = "your-app-id"
   $sp = Get-AzADServicePrincipal -ApplicationId $appId
   if (-not $sp) {
       New-AzADServicePrincipal -ApplicationId $appId
   }
   ```

2. **Admin consent not granted**
   ```powershell
   # Generate consent URL
   $tenantId = "your-tenant-id"
   $consentUrl = "https://login.microsoftonline.com/$tenantId/adminconsent?client_id=$appId"
   Start-Process $consentUrl
   ```

3. **Wrong resource URL**
   - Microsoft Graph: `https://graph.microsoft.com`
   - MDE: `https://api.securitycenter.microsoft.com`
   - M365 Defender: `https://api.security.microsoft.com`
   - Azure ARM: `https://management.azure.com`

### Issue: Multi-Tenant Authentication Fails

**Symptoms**:
```
AADSTS50020: User account from identity provider 'live.com' does not exist in tenant
```

**Solutions**:

1. **Verify app is multi-tenant**
   ```powershell
   $app = Get-AzADApplication -ApplicationId $appId
   if ($app.SignInAudience -ne "AzureADMultipleOrgs") {
       Update-AzADApplication -ApplicationId $appId -SignInAudience "AzureADMultipleOrgs"
   }
   ```

2. **Customer hasn't granted consent**
   - Have customer admin visit consent URL
   - Verify service principal created in customer tenant

3. **Wrong tenant ID in request**
   - Ensure using customer tenant ID, not MSSP tenant ID
   - Check configuration: `$config.Tenants[0].TenantId`

### Issue: Token Expired or Invalid

**Symptoms**:
```
401 Unauthorized: The token is expired
```

**Solutions**:

1. **Token caching issue**
   - Restart Function App to clear cache
   - Verify token refresh logic in AuthenticationHelper

2. **Clock skew**
   - Ensure Function App time is synchronized
   - Check system time: `Get-Date`

3. **Certificate expired**
   ```powershell
   # Check certificate expiration
   $cert = Get-AzKeyVaultCertificate -VaultName $kvName -Name "DefenderXSOAR-Cert"
   if ($cert.Expires -lt (Get-Date)) {
       Write-Warning "Certificate expired on $($cert.Expires)"
   }
   ```

## API Connection Issues

### Issue: Cannot Connect to Microsoft Defender APIs

**Symptoms**:
```
Invoke-RestMethod: The remote server returned an error: (403) Forbidden
```

**Diagnostics**:
```powershell
# Test API connectivity
$apis = @{
    "Microsoft Graph" = "https://graph.microsoft.com/v1.0/security/alerts?`$top=1"
    "MDE" = "https://api.securitycenter.microsoft.com/api/machines?`$top=1"
    "M365 Defender" = "https://api.security.microsoft.com/api/incidents?`$top=1"
}

foreach ($api in $apis.Keys) {
    try {
        $token = Get-AzAccessToken -ResourceUrl ($apis[$api] -replace '/v1.0.*|/api.*', '')
        $headers = @{ Authorization = "Bearer $($token.Token)" }
        Invoke-RestMethod -Uri $apis[$api] -Headers $headers -Method Get | Out-Null
        Write-Host "✓ $api: Connected" -ForegroundColor Green
    } catch {
        Write-Host "✗ $api: Failed - $($_.Exception.Message)" -ForegroundColor Red
    }
}
```

**Solutions**:

1. **Missing API permissions**
   - Run `Grant-DefenderXSOARPermissions.ps1` again
   - Verify permissions in Azure Portal → App registrations → API permissions

2. **Wrong API endpoint**
   - MDE Plan 1 vs Plan 2 endpoints differ
   - Commercial vs GCC/GCC-High endpoints
   - Check configuration: `$config.ApiEndpoints`

3. **License not assigned**
   - Verify Defender product licenses in tenant
   - Check M365 admin center → Licenses

4. **Network connectivity**
   ```powershell
   # Test network connectivity
   Test-NetConnection -ComputerName api.securitycenter.microsoft.com -Port 443
   Test-NetConnection -ComputerName graph.microsoft.com -Port 443
   ```

### Issue: API Rate Limit Exceeded

**Symptoms**:
```
429 Too Many Requests: Rate limit exceeded
Retry-After: 60
```

**Solutions**:

1. **Implement retry logic**
   - Already implemented in workers
   - Exponential backoff with jitter
   - Respect `Retry-After` header

2. **Reduce API call frequency**
   - Enable caching in configuration
   - Increase cache TTL
   - Batch API requests

3. **Request rate limit increase**
   - Contact Microsoft Support
   - Provide use case justification
   - Available for enterprise customers

### Issue: MCAS API Token Invalid

**Symptoms**:
```
401 Unauthorized: Invalid token
```

**Solutions**:

1. **Regenerate token**
   - Log in to MCAS portal
   - Settings → Security extensions → API tokens
   - Revoke old token and create new one
   - Update Key Vault secret

2. **Verify token format**
   - Should be long alphanumeric string
   - No Bearer prefix needed
   - Store directly in Key Vault

3. **Check MCAS URL**
   - Tenant-specific: `https://yourtenant.portal.cloudappsecurity.com`
   - Different for GCC: `https://yourtenant.portal.cloudappsecurity.us`

## Performance Issues

### Issue: Function Takes Too Long to Execute

**Symptoms**:
- Functions timing out (10-minute limit on Consumption)
- Slow incident enrichment (> 2 minutes)
- High Application Insights latency metrics

**Diagnostics**:
```kql
// In Application Insights
requests
| where timestamp > ago(24h)
| where name == "Start-DefenderXSOAROrchestration"
| summarize 
    AvgDuration = avg(duration),
    P50 = percentile(duration, 50),
    P95 = percentile(duration, 95),
    P99 = percentile(duration, 99)
| project AvgDuration, P50, P95, P99
```

**Solutions**:

1. **Enable parallel execution**
   ```json
   {
     "WorkerSettings": {
       "ParallelExecution": true,
       "MaxDegreeOfParallelism": 6
     }
   }
   ```

2. **Optimize API calls**
   - Use `$select` to limit returned fields
   - Use `$top` to limit result count
   - Filter server-side, not client-side

3. **Upgrade to Premium plan**
   ```powershell
   # Switch to Premium EP1
   Set-AzWebApp -ResourceGroupName "DefenderXSOAR-RG" -Name "defenderxsoar-func" -AppServicePlan "EP1"
   ```

4. **Implement caching**
   - Cache entity lookups
   - Cache threat intelligence
   - Use Azure Redis Cache (optional)

### Issue: Cold Start Delays

**Symptoms**:
- First execution after idle period takes 10-15 seconds
- Warm-up requests timing out

**Solutions**:

1. **Use Premium plan with always-ready instances**
   - Pre-warmed instances eliminate cold starts
   - Set minimum instance count: 1-3

2. **Implement keep-alive**
   ```powershell
   # Create timer-triggered function to keep warm
   # Runs every 5 minutes
   ```

3. **Optimize package size**
   - Remove unused modules
   - Use module caching
   - Reduce deployment package

### Issue: High Memory Usage

**Symptoms**:
```
OutOfMemoryException: Insufficient memory to continue execution
```

**Diagnostics**:
```kql
// In Application Insights
performanceCounters
| where timestamp > ago(1h)
| where name == "Private Bytes"
| summarize AvgMemory = avg(value) by bin(timestamp, 5m)
| render timechart
```

**Solutions**:

1. **Process incidents in batches**
   - Limit concurrent worker execution
   - Process large entity lists in chunks
   - Use streaming where possible

2. **Clear variables**
   ```powershell
   # After processing each incident
   Remove-Variable -Name * -ErrorAction SilentlyContinue
   [System.GC]::Collect()
   ```

3. **Upgrade instance size**
   - Premium EP2: 7 GB memory
   - Premium EP3: 14 GB memory

## Data Ingestion Issues

### Issue: Data Not Appearing in Log Analytics

**Symptoms**:
- `DefenderXSOAR_CL` table not found
- No data in custom tables
- Queries return empty results

**Diagnostics**:
```kql
// Check if table exists
search "*"
| where TimeGenerated > ago(7d)
| where $table has "DefenderXSOAR"
| distinct $table

// Check recent ingestion
DefenderXSOAR_CL
| where TimeGenerated > ago(1h)
| count
```

**Solutions**:

1. **Wait for table creation**
   - First ingestion can take 5-10 minutes
   - Tables created automatically on first write
   - Check after 10 minutes

2. **Verify workspace permissions**
   ```powershell
   $workspaceId = "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}"
   $principalId = (Get-AzWebApp -ResourceGroupName "DefenderXSOAR-RG" -Name "defenderxsoar-func").Identity.PrincipalId
   
   New-AzRoleAssignment -ObjectId $principalId -RoleDefinitionName "Log Analytics Contributor" -Scope $workspaceId
   ```

3. **Check workspace ID and key**
   ```powershell
   # Verify in Function App settings
   $app = Get-AzWebApp -ResourceGroupName "DefenderXSOAR-RG" -Name "defenderxsoar-func"
   $wsIdSetting = $app.SiteConfig.AppSettings | Where-Object { $_.Name -eq "SentinelWorkspaceId" }
   Write-Host "Configured Workspace: $($wsIdSetting.Value)"
   ```

4. **Test ingestion manually**
   ```powershell
   # Use DataTableManager module
   $data = @{
       IncidentId = "TEST-001"
       TimeGenerated = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
       Message = "Test ingestion"
   }
   Send-DefenderXSOARToLogAnalytics -Data $data -TableName "DefenderXSOAR_CL"
   ```

### Issue: Data Ingestion Latency

**Symptoms**:
- Data appears in Log Analytics 15-30 minutes late
- Real-time dashboards not updating

**Expected Behavior**:
- Typical latency: 2-5 minutes
- Maximum latency: 15 minutes
- This is normal Azure behavior

**Solutions**:

1. **Use Application Insights for real-time**
   - Application Insights has lower latency (seconds)
   - Use for real-time monitoring
   - Use Log Analytics for historical analysis

2. **Implement caching for dashboards**
   - Cache query results for 5 minutes
   - Reduce query frequency

### Issue: Data Schema Mismatch

**Symptoms**:
```
Error: Column 'RiskScore_s' not found
```

**Solutions**:

1. **Check data types**
   - Strings end with `_s`
   - Numbers end with `_d`
   - Booleans end with `_b`
   - Datetime is `TimeGenerated`

2. **Regenerate schema**
   - Delete old test data
   - Reingest with correct schema
   - Wait for table recreation

## Configuration Issues

### Issue: Configuration Not Loading

**Symptoms**:
```
Error: Configuration file not found or invalid JSON
```

**Solutions**:

1. **Verify configuration in Key Vault**
   ```powershell
   $kvName = "defenderxsoar-kv-12345"
   $config = Get-AzKeyVaultSecret -VaultName $kvName -Name "DefenderXSOAR-Configuration" -AsPlainText
   $config | ConvertFrom-Json
   ```

2. **Rerun configuration script**
   ```powershell
   .\Configure-DefenderXSOAR.ps1 `
       -FunctionAppName "defenderxsoar-func" `
       -ResourceGroupName "DefenderXSOAR-RG" `
       -ConfigFilePath "..\Config\DefenderXSOAR.json"
   ```

3. **Validate JSON syntax**
   ```powershell
   Test-Json -Path "..\Config\DefenderXSOAR.json"
   ```

### Issue: Product Worker Disabled

**Symptoms**:
- Specific product data not enriched
- Worker not executed

**Solutions**:

1. **Enable product in configuration**
   ```json
   {
     "Products": {
       "MDE": {
         "Enabled": true,
         "Priority": 1
       }
     }
   }
   ```

2. **Verify licenses**
   - Check if Defender product licensed
   - Verify in M365 admin center

3. **Check worker logs**
   ```kql
   traces
   | where message contains "Worker"
   | where timestamp > ago(1h)
   | order by timestamp desc
   ```

## Monitoring and Logging

### Issue: No Telemetry in Application Insights

**Symptoms**:
- Empty Application Insights dashboards
- No traces or metrics

**Solutions**:

1. **Verify instrumentation key**
   ```powershell
   $app = Get-AzWebApp -ResourceGroupName "DefenderXSOAR-RG" -Name "defenderxsoar-func"
   $aiKey = $app.SiteConfig.AppSettings | Where-Object { $_.Name -eq "APPINSIGHTS_INSTRUMENTATIONKEY" }
   Write-Host "AI Key: $($aiKey.Value)"
   ```

2. **Check sampling rate**
   - Ensure sampling not set too low
   - Default: 100% (no sampling)

3. **Verify connection**
   ```powershell
   # Test Application Insights endpoint
   Test-NetConnection -ComputerName dc.services.visualstudio.com -Port 443
   ```

### Issue: Cannot Find Logs

**Where to Look**:

1. **Function execution logs**
   - Portal: Function App → Functions → Monitor
   - Or Application Insights → Logs

2. **System logs**
   ```kql
   FunctionAppLogs
   | where TimeGenerated > ago(1h)
   | where Level == "Error"
   | order by TimeGenerated desc
   ```

3. **Custom traces**
   ```kql
   traces
   | where customDimensions.Category == "DefenderXSOAR"
   | where timestamp > ago(1h)
   | order by timestamp desc
   ```

## Getting Help

### Self-Help Resources

1. **Review documentation**
   - [Prerequisites](Prerequisites.md)
   - [Permissions](Permissions.md)
   - [Architecture](Architecture.md)

2. **Check Application Insights**
   - Failures blade for errors
   - Performance blade for slow queries
   - Live metrics for real-time view

3. **Review Azure status**
   - https://status.azure.com
   - Check for service outages

### Support Channels

1. **GitHub Issues**
   - https://github.com/akefallonitis/defenderc2enrichement/issues
   - Provide detailed error messages
   - Include deployment details (region, SKU, etc.)

2. **Microsoft Support**
   - For Azure-specific issues
   - For API/product licensing issues
   - Include correlation IDs from errors

### Diagnostic Data Collection

When reporting issues, collect:

```powershell
# Run diagnostic script
$diagnostics = @{
    FunctionAppState = (Get-AzWebApp -ResourceGroupName "DefenderXSOAR-RG" -Name "defenderxsoar-func").State
    ManagedIdentity = (Get-AzWebApp -ResourceGroupName "DefenderXSOAR-RG" -Name "defenderxsoar-func").Identity.Type
    AppSettings = (Get-AzWebApp -ResourceGroupName "DefenderXSOAR-RG" -Name "defenderxsoar-func").SiteConfig.AppSettings | Select-Object Name
    Timestamp = Get-Date
}

$diagnostics | ConvertTo-Json | Out-File "DefenderXSOAR-Diagnostics.json"
```

## Common Error Messages

| Error | Meaning | Solution |
|-------|---------|----------|
| `AADSTS700016` | App not found | Create service principal |
| `AADSTS50020` | User/tenant mismatch | Check tenant ID |
| `403 Forbidden` | Missing permissions | Grant API permissions |
| `429 Too Many Requests` | Rate limit | Implement backoff |
| `OutOfMemoryException` | Memory exhausted | Upgrade instance size |
| `The token is expired` | Token refresh failed | Restart Function App |
