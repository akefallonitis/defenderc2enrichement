# DefenderXSOAR Azure Functions

This directory contains the Azure Function triggers for DefenderXSOAR.

## Function Triggers

### 1. DefenderXSOAROrchestrator (HTTP Trigger)

**Purpose:** Main entry point for DefenderXSOAR orchestration via HTTP request

**Trigger Type:** HTTP POST  
**Auth Level:** Function (requires function key)  
**Endpoint:** `/api/DefenderXSOAROrchestrator`

**Request Body:**
```json
{
  "IncidentId": "12345",
  "IncidentArmId": "/subscriptions/.../incidents/...",
  "Entities": [
    {
      "Type": "Account",
      "Properties": {
        "UPN": "user@contoso.com"
      }
    }
  ],
  "TenantId": "tenant-id-guid",
  "Products": ["MDE", "MDC", "MCAS", "MDI", "MDO", "EntraID"]
}
```

**Response:**
```json
{
  "Status": "Success",
  "IncidentId": "12345",
  "RiskScore": 85,
  "EnrichedEntities": [...],
  "Recommendations": [...]
}
```

**Usage:**
```powershell
$functionUrl = "https://defenderxsoar-func-xxx.azurewebsites.net/api/DefenderXSOAROrchestrator"
$functionKey = "your-function-key"

$body = @{
    IncidentId = "12345"
    TenantId = "tenant-guid"
    Entities = @()
    Products = @('MDE', 'EntraID')
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri "$functionUrl?code=$functionKey" `
    -Method Post `
    -Body $body `
    -ContentType "application/json"
```

---

### 2. DefenderXSOARTimer (Timer Trigger)

**Purpose:** Scheduled polling of Microsoft Defender products for new incidents

**Trigger Type:** Timer (CRON)  
**Default Schedule:** `0 */15 * * * *` (Every 15 minutes)  
**Auth Level:** N/A (internal trigger)

**Configuration:**

Edit `DefenderXSOARTimer/function.json` to change schedule:
```json
{
  "schedule": "0 */30 * * * *"  // Every 30 minutes
}
```

**CRON Schedule Examples:**
- `0 */5 * * * *` - Every 5 minutes
- `0 */15 * * * *` - Every 15 minutes (default)
- `0 0 */1 * * *` - Every hour
- `0 0 */6 * * *` - Every 6 hours

**Features:**
- Polls Microsoft 365 Defender for high-risk incidents
- Checks for new incidents since last run
- Processes incidents automatically based on severity
- Respects configuration settings for enabled/disabled

**Enable/Disable:**

Set in configuration:
```json
{
  "Triggers": {
    "DefenderPolling": {
      "Enabled": true,
      "IntervalMinutes": 15,
      "MinimumSeverity": "High"
    }
  }
}
```

---

### 3. DefenderXSOARWebhook (HTTP Trigger)

**Purpose:** Sentinel webhook handler for automatic incident enrichment

**Trigger Type:** HTTP POST  
**Auth Level:** Function (requires function key)  
**Endpoint:** `/api/sentinel/webhook`

**Request Body (Sentinel Incident):**
```json
{
  "id": "/subscriptions/.../incidents/...",
  "properties": {
    "incidentNumber": 123,
    "title": "Suspicious activity detected",
    "severity": "High",
    "status": "New",
    "relatedEntities": [
      {
        "kind": "Account",
        "properties": {
          "accountName": "user@contoso.com"
        }
      }
    ]
  }
}
```

**Sentinel Automation Rule Setup:**

1. Navigate to Microsoft Sentinel
2. Go to **Automation** > **Automation rules**
3. Click **+ Create** > **Automation rule**
4. Configure:
   - **Name**: DefenderXSOAR Auto-Enrichment
   - **Trigger**: When incident is created
   - **Conditions**: 
     - Severity equals High OR Critical
   - **Actions**: 
     - Run playbook > Call webhook
     - Webhook URL: `https://{function-app}.azurewebsites.net/api/sentinel/webhook?code={function-key}`
5. Save

**Features:**
- Automatic triggering on Sentinel incident creation
- Severity-based filtering
- Entity extraction from incident
- Real-time enrichment
- Incident comment posting with results

---

## Configuration Files

### host.json

Global Function App configuration:

```json
{
  "version": "2.0",
  "functionTimeout": "00:10:00",
  "logging": {
    "applicationInsights": {
      "samplingSettings": {
        "isEnabled": true
      }
    }
  }
}
```

### requirements.psd1

PowerShell module dependencies:

```powershell
@{
    'Az.Accounts' = '2.*'
    'Az.KeyVault' = '4.*'
    'Az.Resources' = '6.*'
    'Az.SecurityInsights' = '3.*'
}
```

### profile.ps1

Function App startup script that loads DefenderXSOAR modules:

```powershell
# Authenticate with managed identity
Connect-AzAccount -Identity

# Import DefenderXSOAR modules
Import-Module ./Modules/DefenderXSOARBrain.psm1
```

---

## Testing Functions Locally

### Prerequisites

1. Install Azure Functions Core Tools:
```bash
npm install -g azure-functions-core-tools@4
```

2. Install PowerShell 7.2+:
```bash
# Linux/macOS
brew install --cask powershell

# Windows
winget install Microsoft.PowerShell
```

### Local Development

1. Clone repository:
```bash
git clone https://github.com/akefallonitis/defenderc2enrichement.git
cd defenderc2enrichement/DefenderXSOAR
```

2. Create `local.settings.json`:
```json
{
  "IsEncrypted": false,
  "Values": {
    "AzureWebJobsStorage": "UseDevelopmentStorage=true",
    "FUNCTIONS_WORKER_RUNTIME": "powershell",
    "FUNCTIONS_WORKER_RUNTIME_VERSION": "7.2",
    "KeyVaultName": "your-keyvault-name",
    "TenantId": "your-tenant-id"
  }
}
```

3. Start Functions locally:
```bash
func start
```

4. Test HTTP trigger:
```powershell
$body = @{
    IncidentId = "12345"
    TenantId = "test-tenant"
    Entities = @()
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri "http://localhost:7071/api/DefenderXSOAROrchestrator" `
    -Method Post `
    -Body $body `
    -ContentType "application/json"
```

---

## Monitoring

### Application Insights

View function execution logs:

```kql
traces
| where timestamp > ago(1h)
| where message contains "DefenderXSOAR"
| order by timestamp desc
```

View function performance:

```kql
requests
| where name contains "DefenderXSOAR"
| summarize 
    Count = count(),
    AvgDuration = avg(duration),
    P95Duration = percentile(duration, 95)
    by name
```

### Azure Portal

1. Navigate to Function App
2. Go to **Functions**
3. Select function (e.g., DefenderXSOAROrchestrator)
4. Click **Monitor**
5. View invocations, logs, and metrics

---

## Troubleshooting

### Function Not Triggering

**Issue:** HTTP trigger returns 404

**Solution:**
1. Verify function is deployed
2. Check function.json exists
3. Restart Function App
4. Verify function key is correct

### Timer Not Running

**Issue:** Timer trigger not executing on schedule

**Solution:**
1. Check CRON syntax in function.json
2. Verify Function App is running
3. Check Application Insights for timer trigger logs
4. Ensure AzureWebJobsStorage is configured

### Authentication Errors

**Issue:** 401 Unauthorized errors in function logs

**Solution:**
1. Verify managed identity is enabled
2. Check API permissions granted
3. Verify Key Vault access
4. Test token acquisition manually

---

## Best Practices

1. **Use Function Keys**: Protect HTTP triggers with function keys
2. **Monitor Costs**: Watch consumption plan executions
3. **Set Timeouts**: Configure appropriate function timeouts
4. **Use Retry Logic**: Enable automatic retries for transient failures
5. **Log Extensively**: Use Write-Host for debugging
6. **Test Locally**: Test functions locally before deployment

---

## Related Documentation

- [Deployment Guide](../Deploy/Documentation/Deployment.md)
- [Configuration Guide](../Deploy/Documentation/Configuration.md)
- [API Reference](../Deploy/Documentation/API-Reference.md)
- [Architecture Documentation](../Deploy/Documentation/Architecture.md)
