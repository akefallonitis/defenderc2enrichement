# DefenderXSOAR Quick Start Guide

Get DefenderXSOAR up and running in 30 minutes!

## Prerequisites Checklist

- [ ] PowerShell 7.0+ installed
- [ ] Azure subscription with active Sentinel workspace
- [ ] Global Administrator or Application Administrator access
- [ ] Microsoft Defender products enabled (at least one)
- [ ] Git installed

## Step 1: Clone and Navigate (2 minutes)

```powershell
# Clone the repository
git clone https://github.com/akefallonitis/defenderc2enrichement.git
cd defenderc2enrichement/DefenderXSOAR
```

## Step 2: Deploy Azure Resources (10 minutes)

```powershell
# Run the deployment script
.\Deploy\Deploy-DefenderXSOAR.ps1 `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "DefenderXSOAR-RG" `
    -Location "eastus" `
    -WorkspaceName "defenderxsoar-workspace" `
    -CreateAppRegistration $true
```

**Save the output!** You'll need:
- Application (Client) ID
- Client Secret
- Workspace ID
- Primary Shared Key

## Step 3: Grant Permissions (10 minutes)

```powershell
# Generate permission requirements
.\Deploy\GrantPermissions.ps1 `
    -ApplicationId "your-app-id-from-step2" `
    -TenantId "your-tenant-id"
```

Then in Azure Portal:
1. Go to **Azure Active Directory** → **App registrations**
2. Find **DefenderXSOAR-ServicePrincipal**
3. Click **API permissions** → **Add a permission**
4. Add all permissions listed in the script output
5. Click **Grant admin consent for [Tenant]**

## Step 4: Configure DefenderXSOAR (5 minutes)

Edit `Config/DefenderXSOAR.json`:

```json
{
  "Tenants": [
    {
      "TenantName": "Production",
      "TenantId": "your-tenant-id",
      "ClientId": "your-client-id-from-step2",
      "ClientSecret": "your-client-secret-from-step2",
      "SubscriptionId": "your-subscription-id",
      "Enabled": true
    }
  ],
  "LogAnalytics": {
    "Enabled": true,
    "WorkspaceId": "workspace-id-from-step2",
    "SharedKey": "shared-key-from-step2"
  }
}
```

## Step 5: Test the Setup (3 minutes)

```powershell
# Create test entities
$testEntities = @(
    @{
        Type = "User"
        UserPrincipalName = "test@yourdomain.com"
        Name = "Test User"
    },
    @{
        Type = "Device"
        HostName = "TEST-DEVICE"
    }
)

# Run orchestration
.\Functions\Start-DefenderXSOAROrchestration.ps1 `
    -ConfigPath ".\Config\DefenderXSOAR.json" `
    -IncidentId "TEST-001" `
    -Entities $testEntities `
    -TenantId "your-tenant-id" `
    -Products @('MDE', 'EntraID')
```

## Expected Output

You should see:

```
╔═══════════════════════════════════════════════════════════════════╗
║                      DefenderXSOAR                                ║
║              Comprehensive Security Orchestration                 ║
║                   Automation & Response                           ║
╚═══════════════════════════════════════════════════════════════════╝

Step 1: Initializing DefenderXSOAR Brain...
Configuration loaded successfully
  ✓ Tenant initialized

Step 2: Starting enrichment orchestration...

Enriching with MDE...
  ✓ MDE enrichment completed

Enriching with EntraID...
  ✓ EntraID enrichment completed

╔═══════════════════════════════════════════════════════════════════╗
║                    ENRICHMENT SUMMARY                             ║
╚═══════════════════════════════════════════════════════════════════╝

Incident ID: TEST-001
Risk Score: XX/100
Severity: Medium
Decision: Investigate
Priority: Medium
```

## Verify Data in Log Analytics

1. Open Azure Portal → Log Analytics workspace
2. Run this query:

```kql
DefenderXSOAR_CL
| where IncidentId_s == "TEST-001"
| project TimeGenerated, RiskScore_d, Severity_s, EntitiesCount_d
```

## Integration with Sentinel

### Option A: Automation Rule

1. In Sentinel, go to **Automation** → **Automation rules**
2. Create new rule:
   - **Trigger**: When incident is created
   - **Conditions**: Severity = Medium, High, or Critical
   - **Actions**: Run playbook → DefenderXSOAR
   - **Order**: 1

### Option B: Logic App

1. Create Logic App with HTTP trigger
2. Add PowerShell script action:

```powershell
$entities = $triggerBody.Entities
$incidentId = $triggerBody.IncidentId

.\Functions\Start-DefenderXSOAROrchestration.ps1 `
    -ConfigPath ".\Config\DefenderXSOAR.json" `
    -IncidentId $incidentId `
    -Entities $entities `
    -TenantId "your-tenant-id"
```

### Option C: Azure Function

Deploy as Azure Function for serverless execution:

```powershell
# Create function app
az functionapp create `
    --resource-group DefenderXSOAR-RG `
    --consumption-plan-location eastus `
    --runtime powershell `
    --functions-version 4 `
    --name defenderxsoar-func `
    --storage-account defenderxsoarstorage
```

## Common Issues

### Issue: "Failed to acquire token"

**Solution**: Verify:
- Client ID and Secret are correct
- App registration has required permissions
- Admin consent has been granted

### Issue: "No data in Log Analytics"

**Solution**: Check:
- Workspace ID and Shared Key are correct
- Service principal has Log Analytics Contributor role
- Wait 5-10 minutes for data ingestion

### Issue: "Product enrichment failed"

**Solution**: Ensure:
- The product is enabled in your tenant
- Service principal has the required API permissions
- Network connectivity to Microsoft endpoints

## Next Steps

1. **Customize Configuration**
   - Adjust risk scoring thresholds
   - Configure auto-escalation rules
   - Add more tenants for MSSP

2. **Explore Playbooks**
   - Review available hunting queries
   - Customize queries for your environment
   - Create custom playbooks

3. **Set Up Monitoring**
   - Create Azure Monitor alerts
   - Set up Log Analytics workbook
   - Configure notification channels

4. **Enable Advanced Features**
   - Watchlist integration
   - UEBA behavioral analysis
   - External workflow automation

## Getting Help

- **Documentation**: See main [README.md](../README.md)
- **Issues**: [GitHub Issues](https://github.com/akefallonitis/defenderc2enrichement/issues)
- **Logs**: Check `DefenderXSOAR/Logs/` directory

## Security Reminders

⚠️ **Important Security Notes**:

1. Never commit secrets to Git
2. Use Azure Key Vault in production
3. Rotate credentials regularly
4. Enable audit logging
5. Follow principle of least privilege

## Success Checklist

- [ ] All Azure resources deployed
- [ ] App registration created with permissions
- [ ] Configuration file updated
- [ ] Test run completed successfully
- [ ] Data visible in Log Analytics
- [ ] Sentinel integration configured
- [ ] Monitoring and alerts set up

## Congratulations! 🎉

You've successfully deployed DefenderXSOAR! Your security operations are now automated and enhanced across all Microsoft Defender products.

For advanced configuration and detailed documentation, refer to the main [README.md](../README.md).
