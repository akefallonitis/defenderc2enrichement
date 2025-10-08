# DefenderXSOAR API Reference

This document provides comprehensive API reference for DefenderXSOAR's direct Microsoft API integrations.

## Table of Contents

- [Overview](#overview)
- [Microsoft Graph API](#microsoft-graph-api)
- [Microsoft 365 Defender API](#microsoft-365-defender-api)
- [Azure Resource Manager API](#azure-resource-manager-api)
- [Microsoft Defender for Cloud Apps API](#microsoft-defender-for-cloud-apps-api)
- [Authentication](#authentication)
- [Entity Mapping](#entity-mapping)

## Overview

DefenderXSOAR uses **direct API calls** to official Microsoft endpoints. No Logic Apps custom connectors are used, ensuring:

- ✅ Production-ready reliability
- ✅ Reduced dependencies
- ✅ Better performance
- ✅ Easier troubleshooting
- ✅ Multi-tenant support

## Microsoft Graph API

Base URL: `https://graph.microsoft.com/v1.0`

### Authentication

```powershell
$GraphToken = Get-DefenderXSOARToken `
    -TenantId $TenantId `
    -ClientId $ClientId `
    -ClientSecret $ClientSecret `
    -Scope "https://graph.microsoft.com/.default"

$Headers = @{
    'Authorization' = "Bearer $GraphToken"
    'Content-Type' = 'application/json'
}
```

### Identity Protection

#### Get Risky Users

```powershell
GET /identityProtection/riskyUsers
GET /identityProtection/riskyUsers?$filter=riskLevel eq 'high'
```

**Response:**
```json
{
  "value": [
    {
      "id": "user-id",
      "userPrincipalName": "user@contoso.com",
      "riskLevel": "high",
      "riskState": "atRisk",
      "riskDetail": "leaked credentials"
    }
  ]
}
```

#### Get Risky Sign-Ins

```powershell
GET /identityProtection/riskySignIns?$top=100
GET /identityProtection/riskySignIns?$filter=userPrincipalName eq 'user@contoso.com'
```

#### Get Risk Detections

```powershell
GET /identityProtection/riskDetections
```

### Users

```powershell
GET /users/{id}
GET /users?$filter=userPrincipalName eq 'user@contoso.com'
GET /users/{id}/memberOf
```

### Devices

```powershell
GET /devices/{id}
GET /devices?$filter=displayName eq 'DEVICE01'
```

### Security

```powershell
GET /security/alerts
GET /security/incidents
GET /security/threatIntelligence/articles
```

## Microsoft 365 Defender API

Base URL: `https://api.security.microsoft.com/api`

### Authentication

```powershell
$DefenderToken = Get-DefenderXSOARToken `
    -TenantId $TenantId `
    -ClientId $ClientId `
    -ClientSecret $ClientSecret `
    -Scope "https://api.security.microsoft.com/.default"

$Headers = @{
    'Authorization' = "Bearer $DefenderToken"
    'Content-Type' = 'application/json'
}
```

### Incidents

#### Get Incidents

```powershell
GET /incidents
GET /incidents?$filter=severity eq 'High'
```

**Response:**
```json
{
  "value": [
    {
      "incidentId": "123",
      "incidentName": "Suspicious activity",
      "severity": "High",
      "status": "Active",
      "assignedTo": null,
      "alerts": []
    }
  ]
}
```

#### Get Incident Details

```powershell
GET /incidents/{incidentId}
```

### Alerts

```powershell
GET /alerts
GET /alerts?$filter=severity eq 'High' and status eq 'New'
```

### Machines (Devices)

```powershell
GET /machines
GET /machines/{machineId}
GET /machines?$filter=computerDnsName eq 'device.contoso.com'
GET /machines/{machineId}/alerts
```

### Advanced Hunting

```powershell
POST /advancedqueries/run

Body:
{
  "Query": "DeviceInfo | where DeviceName == 'DEVICE01' | limit 10"
}
```

**Example Queries:**

```kql
// Get device information
DeviceInfo
| where DeviceName == 'DEVICE01'
| project Timestamp, DeviceId, OSPlatform, OSVersion, PublicIP

// Get process executions
DeviceProcessEvents
| where DeviceName == 'DEVICE01'
| where Timestamp > ago(7d)
| project Timestamp, FileName, FolderPath, ProcessCommandLine, AccountName

// Get network connections
DeviceNetworkEvents
| where DeviceName == 'DEVICE01'
| where Timestamp > ago(7d)
| project Timestamp, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
```

### Files

```powershell
GET /files/{sha1}
GET /files/{sha1}/machines
```

## Azure Resource Manager API

Base URL: `https://management.azure.com`

### Authentication

```powershell
$ArmToken = Get-DefenderXSOARToken `
    -TenantId $TenantId `
    -ClientId $ClientId `
    -ClientSecret $ClientSecret `
    -Scope "https://management.azure.com/.default"

$Headers = @{
    'Authorization' = "Bearer $ArmToken"
    'Content-Type' = 'application/json'
}
```

### Microsoft Defender for Cloud

#### Security Assessments

```powershell
GET /subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01
GET /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Security/assessments?api-version=2020-01-01
```

#### Security Alerts

```powershell
GET /subscriptions/{subscriptionId}/providers/Microsoft.Security/alerts?api-version=2022-01-01
```

#### Secure Score

```powershell
GET /subscriptions/{subscriptionId}/providers/Microsoft.Security/secureScores?api-version=2020-01-01
```

#### Compliance Results

```powershell
GET /subscriptions/{subscriptionId}/providers/Microsoft.Security/regulatoryComplianceStandards?api-version=2019-01-01-preview
```

## Microsoft Defender for Cloud Apps API

Base URL: `https://{tenant}.portal.cloudappsecurity.com/api/v1`

### Authentication

```powershell
$Headers = @{
    'Authorization' = "Token $MCASToken"
    'Content-Type' = 'application/json'
}
```

### Alerts

```powershell
GET /alerts/
POST /alerts/

Body (for filtering):
{
  "filters": {
    "severity": { "eq": "high" },
    "resolutionStatus": { "eq": "open" }
  }
}
```

### Activities

```powershell
POST /activities/

Body:
{
  "filters": {
    "user.username": { "eq": "user@contoso.com" },
    "date": { "gte_ndays": 7 }
  }
}
```

### Files

```powershell
GET /files/
POST /files/

Body:
{
  "filters": {
    "fileType": { "eq": "Document" },
    "quarantined": { "eq": false }
  }
}
```

## Authentication

DefenderXSOAR uses OAuth 2.0 client credentials flow for authentication.

### Token Acquisition

```powershell
$tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

$body = @{
    client_id     = $ClientId
    client_secret = $ClientSecret
    scope         = $Scope
    grant_type    = "client_credentials"
}

$response = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $body
$accessToken = $response.access_token
```

### Token Caching

DefenderXSOAR automatically caches tokens and refreshes them before expiration:

```powershell
$cacheKey = "$TenantId-$Scope"
if ($script:AccessTokenCache[$cacheKey] -and 
    $script:AccessTokenCache[$cacheKey].ExpiresOn -gt (Get-Date).AddMinutes(5)) {
    return $script:AccessTokenCache[$cacheKey].AccessToken
}
```

### Required Scopes

| API | Scope |
|-----|-------|
| Microsoft Graph | `https://graph.microsoft.com/.default` |
| Microsoft 365 Defender | `https://api.security.microsoft.com/.default` |
| Azure Resource Manager | `https://management.azure.com/.default` |

## Entity Mapping

DefenderXSOAR normalizes entities from different sources to a unified schema.

### Supported Entity Types

#### Account

**Official Microsoft Sentinel Schema:**
- UPN (User Principal Name)
- ObjectGUID
- SID (Security Identifier)
- AADUserId (Azure AD User ID)
- NTDomain
- DnsDomain
- DisplayName
- AccountName

#### Host

**Official Microsoft Sentinel Schema:**
- Hostname
- NetBiosName
- AzureID
- OMSAgentID
- OSVersion
- FQDN (Fully Qualified Domain Name)
- MdatpDeviceId (Microsoft Defender ATP Device ID)

#### IP Address

**Official Microsoft Sentinel Schema:**
- Address (IPv4/IPv6)
- Location
- ThreatIntelligence

#### File

**Official Microsoft Sentinel Schema:**
- FileHash (SHA1, SHA256, MD5)
- FileName
- FilePath
- Directory
- Size
- CreationTime

#### Process

**Official Microsoft Sentinel Schema:**
- ProcessID
- ProcessName
- CommandLine
- ParentProcess
- CreationTime
- ElevationToken

#### URL

**Official Microsoft Sentinel Schema:**
- Url (full string)
- Host
- Domain
- Path
- QueryString

#### Mailbox

**Official Microsoft Sentinel Schema:**
- DisplayName
- Alias
- MailboxGuid
- ExternalDirectoryObjectId
- UserPrincipalName

#### CloudApplication

**Official Microsoft Sentinel Schema:**
- ApplicationID
- ResourceID
- AppDisplayName
- InstanceName
- Type

#### AzureResource

**Official Microsoft Sentinel Schema:**
- ResourceId
- SubscriptionId
- ResourceGroup
- ResourceType
- ResourceName

#### Registry

**Official Microsoft Sentinel Schema:**
- RegistryKey
- RegistryHive
- RegistryValueName
- RegistryValueData
- RegistryValueType

#### DNS

**Official Microsoft Sentinel Schema:**
- DomainName
- DnsServerIP
- QueryType
- QueryClass
- QueryResponse

### Example: Entity Normalization

```powershell
# MDE Device to Host Entity
$mdeDevice = @{
    id = "abc123"
    computerDnsName = "DEVICE01.contoso.com"
    azureAdDeviceId = "azure-id-123"
    osVersion = "Windows 11"
    osPlatform = "Windows11"
    riskScore = "High"
}

$normalizedHost = ConvertTo-NormalizedEntity `
    -EntityData $mdeDevice `
    -EntityType "Host" `
    -Source "MDE"

# Result:
{
    Hostname: "DEVICE01.contoso.com"
    NetBiosName: "DEVICE01"
    FQDN: "DEVICE01.contoso.com"
    MdatpDeviceId: "abc123"
    AzureID: "azure-id-123"
    OSVersion: "Windows 11"
    OSPlatform: "Windows11"
    RiskScore: "High"
}
```

## Error Handling

All API calls include comprehensive error handling:

```powershell
try {
    $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
    return $response.value
}
catch {
    Write-Error "API call failed: $_"
    
    if ($_.Exception.Response) {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $statusDescription = $_.Exception.Response.StatusDescription
        Write-Error "Status: $statusCode - $statusDescription"
    }
    
    return @()
}
```

## Rate Limiting

DefenderXSOAR respects API rate limits:

- **Microsoft Graph**: 2000 requests per minute per app
- **Microsoft 365 Defender**: 45 requests per minute per tenant
- **Azure Resource Manager**: 12,000 reads per hour per subscription

## Best Practices

1. **Use caching**: Avoid repeated API calls for the same data
2. **Batch operations**: Use `$batch` endpoint when possible
3. **Filter server-side**: Use `$filter` to reduce data transfer
4. **Use pagination**: Handle large result sets with `@odata.nextLink`
5. **Monitor throttling**: Implement exponential backoff on 429 responses

## Additional Resources

- [Microsoft Graph API Documentation](https://docs.microsoft.com/graph/api/overview)
- [Microsoft 365 Defender API Documentation](https://docs.microsoft.com/microsoft-365/security/defender-endpoint/api-overview)
- [Azure Resource Manager REST API](https://docs.microsoft.com/rest/api/azure/)
- [Microsoft Defender for Cloud Apps API](https://docs.microsoft.com/cloud-app-security/api-introduction)
