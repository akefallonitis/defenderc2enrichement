# DefenderXSOAR - Architecture Overview

This document provides a comprehensive overview of the DefenderXSOAR architecture, deployment patterns, and technical design.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Microsoft Sentinel                          │
│                  (Log Analytics Workspace)                      │
└────────────┬────────────────────────────────────┬───────────────┘
             │                                    │
             │ Incident Trigger                   │ Write Results
             │                                    │
             ▼                                    ▼
┌────────────────────────────────────────────────────────────────┐
│                    Azure Function App                           │
│                  (PowerShell 7.2 Runtime)                      │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │           DefenderXSOAR Orchestration Brain               │ │
│  └──────────────────────────────────────────────────────────┘ │
│                          │                                     │
│         ┌────────────────┼────────────────┐                   │
│         ▼                ▼                ▼                   │
│  ┌───────────┐   ┌───────────┐   ┌───────────┐              │
│  │ MDE Worker│   │ MDC Worker│   │MCAS Worker│              │
│  └───────────┘   └───────────┘   └───────────┘              │
│  ┌───────────┐   ┌───────────┐   ┌───────────┐              │
│  │ MDI Worker│   │ MDO Worker│   │Entra Worker│              │
│  └───────────┘   └───────────┘   └───────────┘              │
└────────────┬────────────────────────────────────────────────────┘
             │
             │ API Calls via Managed Identity
             │
             ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Microsoft Security APIs                        │
├─────────────────┬──────────────┬───────────────┬───────────────┤
│ Microsoft Graph │ MDE API      │ M365 Defender │ Azure ARM     │
│ Entra ID        │ Threat Intel │ MCAS          │ MDC           │
└─────────────────┴──────────────┴───────────────┴───────────────┘
```

## Core Components

### 1. Azure Function App

**Role**: Hosting environment for DefenderXSOAR
**Technology**: Azure Functions v4, PowerShell 7.2
**Deployment**: Consumption or Premium plan

**Key Features**:
- Serverless execution model
- Automatic scaling (up to 200 instances)
- Pay-per-execution pricing
- Built-in authentication via managed identity
- Integration with Application Insights

**Configuration**:
```json
{
  "FUNCTIONS_WORKER_RUNTIME": "powershell",
  "FUNCTIONS_WORKER_RUNTIME_VERSION": "7.2",
  "FUNCTIONS_EXTENSION_VERSION": "~4"
}
```

### 2. Storage Account

**Role**: Function App storage and artifact persistence
**Type**: General Purpose v2 (StorageV2)
**Redundancy**: Locally Redundant Storage (LRS)

**Contents**:
- Function code packages
- Execution logs (short-term)
- Configuration cache
- Deployment artifacts

**Security**:
- HTTPS only
- TLS 1.2 minimum
- No public blob access
- Managed identity access

### 3. Key Vault

**Role**: Secure credential and secret storage
**Type**: Standard tier
**Access Model**: Azure RBAC

**Stored Secrets**:
- Multi-tenant app client secrets
- MCAS API tokens
- Log Analytics shared keys
- Customer tenant credentials
- Certificate private keys (optional)

**Features**:
- Soft delete (90-day retention)
- Purge protection (optional)
- Access logging and auditing
- Integration with Function App managed identity

### 4. Application Insights

**Role**: Monitoring, telemetry, and diagnostics
**Type**: Workspace-based
**Data**: Linked to Sentinel workspace

**Telemetry Collected**:
- Function execution traces
- Custom metrics (enrichment success rate, API latencies)
- Exceptions and errors
- Dependency tracking (API calls)
- Live metrics stream

**Custom Metrics**:
- `DefenderXSOAR.EnrichmentDuration` - Time to process incident
- `DefenderXSOAR.RiskScore` - Calculated risk scores
- `DefenderXSOAR.APICallCount` - API calls per product
- `DefenderXSOAR.ErrorRate` - Percentage of failed enrichments

### 5. App Service Plan

**Role**: Compute resources for Function App
**Options**:
- **Consumption (Y1)**: Pay-per-execution, 10-min timeout
- **Premium (EP1/EP2/EP3)**: Pre-warmed instances, VNet integration

**Scaling**:
- Automatic scale-out based on load
- Scale-in when idle
- Maximum 200 instances (Consumption)

## PowerShell Module Architecture

### DefenderXSOARBrain.psm1 (Orchestrator)

**Responsibilities**:
- Incident intake and validation
- Entity normalization across products
- Worker orchestration and parallel execution
- Risk score calculation
- Result aggregation
- Decision recommendations

**Key Functions**:
- `Start-DefenderXSOAREnrichment` - Main entry point
- `Invoke-ProductWorkers` - Parallel worker execution
- `Calculate-RiskScore` - Multi-factor risk calculation
- `Generate-IncidentDecision` - Auto-escalation logic

### Product Workers

Each worker is a specialized module for a specific Microsoft Defender product:

#### MDEWorker.psm1 (Microsoft Defender for Endpoint)
- Device compromise detection
- Malware file analysis
- Process tree analysis
- Network connection analysis
- Advanced hunting queries

#### MDCWorker.psm1 (Microsoft Defender for Cloud)
- Security posture assessment
- Vulnerability analysis
- Compliance gap detection
- Resource configuration review

#### MCASWorker.psm1 (Microsoft Defender for Cloud Apps)
- Cloud app risk scoring
- User behavior analytics (UEBA)
- Data exfiltration detection
- OAuth app analysis

#### MDIWorker.psm1 (Microsoft Defender for Identity)
- Identity compromise detection
- Lateral movement analysis
- Kerberos attack detection
- Privilege escalation detection

#### MDOWorker.psm1 (Microsoft Defender for Office 365)
- Phishing campaign detection
- Email security analysis
- Malicious attachment analysis
- URL reputation checks

#### EntraIDWorker.psm1 (Microsoft Entra ID)
- Risky sign-in analysis
- Identity risk events
- MFA bypass detection
- Conditional access violations

### Common Modules

#### AuthenticationHelper.psm1
- Token acquisition and caching
- Multi-tenant authentication
- Managed identity support
- Token refresh logic

#### EntityNormalizer.psm1
- Entity type detection
- Cross-product entity matching
- Entity enrichment
- Duplicate detection

#### DataTableManager.psm1
- Log Analytics integration
- Custom table creation
- Batch data ingestion
- Schema management

## Data Flow

### 1. Incident Trigger

```
Sentinel Incident → Automation Rule → Logic App/Webhook → Function App HTTP Trigger
```

**Input Payload**:
```json
{
  "IncidentId": "12345",
  "IncidentArmId": "/subscriptions/.../incidents/12345",
  "Title": "Suspicious PowerShell execution",
  "Severity": "High",
  "Entities": [
    { "Type": "Account", "Name": "user@domain.com" },
    { "Type": "Host", "Name": "DESKTOP-ABC123" }
  ]
}
```

### 2. Orchestration

```
Brain Module → Entity Normalization → Parallel Worker Execution → Result Aggregation
```

**Parallel Execution**:
- Each product worker runs in parallel
- Timeout: 300 seconds per worker
- Retry logic: 3 attempts
- Error isolation: Worker failure doesn't fail entire enrichment

### 3. API Calls

Each worker makes API calls to respective Microsoft security services:

**Authentication Flow**:
```
Function App → Managed Identity → Azure AD → Access Token → API Call
```

**Token Caching**:
- Tokens cached for 55 minutes (5-min buffer before expiration)
- Per-resource token cache
- Automatic refresh on expiration

### 4. Result Processing

```
Worker Results → Risk Calculation → Decision Logic → Log Analytics Write
```

**Risk Score Formula**:
```
RiskScore = Σ(Product_Score × Product_Weight × Severity_Multiplier)
```

Where:
- Product scores: 0-100 from each worker
- Product weights: Configurable (MDE: 1.2, MDI: 1.3, etc.)
- Severity multiplier: Critical: 1.5, High: 1.2, Medium: 1.0, Low: 0.8

### 5. Output

**Log Analytics Tables**:
- `DefenderXSOAR_CL` - Main enrichment results
- `DefenderXSOAR_Entities_CL` - Normalized entities
- `DefenderXSOAR_Risk_CL` - Risk scores
- `DefenderXSOAR_Decisions_CL` - Auto-decisions

**Sentinel Update**:
- Incident comments added
- Tags updated
- Severity adjusted (if auto-escalate enabled)
- Owner assigned (if configured)

## Deployment Patterns

### Pattern 1: Single Tenant (Small Organization)

```
┌────────────────┐
│   Azure        │
│   Tenant       │
│                │
│  ┌──────────┐  │
│  │ Sentinel │  │
│  └────┬─────┘  │
│       │        │
│  ┌────▼─────┐  │
│  │DefenderXSOAR│
│  │(Managed ID) │
│  └──────────┘  │
└────────────────┘
```

**Characteristics**:
- One Azure tenant
- Managed identity authentication
- Direct Sentinel integration
- Simplest deployment

### Pattern 2: Multi-Tenant MSSP (Service Provider)

```
┌────────────────┐      ┌────────────────┐      ┌────────────────┐
│  MSSP Tenant   │      │ Customer 1     │      │ Customer 2     │
│                │      │                │      │                │
│  ┌──────────┐  │      │  ┌──────────┐  │      │  ┌──────────┐  │
│  │DefenderXSOAR│◄─────┤  │ Sentinel │  │      │  │ Sentinel │  │
│  │(App Reg)   │  │    │  └──────────┘  │      │  └──────────┘  │
│  └──────────┘  │      │                │      │                │
│                │      │  ┌──────────┐  │      │  ┌──────────┐  │
│                │◄─────┤  │ MDE/MDC  │  │      │  │ MDE/MDC  │  │
│                │      │  └──────────┘  │      │  └──────────┘  │
└────────────────┘      └────────────────┘      └────────────────┘
```

**Characteristics**:
- Central MSSP tenant hosts DefenderXSOAR
- Multi-tenant app registration
- Cross-tenant authentication
- Per-customer configuration

### Pattern 3: Hybrid (Customer-Owned + MSSP Managed)

```
┌────────────────┐      ┌────────────────┐
│ Customer Tenant│      │  MSSP Portal   │
│                │      │                │
│  ┌──────────┐  │      │  ┌──────────┐  │
│  │DefenderXSOAR│◄─────┤  │Monitoring│  │
│  │(Managed ID) │  │   │  │Dashboard │  │
│  └──────────┘  │      │  └──────────┘  │
│       │        │      │                │
│  ┌────▼─────┐  │      │                │
│  │ Sentinel │  │      │                │
│  └──────────┘  │      │                │
└────────────────┘      └────────────────┘
```

**Characteristics**:
- DefenderXSOAR deployed in customer tenant
- MSSP has monitoring access
- Customer maintains control
- Hybrid management model

## Security Architecture

### Authentication & Authorization

**Managed Identity Flow**:
```
Function App → System-Assigned Identity → Azure AD → API Permissions → Resource Access
```

**Multi-Tenant App Flow**:
```
Function App → App Registration (Cert) → Customer Azure AD → Admin Consent → Resource Access
```

### Network Security

**Inbound**:
- HTTPS only (port 443)
- Azure Front Door (optional)
- IP restrictions (optional)
- API keys for webhook triggers

**Outbound**:
- Microsoft service endpoints only
- No internet access required
- Service tags for firewall rules
- Private endpoints (Premium plan)

### Data Protection

**At Rest**:
- Storage account encryption (Microsoft-managed keys)
- Key Vault secrets encrypted
- Log Analytics data encrypted

**In Transit**:
- TLS 1.2 minimum
- Certificate pinning (optional)
- End-to-end encryption

**Data Residency**:
- All data processed in deployment region
- No cross-region transfers (default)
- GDPR compliance for EU deployments

### Secrets Management

```
Configuration File → Key Vault Secret → Function App Managed Identity → Runtime Access
```

**Secret Rotation**:
- Automatic detection of secret expiration
- Alert 30 days before expiry
- Zero-downtime secret rotation
- Versioned secrets in Key Vault

## Scalability & Performance

### Scaling Triggers

**Consumption Plan**:
- Queue depth
- HTTP request rate
- CPU utilization
- Memory pressure

**Premium Plan**:
- Pre-warmed instances (always on)
- Custom scaling rules
- VNet integration
- Dedicated compute

### Performance Optimization

**Parallel Execution**:
- Workers run in parallel (6 concurrent)
- Runspace pools for PowerShell
- Async API calls
- Result caching

**Token Caching**:
- In-memory token cache
- 55-minute TTL
- Per-resource tokens
- Reduces auth overhead

**API Throttling Handling**:
- Exponential backoff
- Retry with jitter
- Circuit breaker pattern
- Rate limit detection

### Capacity Planning

| Metric | Consumption | Premium EP1 | Premium EP2 |
|--------|-------------|-------------|-------------|
| Max Concurrent | 200 | 20 | 40 |
| Memory per Instance | 1.5 GB | 3.5 GB | 7 GB |
| Max Execution Time | 10 min | Unlimited | Unlimited |
| Cold Start | ~5 sec | ~1 sec | ~1 sec |
| Recommended Load | <100/day | 100-500/day | 500-2000/day |

## Monitoring Architecture

### Application Insights

**Trace Hierarchy**:
```
Request (HTTP Trigger)
  └─ Dependency (Azure AD Auth)
  └─ Trace (Brain Orchestration)
      └─ Dependency (MDE API)
      └─ Dependency (Graph API)
      └─ Trace (Risk Calculation)
  └─ Dependency (Log Analytics Write)
```

**Custom Events**:
- `EnrichmentStarted` - Incident received
- `WorkerCompleted` - Product worker finished
- `RiskScoreCalculated` - Final risk score
- `DecisionGenerated` - Auto-decision made
- `EnrichmentCompleted` - Full process done

### Alerting Strategy

**Critical Alerts**:
- Authentication failures (> 5 in 5 minutes)
- API rate limit exceeded
- Function execution failures (> 10%)
- Key Vault access denied

**Warning Alerts**:
- Slow performance (> 2 minutes avg)
- High API latency (> 5 seconds)
- Token refresh failures
- Memory pressure

**Informational Alerts**:
- Daily enrichment summary
- Unusual risk score patterns
- New entity types detected

## Disaster Recovery

### Backup Strategy

**Function Code**:
- Source control in Git
- ARM template versioned
- Deployment package in Storage

**Configuration**:
- Key Vault secrets backed up
- ARM template parameters
- Log Analytics queries exported

**Data**:
- Log Analytics retention (90 days default)
- Application Insights (90 days)
- No persistent state in Function App

### Recovery Procedures

**RTO (Recovery Time Objective)**: 30 minutes
**RPO (Recovery Point Objective)**: 0 (no data loss)

**Recovery Steps**:
1. Deploy ARM template to new region
2. Restore Key Vault secrets
3. Deploy function code
4. Update DNS/webhook endpoints
5. Validate with test incident

### High Availability

**Azure Functions**:
- Multi-instance deployment
- Zone redundancy (Premium plan)
- Automatic failover

**Dependencies**:
- Key Vault: 99.99% SLA
- Storage: 99.9% SLA (LRS)
- Application Insights: 99.9% SLA

## Cost Optimization

### Cost Breakdown (Estimated Monthly)

| Resource | Consumption | Premium EP1 |
|----------|-------------|-------------|
| Function App | $10-50 | $180 |
| Storage Account | $2-5 | $2-5 |
| Key Vault | $3 | $3 |
| Application Insights | $5-20 | $10-30 |
| Log Analytics | $10-50 | $20-100 |
| **Total** | **$30-130** | **$215-318** |

### Optimization Tips

1. **Use Consumption plan** for <100 incidents/day
2. **Configure data retention** appropriately
3. **Archive old logs** to cheaper storage
4. **Use sampling** in Application Insights
5. **Monitor unused resources**
6. **Right-size Log Analytics ingestion**

## Future Enhancements

### Roadmap Items

- **Real-time streaming** with Event Grid
- **Machine learning** risk scoring models
- **Graph-based** attack chain visualization
- **Mobile app** for incident response
- **Kubernetes deployment** option
- **On-premises** data connector

## References

- [Azure Functions Best Practices](https://docs.microsoft.com/azure/azure-functions/functions-best-practices)
- [Key Vault Security Baseline](https://docs.microsoft.com/security/benchmark/azure/baselines/key-vault-security-baseline)
- [Microsoft Defender APIs](https://docs.microsoft.com/microsoft-365/security/defender/api-overview)
- [Sentinel Automation](https://docs.microsoft.com/azure/sentinel/automate-incident-handling-with-automation-rules)
