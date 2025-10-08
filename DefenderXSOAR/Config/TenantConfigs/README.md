# Tenant Configurations

This directory contains tenant-specific configuration files for multi-tenant MSSP deployments.

## Structure

Each tenant should have its own JSON configuration file:

```
TenantConfigs/
├── tenant1.json
├── tenant2.json
└── tenant3.json
```

## Tenant Configuration Template

Create a file `{tenant-name}.json` with the following structure:

```json
{
  "TenantName": "Customer ABC",
  "TenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "ClientId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "ClientSecret": "your-secret-here",
  "SubscriptionId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "MCASUrl": "https://tenant.portal.cloudappsecurity.com",
  "MCASToken": "your-mcas-token",
  "Enabled": true,
  "Settings": {
    "AutoEscalate": true,
    "MinimumRiskScore": 70,
    "Products": ["MDE", "MDC", "MCAS", "MDI", "MDO", "EntraID"],
    "CustomRiskWeights": {
      "MDE": 1.3,
      "MDI": 1.4
    }
  }
}
```

## Security Best Practices

1. **Never commit secrets to source control**
   - Use Azure Key Vault for production
   - Use environment variables for CI/CD
   - Add `*.json` to `.gitignore` (except templates)

2. **Use separate service principals per tenant**
   - Isolate permissions
   - Easier revocation and rotation
   - Better audit trails

3. **Rotate secrets regularly**
   - Set up automated rotation
   - Use short-lived credentials when possible
   - Monitor for unauthorized access

4. **Encrypt configuration files**
   - Use Azure Key Vault
   - Or encrypt files at rest
   - Decrypt only when needed

## Loading Tenant Configurations

The main configuration file references tenant configs:

```json
{
  "Tenants": [
    {
      "ConfigFile": "./TenantConfigs/tenant1.json"
    },
    {
      "ConfigFile": "./TenantConfigs/tenant2.json"
    }
  ]
}
```

Or embed directly in the main config as shown in the default `DefenderXSOAR.json`.
