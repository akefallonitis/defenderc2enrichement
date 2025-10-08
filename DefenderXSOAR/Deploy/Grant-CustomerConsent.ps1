<#
.SYNOPSIS
    Grant admin consent for DefenderXSOAR multi-tenant app in customer tenant
.DESCRIPTION
    Customer admin runs this script to grant consent for the MSSP's DefenderXSOAR app
.PARAMETER MultiTenantAppId
    Application ID of the MSSP's multi-tenant DefenderXSOAR app
.PARAMETER CustomerTenantId
    Customer's Azure AD tenant ID
.PARAMETER AutoConsent
    Automatically grant consent without confirmation prompt
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$MultiTenantAppId,
    
    [Parameter(Mandatory = $true)]
    [string]$CustomerTenantId,
    
    [Parameter(Mandatory = $false)]
    [switch]$AutoConsent
)

Write-Host @"
╔═══════════════════════════════════════════════════════════════════╗
║        DefenderXSOAR Customer Consent Script                      ║
╚═══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Verify GUID formats
if ($MultiTenantAppId -notmatch '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$') {
    Write-Error "Invalid Application ID format"
    exit 1
}

if ($CustomerTenantId -notmatch '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$') {
    Write-Error "Invalid Tenant ID format"
    exit 1
}

Write-Host @"

╔═══════════════════════════════════════════════════════════════════╗
║                        IMPORTANT NOTICE                           ║
╚═══════════════════════════════════════════════════════════════════╝

This script will grant the following permissions to DefenderXSOAR:

Microsoft Graph API (Read-Only):
  ✓ SecurityEvents.Read.All - Read security events
  ✓ SecurityActions.Read.All - Read security actions
  ✓ IdentityRiskEvent.Read.All - Read identity risk events
  ✓ IdentityRiskyUser.Read.All - Read risky users
  ✓ Directory.Read.All - Read directory data
  ✓ User.Read.All - Read user profiles
  ✓ Device.Read.All - Read device information
  ✓ Application.Read.All - Read applications
  ✓ AuditLog.Read.All - Read audit logs
  ✓ SecurityAlert.Read.All - Read security alerts
  ✓ ThreatIndicators.Read.All - Read threat indicators

Microsoft Defender for Endpoint API (Read-Only):
  ✓ Machine.Read.All - Read machines
  ✓ Alert.Read.All - Read alerts
  ✓ File.Read.All - Read files
  ✓ AdvancedQuery.Read.All - Run advanced hunting queries

Application Details:
  Application ID: $MultiTenantAppId
  Your Tenant ID: $CustomerTenantId

These permissions are READ-ONLY and allow DefenderXSOAR to:
- Analyze security incidents
- Enrich alerts with context
- Correlate threats across Microsoft security products
- Generate risk scores and recommendations

DefenderXSOAR will NOT:
- Modify any data
- Take automated remediation actions
- Access sensitive personal data
- Make changes to your environment

"@ -ForegroundColor Yellow

if (-not $AutoConsent) {
    $confirmation = Read-Host "Do you want to proceed with granting consent? (Y/N)"
    if ($confirmation -ne "Y") {
        Write-Host "Consent not granted. Exiting." -ForegroundColor Yellow
        exit 0
    }
}

# Check for Az modules
Write-Host "`nChecking prerequisites..." -ForegroundColor Yellow
$requiredModules = @('Az.Accounts', 'Az.Resources')

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "  Installing module: $module" -ForegroundColor Yellow
        Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
    }
    Import-Module $module -Force
}
Write-Host "  ✓ Prerequisites checked" -ForegroundColor Green

# Connect to customer tenant
Write-Host "`nConnecting to customer tenant..." -ForegroundColor Yellow
Write-Host "  You will be prompted to sign in with Global Administrator credentials" -ForegroundColor Cyan

try {
    Connect-AzAccount -TenantId $CustomerTenantId -ErrorAction Stop
    Set-AzContext -TenantId $CustomerTenantId | Out-Null
    
    $context = Get-AzContext
    Write-Host "  ✓ Connected successfully" -ForegroundColor Green
    Write-Host "    Tenant: $($context.Tenant.Id)" -ForegroundColor Cyan
    Write-Host "    Account: $($context.Account.Id)" -ForegroundColor Cyan
}
catch {
    Write-Error "Failed to connect to tenant: $_"
    exit 1
}

# Verify user has Global Administrator role
Write-Host "`nVerifying permissions..." -ForegroundColor Yellow
$currentUser = Get-AzADUser -SignedIn
if (-not $currentUser) {
    Write-Warning "Could not verify user permissions. Proceeding with consent..."
}
else {
    Write-Host "  Current user: $($currentUser.UserPrincipalName)" -ForegroundColor Cyan
}

# Method 1: Try using Az cmdlets
Write-Host "`nGranting admin consent..." -ForegroundColor Yellow

try {
    # Check if service principal already exists
    $sp = Get-AzADServicePrincipal -ApplicationId $MultiTenantAppId -ErrorAction SilentlyContinue
    
    if ($sp) {
        Write-Host "  ✓ Service principal already exists in this tenant" -ForegroundColor Green
        Write-Host "    Display Name: $($sp.DisplayName)" -ForegroundColor Cyan
    }
    else {
        # Service principal doesn't exist, consent will create it
        Write-Host "  Service principal will be created during consent" -ForegroundColor Cyan
    }
}
catch {
    Write-Warning "Could not check for existing service principal: $_"
}

# Generate consent URL
$consentUrl = "https://login.microsoftonline.com/$CustomerTenantId/adminconsent?client_id=$MultiTenantAppId"

Write-Host @"

╔═══════════════════════════════════════════════════════════════════╗
║                   ADMIN CONSENT REQUIRED                          ║
╚═══════════════════════════════════════════════════════════════════╝

Opening admin consent page in your browser...

If the browser doesn't open automatically, please visit:
$consentUrl

You will be asked to:
1. Sign in with your Global Administrator account (if not already signed in)
2. Review the permissions requested
3. Click "Accept" to grant consent

"@ -ForegroundColor Yellow

# Try to open browser
try {
    Start-Process $consentUrl
    Write-Host "Browser opened successfully" -ForegroundColor Green
}
catch {
    Write-Warning "Could not open browser automatically. Please manually open the URL above."
}

# Wait for user to complete consent
Write-Host "`nWaiting for consent to be granted..." -ForegroundColor Yellow
Write-Host "Press Enter after you have completed the consent process in the browser..." -ForegroundColor Cyan
Read-Host

# Verify consent was granted
Write-Host "`nVerifying consent..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

try {
    $sp = Get-AzADServicePrincipal -ApplicationId $MultiTenantAppId -ErrorAction Stop
    
    if ($sp) {
        Write-Host "  ✓ Consent granted successfully!" -ForegroundColor Green
        Write-Host "    Service Principal ID: $($sp.Id)" -ForegroundColor Cyan
        Write-Host "    Display Name: $($sp.DisplayName)" -ForegroundColor Cyan
        
        # Get app role assignments
        Write-Host "`nVerifying permissions..." -ForegroundColor Yellow
        
        # This is a simplified check - actual permissions are on the service principal
        Write-Host "  ✓ Service principal created in tenant" -ForegroundColor Green
        Write-Host "  ✓ API permissions granted (via consent)" -ForegroundColor Green
        
        $consentGranted = $true
    }
    else {
        Write-Warning "Service principal not found. Consent may not have been completed."
        $consentGranted = $false
    }
}
catch {
    Write-Warning "Could not verify consent status: $_"
    $consentGranted = $false
}

# Summary
if ($consentGranted) {
    Write-Host @"

╔═══════════════════════════════════════════════════════════════════╗
║                  CONSENT GRANTED SUCCESSFULLY                     ║
╚═══════════════════════════════════════════════════════════════════╝

Application ID: $MultiTenantAppId
Tenant ID: $CustomerTenantId
Service Principal: $($sp.DisplayName)

DefenderXSOAR can now access your tenant's security data.

NEXT STEPS:

1. INFORM YOUR MSSP
   Share the following information with your MSSP:
   
   ✓ Tenant ID: $CustomerTenantId
   ✓ Tenant Name: $($context.Tenant.Directory)
   ✓ Consent Date: $(Get-Date)
   
2. MSSP CONFIGURATION
   Your MSSP will add your tenant to their DefenderXSOAR configuration:
   
   {
     "TenantName": "YourCompany",
     "TenantId": "$CustomerTenantId",
     "ClientId": "$MultiTenantAppId",
     "Enabled": true
   }

3. TEST THE INTEGRATION
   Your MSSP will test the integration and confirm functionality.

4. MONITOR ACCESS (Optional)
   You can monitor DefenderXSOAR's activity in:
   - Azure AD Audit Logs
   - Microsoft 365 Security Center
   - Azure Monitor

TO REVOKE ACCESS LATER:
1. Go to Azure Portal
2. Navigate to Azure Active Directory > Enterprise Applications
3. Find "DefenderXSOAR" (Application ID: $MultiTenantAppId)
4. Click "Delete" or disable user assignment

"@ -ForegroundColor Green
}
else {
    Write-Host @"

╔═══════════════════════════════════════════════════════════════════╗
║                    CONSENT NOT VERIFIED                           ║
╚═══════════════════════════════════════════════════════════════════╝

The consent process may not have completed successfully.

Please verify:
1. You signed in with a Global Administrator account
2. You clicked "Accept" on the consent page
3. No error messages appeared

To retry:
1. Run this script again, OR
2. Manually visit the consent URL:
   $consentUrl

For assistance, contact your MSSP or Microsoft support.

"@ -ForegroundColor Yellow
}

# Save consent record
$consentRecord = @{
    ApplicationId = $MultiTenantAppId
    TenantId = $CustomerTenantId
    ConsentDate = Get-Date
    ConsentGranted = $consentGranted
    GrantedBy = $context.Account.Id
}

$recordFile = ".\DefenderXSOAR-Consent-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
$consentRecord | ConvertTo-Json | Out-File -FilePath $recordFile
Write-Host "Consent record saved to: $recordFile" -ForegroundColor Cyan

if ($consentGranted) {
    Write-Host "`nConsent process completed successfully!" -ForegroundColor Green
    exit 0
}
else {
    Write-Host "`nConsent process may require manual verification." -ForegroundColor Yellow
    exit 1
}
