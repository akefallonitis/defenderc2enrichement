<#
.SYNOPSIS
    Create a multi-tenant Azure AD app registration for DefenderXSOAR
.DESCRIPTION
    Creates an app registration configured for multi-tenant MSSP scenarios with required API permissions
.PARAMETER AppName
    Name for the app registration (default: DefenderXSOAR-MultiTenant)
.PARAMETER TenantId
    MSSP tenant ID where the app will be created
.PARAMETER UseCertificate
    Use certificate-based authentication instead of client secret (recommended)
.PARAMETER CertificateSubject
    Certificate subject name (default: CN=DefenderXSOAR)
.PARAMETER CertificateValidityYears
    Certificate validity in years (default: 2)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$AppName = "DefenderXSOAR-MultiTenant",
    
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [switch]$UseCertificate,
    
    [Parameter(Mandatory = $false)]
    [string]$CertificateSubject = "CN=DefenderXSOAR",
    
    [Parameter(Mandatory = $false)]
    [int]$CertificateValidityYears = 2
)

Write-Host @"
╔═══════════════════════════════════════════════════════════════════╗
║      DefenderXSOAR Multi-Tenant App Registration Script          ║
╚═══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Check for required modules
Write-Host "`nChecking prerequisites..." -ForegroundColor Yellow
$requiredModules = @('Az.Accounts', 'Az.Resources')

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "  Installing module: $module" -ForegroundColor Yellow
        Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
    }
    Import-Module $module -Force
    Write-Host "  ✓ $module loaded" -ForegroundColor Green
}

# Connect to Azure
Write-Host "`nConnecting to Azure..." -ForegroundColor Yellow
Connect-AzAccount -TenantId $TenantId
Set-AzContext -TenantId $TenantId

$context = Get-AzContext
Write-Host "  ✓ Connected to tenant: $($context.Tenant.Id)" -ForegroundColor Green
Write-Host "  Account: $($context.Account.Id)" -ForegroundColor Cyan

# Check if app already exists
Write-Host "`nChecking for existing app registration..." -ForegroundColor Yellow
$existingApp = Get-AzADApplication -DisplayName $AppName -ErrorAction SilentlyContinue

if ($existingApp) {
    Write-Warning "App registration '$AppName' already exists!"
    $response = Read-Host "Do you want to update it? (Y/N)"
    if ($response -ne "Y") {
        Write-Host "Exiting without changes." -ForegroundColor Yellow
        exit 0
    }
    $app = $existingApp
    Write-Host "  ✓ Using existing app: $($app.AppId)" -ForegroundColor Green
}
else {
    # Create new app registration
    Write-Host "`nCreating app registration..." -ForegroundColor Yellow
    
    $app = New-AzADApplication `
        -DisplayName $AppName `
        -SignInAudience "AzureADMultipleOrgs" `
        -ErrorAction Stop
    
    Write-Host "  ✓ App registration created" -ForegroundColor Green
    Write-Host "    Application ID: $($app.AppId)" -ForegroundColor Cyan
    Write-Host "    Object ID: $($app.Id)" -ForegroundColor Cyan
}

# Create service principal if it doesn't exist
Write-Host "`nCreating service principal..." -ForegroundColor Yellow
$sp = Get-AzADServicePrincipal -ApplicationId $app.AppId -ErrorAction SilentlyContinue

if (-not $sp) {
    $sp = New-AzADServicePrincipal -ApplicationId $app.AppId -ErrorAction Stop
    Write-Host "  ✓ Service principal created" -ForegroundColor Green
}
else {
    Write-Host "  ✓ Service principal already exists" -ForegroundColor Green
}

# Configure authentication
if ($UseCertificate) {
    Write-Host "`nConfiguring certificate-based authentication..." -ForegroundColor Yellow
    
    # Create self-signed certificate
    $cert = New-SelfSignedCertificate `
        -Subject $CertificateSubject `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyExportPolicy Exportable `
        -KeySpec Signature `
        -KeyLength 2048 `
        -KeyAlgorithm RSA `
        -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddYears($CertificateValidityYears)
    
    Write-Host "  ✓ Certificate created" -ForegroundColor Green
    Write-Host "    Thumbprint: $($cert.Thumbprint)" -ForegroundColor Cyan
    Write-Host "    Expires: $($cert.NotAfter)" -ForegroundColor Cyan
    
    # Upload certificate to app registration
    $keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())
    $keyCredential = @{
        Type = "AsymmetricX509Cert"
        Usage = "Verify"
        Key = [System.Text.Encoding]::UTF8.GetBytes($keyValue)
    }
    
    Update-AzADApplication -ObjectId $app.Id -KeyCredentials $keyCredential
    Write-Host "  ✓ Certificate uploaded to app registration" -ForegroundColor Green
    
    # Export certificate for deployment
    $certPath = ".\DefenderXSOAR-Certificate.pfx"
    $certPassword = Read-Host "Enter password for certificate export" -AsSecureString
    Export-PfxCertificate -Cert $cert -FilePath $certPath -Password $certPassword | Out-Null
    
    Write-Host "  ✓ Certificate exported to: $certPath" -ForegroundColor Green
    Write-Host "    IMPORTANT: Store this certificate securely!" -ForegroundColor Red
}
else {
    Write-Host "`nConfiguring client secret authentication..." -ForegroundColor Yellow
    
    # Create client secret
    $secret = New-AzADAppCredential `
        -ApplicationId $app.AppId `
        -EndDate (Get-Date).AddYears(2) `
        -ErrorAction Stop
    
    Write-Host "  ✓ Client secret created" -ForegroundColor Green
    Write-Host "    Secret: $($secret.SecretText)" -ForegroundColor Cyan
    Write-Host "    Expires: $($secret.EndDateTime)" -ForegroundColor Cyan
    Write-Host "    IMPORTANT: Save this secret - it won't be shown again!" -ForegroundColor Red
}

# Add API permissions
Write-Host "`nAdding API permissions..." -ForegroundColor Yellow

$requiredResourceAccess = @()

# Microsoft Graph
$graphResourceId = "00000003-0000-0000-c000-000000000000"
$graphPermissions = @(
    "bf394140-e372-4bf9-a898-299cfc7564e5", # SecurityEvents.Read.All
    "5e0edab9-c148-49d0-b423-ac253e121825", # SecurityActions.Read.All
    "6e472fd1-ad78-48da-a0f0-97ab2c6b769e", # IdentityRiskEvent.Read.All
    "dc5007c0-2d7d-4c42-879c-2dab87571379", # IdentityRiskyUser.Read.All
    "7ab1d382-f21e-4acd-a863-ba3e13f7da61", # Directory.Read.All
    "df021288-bdef-4463-88db-98f22de89214", # User.Read.All
    "7438b122-aefc-4978-80ed-43db9fcc7715", # Device.Read.All
    "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30", # Application.Read.All
    "b0afded3-3588-46d8-8b3d-9842eff778da", # AuditLog.Read.All
    "45cc0394-e837-488b-a098-1918f48d186c", # SecurityAlert.Read.All
    "197ee4e9-b993-4066-898f-d6aecc55125b"  # ThreatIndicators.Read.All
)

$graphAccess = @{
    ResourceAppId = $graphResourceId
    ResourceAccess = $graphPermissions | ForEach-Object {
        @{
            Id = $_
            Type = "Role"
        }
    }
}
$requiredResourceAccess += $graphAccess

# Microsoft Defender for Endpoint
$mdeResourceId = "fc780465-2017-40d4-a0c5-307022471b92"
$mdePermissions = @(
    "ea8291d3-4b9a-44b5-bc3a-6cea3026dc79", # Machine.Read.All
    "3b14d7f8-5c27-4d2e-9e67-7b1b6b9f0b3a", # Alert.Read.All
    "7734e8e5-8dde-42fc-b5ae-6eafea078693", # File.Read.All
    "b152f2ba-5d6d-4b0d-8c1e-1e0e4c1c1e0e"  # AdvancedQuery.Read.All
)

$mdeAccess = @{
    ResourceAppId = $mdeResourceId
    ResourceAccess = $mdePermissions | ForEach-Object {
        @{
            Id = $_
            Type = "Role"
        }
    }
}
$requiredResourceAccess += $mdeAccess

# Update app with permissions
Update-AzADApplication -ObjectId $app.Id -RequiredResourceAccess $requiredResourceAccess
Write-Host "  ✓ API permissions added" -ForegroundColor Green

# Display consent URL
$consentUrl = "https://login.microsoftonline.com/$TenantId/adminconsent?client_id=$($app.AppId)"

Write-Host @"

╔═══════════════════════════════════════════════════════════════════╗
║              APP REGISTRATION CREATED                             ║
╚═══════════════════════════════════════════════════════════════════╝

Application Name: $AppName
Application (Client) ID: $($app.AppId)
Object ID: $($app.Id)
Tenant ID: $TenantId

Authentication Method: $(if ($UseCertificate) { "Certificate" } else { "Client Secret" })
"@ -ForegroundColor Green

if ($UseCertificate) {
    Write-Host @"
Certificate Details:
  Thumbprint: $($cert.Thumbprint)
  Expires: $($cert.NotAfter)
  Exported to: $certPath
  
To use the certificate in Azure Functions:
1. Upload the PFX file to Azure Key Vault
2. Grant Function App access to the certificate
3. Configure Function App to use certificate authentication
"@ -ForegroundColor Cyan
}
else {
    Write-Host @"
Client Secret: $($secret.SecretText)
Secret Expires: $($secret.EndDateTime)

IMPORTANT: Save this secret immediately - it won't be shown again!
"@ -ForegroundColor Cyan
}

Write-Host @"

╔═══════════════════════════════════════════════════════════════════╗
║                   NEXT STEPS                                      ║
╚═══════════════════════════════════════════════════════════════════╝

1. GRANT ADMIN CONSENT IN MSSP TENANT
   Open this URL in your browser (requires Global Administrator):
   
   $consentUrl
   
   Or use Azure CLI:
   az ad app permission admin-consent --id $($app.AppId)

2. GRANT CONSENT IN EACH CUSTOMER TENANT
   For each customer tenant, have their admin run:
   
   .\Grant-CustomerConsent.ps1 ``
       -MultiTenantAppId "$($app.AppId)" ``
       -CustomerTenantId "<customer-tenant-id>"
   
   Or share this URL with customer admin:
   https://login.microsoftonline.com/<customer-tenant-id>/adminconsent?client_id=$($app.AppId)

3. UPDATE DEFENDERXSOAR CONFIGURATION
   Add to your DefenderXSOAR configuration:
   
   {
     "Tenants": [
       {
         "TenantName": "Customer1",
         "TenantId": "<customer-tenant-id>",
         "ClientId": "$($app.AppId)",
"@ -ForegroundColor Yellow

if ($UseCertificate) {
    Write-Host @"
         "CertificateThumbprint": "$($cert.Thumbprint)",
         "UseCertificate": true,
"@ -ForegroundColor Yellow
}
else {
    Write-Host @"
         "ClientSecret": "$($secret.SecretText)",
"@ -ForegroundColor Yellow
}

Write-Host @"
         "Enabled": true
       }
     ]
   }

4. DEPLOY TO AZURE
   Use the ARM template deployment with multi-tenant app ID:
   
   New-AzResourceGroupDeployment ``
       -ResourceGroupName "DefenderXSOAR-RG" ``
       -TemplateFile ".\defenderxsoar-deploy.json" ``
       -MultiTenantAppId "$($app.AppId)"

5. TEST THE SETUP
   After deployment, test authentication to each tenant:
   
   .\Test-DefenderXSOAR.ps1 ``
       -FunctionAppName "defenderxsoar-func" ``
       -ResourceGroupName "DefenderXSOAR-RG"

"@ -ForegroundColor Yellow

# Save details to file
$outputFile = ".\DefenderXSOAR-AppRegistration-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
$appDetails = @{
    ApplicationId = $app.AppId
    ObjectId = $app.Id
    TenantId = $TenantId
    ApplicationName = $AppName
    AuthenticationMethod = if ($UseCertificate) { "Certificate" } else { "ClientSecret" }
    ConsentUrl = $consentUrl
    CreatedDate = Get-Date
}

if ($UseCertificate) {
    $appDetails.CertificateThumbprint = $cert.Thumbprint
    $appDetails.CertificateExpires = $cert.NotAfter
    $appDetails.CertificatePath = $certPath
}
else {
    $appDetails.ClientSecret = $secret.SecretText
    $appDetails.SecretExpires = $secret.EndDateTime
}

$appDetails | ConvertTo-Json | Out-File -FilePath $outputFile
Write-Host "App registration details saved to: $outputFile" -ForegroundColor Green

Write-Host "`nMulti-tenant app registration completed successfully!" -ForegroundColor Green
