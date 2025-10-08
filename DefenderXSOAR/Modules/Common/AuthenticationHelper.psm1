<#
.SYNOPSIS
    Authentication Helper module for DefenderXSOAR
.DESCRIPTION
    Provides centralized authentication functionality for all Defender products and Azure services
#>

# Module variables
$script:AccessTokenCache = @{}
$script:TenantConfigs = @{}

function Get-DefenderXSOARToken {
    <#
    .SYNOPSIS
        Gets access token for specified resource
    .PARAMETER TenantId
        Azure AD Tenant ID
    .PARAMETER ClientId
        Application Client ID
    .PARAMETER ClientSecret
        Application Client Secret
    .PARAMETER Resource
        Resource URL to get token for
    .PARAMETER Scope
        OAuth scope for the resource
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientSecret,
        
        [Parameter(Mandatory = $false)]
        [string]$Resource,
        
        [Parameter(Mandatory = $false)]
        [string]$Scope
    )
    
    try {
        $cacheKey = "$TenantId-$Resource-$Scope"
        
        # Check if token is cached and still valid
        if ($script:AccessTokenCache.ContainsKey($cacheKey)) {
            $cachedToken = $script:AccessTokenCache[$cacheKey]
            if ($cachedToken.ExpiresOn -gt (Get-Date).AddMinutes(5)) {
                Write-Verbose "Using cached token for $Resource"
                return $cachedToken.AccessToken
            }
        }
        
        $body = @{
            client_id     = $ClientId
            client_secret = $ClientSecret
            grant_type    = "client_credentials"
        }
        
        if ($Scope) {
            $body.Add("scope", $Scope)
        } elseif ($Resource) {
            $body.Add("resource", $Resource)
        }
        
        $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        
        $response = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        
        # Cache the token
        $script:AccessTokenCache[$cacheKey] = @{
            AccessToken = $response.access_token
            ExpiresOn   = (Get-Date).AddSeconds($response.expires_in)
        }
        
        return $response.access_token
    }
    catch {
        Write-Error "Failed to acquire token: $_"
        throw
    }
}

function Initialize-DefenderXSOARAuth {
    <#
    .SYNOPSIS
        Initializes authentication for a tenant
    .PARAMETER TenantConfig
        Hashtable containing tenant configuration
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$TenantConfig
    )
    
    try {
        $tenantId = $TenantConfig.TenantId
        
        # Store tenant configuration
        $script:TenantConfigs[$tenantId] = $TenantConfig
        
        Write-Verbose "Initialized authentication for tenant: $tenantId"
        
        return $true
    }
    catch {
        Write-Error "Failed to initialize authentication: $_"
        return $false
    }
}

function Get-GraphAPIToken {
    <#
    .SYNOPSIS
        Gets Microsoft Graph API access token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientSecret
    )
    
    return Get-DefenderXSOARToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -Scope "https://graph.microsoft.com/.default"
}

function Get-SecurityCenterToken {
    <#
    .SYNOPSIS
        Gets Microsoft Security Center API access token (for MDE)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientSecret
    )
    
    return Get-DefenderXSOARToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -Resource "https://api.securitycenter.microsoft.com"
}

function Get-AzureManagementToken {
    <#
    .SYNOPSIS
        Gets Azure Management API access token (for MDC)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientSecret
    )
    
    return Get-DefenderXSOARToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -Scope "https://management.azure.com/.default"
}

function Get-LogAnalyticsToken {
    <#
    .SYNOPSIS
        Gets Log Analytics API access token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientSecret
    )
    
    return Get-DefenderXSOARToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -Scope "https://api.loganalytics.io/.default"
}

function Clear-DefenderXSOARTokenCache {
    <#
    .SYNOPSIS
        Clears the token cache
    #>
    [CmdletBinding()]
    param()
    
    $script:AccessTokenCache = @{}
    Write-Verbose "Token cache cleared"
}

# Export module members
Export-ModuleMember -Function @(
    'Get-DefenderXSOARToken',
    'Initialize-DefenderXSOARAuth',
    'Get-GraphAPIToken',
    'Get-SecurityCenterToken',
    'Get-AzureManagementToken',
    'Get-LogAnalyticsToken',
    'Clear-DefenderXSOARTokenCache'
)
