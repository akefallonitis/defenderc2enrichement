<#
.SYNOPSIS
    Entity Normalizer module for DefenderXSOAR
.DESCRIPTION
    Provides entity normalization and unification across different Defender products
#>

function ConvertTo-NormalizedEntity {
    <#
    .SYNOPSIS
        Converts raw entity data to normalized format
    .PARAMETER EntityData
        Raw entity data from various sources
    .PARAMETER EntityType
        Type of entity (User, Device, IP, File, etc.)
    .PARAMETER Source
        Source product (MDE, MDC, MCAS, MDI, MDO, EntraID)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$EntityData,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('User', 'Account', 'Device', 'Host', 'IP', 'File', 'URL', 'Process', 'MailMessage', 'Mailbox', 'CloudApp', 'AzureResource', 'Registry', 'DNS')]
        [string]$EntityType,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('MDE', 'MDC', 'MCAS', 'MDI', 'MDO', 'EntraID', 'Sentinel')]
        [string]$Source
    )
    
    $normalizedEntity = @{
        EntityType      = $EntityType
        Source          = $Source
        RawData         = $EntityData
        NormalizedData  = @{}
        Timestamp       = Get-Date -Format "o"
        CorrelationId   = [guid]::NewGuid().ToString()
    }
    
    switch ($EntityType) {
        'User' {
            $normalizedEntity.NormalizedData = Get-NormalizedUser -EntityData $EntityData -Source $Source
        }
        'Account' {
            $normalizedEntity.NormalizedData = Get-NormalizedAccount -EntityData $EntityData -Source $Source
        }
        'Device' {
            $normalizedEntity.NormalizedData = Get-NormalizedDevice -EntityData $EntityData -Source $Source
        }
        'Host' {
            $normalizedEntity.NormalizedData = Get-NormalizedHost -EntityData $EntityData -Source $Source
        }
        'IP' {
            $normalizedEntity.NormalizedData = Get-NormalizedIP -EntityData $EntityData -Source $Source
        }
        'File' {
            $normalizedEntity.NormalizedData = Get-NormalizedFile -EntityData $EntityData -Source $Source
        }
        'URL' {
            $normalizedEntity.NormalizedData = Get-NormalizedURL -EntityData $EntityData -Source $Source
        }
        'Process' {
            $normalizedEntity.NormalizedData = Get-NormalizedProcess -EntityData $EntityData -Source $Source
        }
        'MailMessage' {
            $normalizedEntity.NormalizedData = Get-NormalizedMailMessage -EntityData $EntityData -Source $Source
        }
        'Mailbox' {
            $normalizedEntity.NormalizedData = Get-NormalizedMailbox -EntityData $EntityData -Source $Source
        }
        'CloudApp' {
            $normalizedEntity.NormalizedData = Get-NormalizedCloudApp -EntityData $EntityData -Source $Source
        }
        'AzureResource' {
            $normalizedEntity.NormalizedData = Get-NormalizedAzureResource -EntityData $EntityData -Source $Source
        }
        'Registry' {
            $normalizedEntity.NormalizedData = Get-NormalizedRegistry -EntityData $EntityData -Source $Source
        }
        'DNS' {
            $normalizedEntity.NormalizedData = Get-NormalizedDNS -EntityData $EntityData -Source $Source
        }
    }
    
    return $normalizedEntity
}

function Get-NormalizedUser {
    [CmdletBinding()]
    param($EntityData, $Source)
    
    $normalized = @{
        UserPrincipalName = $null
        DisplayName       = $null
        ObjectId          = $null
        OnPremisesSid     = $null
        RiskLevel         = 'Unknown'
        Accounts          = @()
    }
    
    switch ($Source) {
        'EntraID' {
            $normalized.UserPrincipalName = $EntityData.userPrincipalName
            $normalized.DisplayName = $EntityData.displayName
            $normalized.ObjectId = $EntityData.id
        }
        'MDE' {
            $normalized.UserPrincipalName = $EntityData.accountName
            $normalized.OnPremisesSid = $EntityData.accountSid
        }
        'MCAS' {
            $normalized.UserPrincipalName = $EntityData.username
        }
        'MDI' {
            $normalized.UserPrincipalName = $EntityData.accountName
            $normalized.OnPremisesSid = $EntityData.sid
        }
    }
    
    return $normalized
}

function Get-NormalizedDevice {
    [CmdletBinding()]
    param($EntityData, $Source)
    
    $normalized = @{
        DeviceName       = $null
        DeviceId         = $null
        OSPlatform       = $null
        IPAddresses      = @()
        MACAddresses     = @()
        RiskScore        = 0
        HealthStatus     = 'Unknown'
        OnboardingStatus = 'Unknown'
    }
    
    switch ($Source) {
        'MDE' {
            $normalized.DeviceName = $EntityData.computerDnsName
            $normalized.DeviceId = $EntityData.id
            $normalized.OSPlatform = $EntityData.osPlatform
            $normalized.RiskScore = if ($EntityData.riskScore) { $EntityData.riskScore } else { 0 }
            $normalized.HealthStatus = $EntityData.healthStatus
            $normalized.OnboardingStatus = $EntityData.onboardingStatus
        }
        'MDC' {
            $normalized.DeviceName = $EntityData.properties.displayName
            $normalized.DeviceId = $EntityData.id
        }
        'EntraID' {
            $normalized.DeviceName = $EntityData.displayName
            $normalized.DeviceId = $EntityData.deviceId
            $normalized.OSPlatform = $EntityData.operatingSystem
        }
    }
    
    return $normalized
}

function Get-NormalizedIP {
    [CmdletBinding()]
    param($EntityData, $Source)
    
    $normalized = @{
        IPAddress     = $null
        GeoLocation   = @{}
        ThreatIntel   = @{}
        IsPrivate     = $false
        IsPublic      = $false
    }
    
    if ($EntityData -is [string]) {
        $normalized.IPAddress = $EntityData
    } else {
        $normalized.IPAddress = $EntityData.address ?? $EntityData.ipAddress ?? $EntityData.ip
    }
    
    # Determine if IP is private
    $normalized.IsPrivate = Test-PrivateIP -IPAddress $normalized.IPAddress
    $normalized.IsPublic = -not $normalized.IsPrivate
    
    return $normalized
}

function Get-NormalizedFile {
    [CmdletBinding()]
    param($EntityData, $Source)
    
    $normalized = @{
        FileName        = $null
        FilePath        = $null
        FileHash        = @{
            MD5    = $null
            SHA1   = $null
            SHA256 = $null
        }
        FileSize        = 0
        FileType        = $null
        ThreatName      = $null
        Verdict         = 'Unknown'
    }
    
    switch ($Source) {
        'MDE' {
            $normalized.FileName = $EntityData.fileName
            $normalized.FilePath = $EntityData.filePath
            $normalized.FileHash.SHA1 = $EntityData.sha1
            $normalized.FileHash.SHA256 = $EntityData.sha256
            $normalized.FileSize = $EntityData.size
        }
        'MDO' {
            $normalized.FileName = $EntityData.fileName
            $normalized.FileHash.SHA256 = $EntityData.sha256
            $normalized.ThreatName = $EntityData.threatName
        }
    }
    
    return $normalized
}

function Get-NormalizedURL {
    [CmdletBinding()]
    param($EntityData, $Source)
    
    $normalized = @{
        URL         = $null
        Domain      = $null
        ThreatIntel = @{}
        Categories  = @()
    }
    
    if ($EntityData -is [string]) {
        $normalized.URL = $EntityData
    } else {
        $normalized.URL = $EntityData.url ?? $EntityData.uri
    }
    
    if ($normalized.URL) {
        try {
            $uri = [System.Uri]$normalized.URL
            $normalized.Domain = $uri.Host
        } catch {
            Write-Verbose "Failed to parse URL: $($normalized.URL)"
        }
    }
    
    return $normalized
}

function Get-NormalizedProcess {
    [CmdletBinding()]
    param($EntityData, $Source)
    
    $normalized = @{
        ProcessName        = $null
        ProcessId          = $null
        CommandLine        = $null
        ParentProcessName  = $null
        ParentProcessId    = $null
        CreationTime       = $null
        AccountName        = $null
    }
    
    switch ($Source) {
        'MDE' {
            $normalized.ProcessName = $EntityData.fileName
            $normalized.ProcessId = $EntityData.processId
            $normalized.CommandLine = $EntityData.processCommandLine
            $normalized.CreationTime = $EntityData.processCreationTime
            $normalized.AccountName = $EntityData.accountName
        }
    }
    
    return $normalized
}

function Get-NormalizedMailMessage {
    [CmdletBinding()]
    param($EntityData, $Source)
    
    $normalized = @{
        MessageId        = $null
        Subject          = $null
        Sender           = $null
        Recipients       = @()
        AttachmentCount  = 0
        ThreatTypes      = @()
        DeliveryAction   = $null
        InternetMessageId = $null
    }
    
    switch ($Source) {
        'MDO' {
            $normalized.MessageId = $EntityData.networkMessageId
            $normalized.Subject = $EntityData.subject
            $normalized.Sender = $EntityData.senderFromAddress
            $normalized.Recipients = $EntityData.recipientEmailAddress
            $normalized.ThreatTypes = $EntityData.threatTypes
            $normalized.DeliveryAction = $EntityData.deliveryAction
            $normalized.InternetMessageId = $EntityData.internetMessageId
        }
    }
    
    return $normalized
}

function Get-NormalizedCloudApp {
    [CmdletBinding()]
    param($EntityData, $Source)
    
    $normalized = @{
        AppName      = $null
        AppId        = $null
        RiskScore    = 0
        Categories   = @()
        Permissions  = @()
    }
    
    switch ($Source) {
        'MCAS' {
            $normalized.AppName = $EntityData.name
            $normalized.AppId = $EntityData.id
            $normalized.RiskScore = $EntityData.riskScore
            $normalized.Categories = $EntityData.categories
        }
    }
    
    return $normalized
}

function Get-NormalizedAzureResource {
    [CmdletBinding()]
    param($EntityData, $Source)
    
    $normalized = @{
        ResourceId       = $null
        ResourceName     = $null
        ResourceType     = $null
        ResourceGroup    = $null
        Subscription     = $null
        Location         = $null
        SecurityScore    = 0
    }
    
    switch ($Source) {
        'MDC' {
            $normalized.ResourceId = $EntityData.id
            $normalized.ResourceName = $EntityData.name
            $normalized.ResourceType = $EntityData.type
            $normalized.Location = $EntityData.location
        }
    }
    
    return $normalized
}

function Get-NormalizedAccount {
    <#
    .SYNOPSIS
        Normalizes Account entity with official Microsoft Sentinel schema
    .DESCRIPTION
        Account entity includes: UPN, ObjectGUID, SID, AADUserId, NTDomain, DnsDomain
    #>
    [CmdletBinding()]
    param($EntityData, $Source)
    
    $normalized = @{
        UPN           = $null
        ObjectGUID    = $null
        SID           = $null
        AADUserId     = $null
        NTDomain      = $null
        DnsDomain     = $null
        DisplayName   = $null
        AccountName   = $null
    }
    
    switch ($Source) {
        'EntraID' {
            $normalized.UPN = $EntityData.userPrincipalName
            $normalized.AADUserId = $EntityData.id
            $normalized.DisplayName = $EntityData.displayName
            $normalized.ObjectGUID = $EntityData.id
        }
        'MDE' {
            $normalized.AccountName = $EntityData.accountName
            $normalized.SID = $EntityData.accountSid
            $normalized.NTDomain = $EntityData.accountDomain
        }
        'MDI' {
            $normalized.AccountName = $EntityData.accountName
            $normalized.SID = $EntityData.sid
            $normalized.NTDomain = $EntityData.domainName
        }
    }
    
    return $normalized
}

function Get-NormalizedHost {
    <#
    .SYNOPSIS
        Normalizes Host entity with official Microsoft Sentinel schema
    .DESCRIPTION
        Host entity includes: Hostname, NetBiosName, AzureID, OMSAgentID, OSVersion
    #>
    [CmdletBinding()]
    param($EntityData, $Source)
    
    $normalized = @{
        Hostname         = $null
        NetBiosName      = $null
        AzureID          = $null
        OMSAgentID       = $null
        OSVersion        = $null
        OSPlatform       = $null
        IPAddresses      = @()
        MACAddresses     = @()
        RiskScore        = 0
        HealthStatus     = 'Unknown'
    }
    
    switch ($Source) {
        'MDE' {
            $normalized.Hostname = $EntityData.computerDnsName
            $normalized.AzureID = $EntityData.azureAdDeviceId
            $normalized.OSVersion = $EntityData.osVersion
            $normalized.OSPlatform = $EntityData.osPlatform
            $normalized.RiskScore = if ($EntityData.riskScore) { $EntityData.riskScore } else { 0 }
            $normalized.HealthStatus = $EntityData.healthStatus
        }
        'MDC' {
            $normalized.Hostname = $EntityData.properties.displayName
            $normalized.AzureID = $EntityData.properties.azureResourceId
        }
        'EntraID' {
            $normalized.Hostname = $EntityData.displayName
            $normalized.AzureID = $EntityData.deviceId
            $normalized.OSVersion = $EntityData.operatingSystemVersion
            $normalized.OSPlatform = $EntityData.operatingSystem
        }
    }
    
    return $normalized
}

function Get-NormalizedMailbox {
    <#
    .SYNOPSIS
        Normalizes Mailbox entity with official Microsoft Sentinel schema
    .DESCRIPTION
        Mailbox entity includes: DisplayName, Alias, MailboxGuid, UPN
    #>
    [CmdletBinding()]
    param($EntityData, $Source)
    
    $normalized = @{
        DisplayName     = $null
        Alias           = $null
        MailboxGuid     = $null
        UPN             = $null
        PrimarySmtpAddress = $null
    }
    
    switch ($Source) {
        'MDO' {
            $normalized.DisplayName = $EntityData.displayName
            $normalized.UPN = $EntityData.userPrincipalName
            $normalized.PrimarySmtpAddress = $EntityData.primarySmtpAddress
            $normalized.MailboxGuid = $EntityData.mailboxGuid
        }
        'EntraID' {
            $normalized.DisplayName = $EntityData.displayName
            $normalized.UPN = $EntityData.userPrincipalName
            $normalized.PrimarySmtpAddress = $EntityData.mail
        }
    }
    
    return $normalized
}

function Get-NormalizedRegistry {
    <#
    .SYNOPSIS
        Normalizes Registry entity with official Microsoft Sentinel schema
    .DESCRIPTION
        Registry entity includes: RegistryKey, RegistryHive, RegistryValueName, RegistryValueData
    #>
    [CmdletBinding()]
    param($EntityData, $Source)
    
    $normalized = @{
        RegistryKey        = $null
        RegistryHive       = $null
        RegistryValueName  = $null
        RegistryValueData  = $null
        RegistryValueType  = $null
    }
    
    switch ($Source) {
        'MDE' {
            $normalized.RegistryKey = $EntityData.registryKey
            $normalized.RegistryHive = $EntityData.registryHive
            $normalized.RegistryValueName = $EntityData.registryValueName
            $normalized.RegistryValueData = $EntityData.registryValueData
            $normalized.RegistryValueType = $EntityData.registryValueType
        }
    }
    
    return $normalized
}

function Get-NormalizedDNS {
    <#
    .SYNOPSIS
        Normalizes DNS entity with official Microsoft Sentinel schema
    .DESCRIPTION
        DNS entity includes: DomainName, DnsServerIP, QueryType, QueryResult
    #>
    [CmdletBinding()]
    param($EntityData, $Source)
    
    $normalized = @{
        DomainName      = $null
        DnsServerIP     = $null
        QueryType       = $null
        QueryResult     = @()
        QueryStatus     = $null
    }
    
    switch ($Source) {
        'MDE' {
            $normalized.DomainName = $EntityData.domainName
            $normalized.DnsServerIP = $EntityData.dnsServerIp
            $normalized.QueryType = $EntityData.queryType
            $normalized.QueryResult = $EntityData.resolvedIpAddresses
        }
    }
    
    return $normalized
}

function Test-PrivateIP {
    [CmdletBinding()]
    param([string]$IPAddress)
    
    try {
        $ip = [System.Net.IPAddress]::Parse($IPAddress)
        $bytes = $ip.GetAddressBytes()
        
        # Check for private IP ranges
        if ($bytes[0] -eq 10) { return $true }
        if ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) { return $true }
        if ($bytes[0] -eq 192 -and $bytes[1] -eq 168) { return $true }
        if ($bytes[0] -eq 127) { return $true }
        
        return $false
    }
    catch {
        return $false
    }
}

# Export module members
Export-ModuleMember -Function @(
    'ConvertTo-NormalizedEntity',
    'Get-NormalizedUser',
    'Get-NormalizedAccount',
    'Get-NormalizedDevice',
    'Get-NormalizedHost',
    'Get-NormalizedIP',
    'Get-NormalizedFile',
    'Get-NormalizedURL',
    'Get-NormalizedProcess',
    'Get-NormalizedMailMessage',
    'Get-NormalizedMailbox',
    'Get-NormalizedCloudApp',
    'Get-NormalizedAzureResource',
    'Get-NormalizedRegistry',
    'Get-NormalizedDNS',
    'Test-PrivateIP'
)
