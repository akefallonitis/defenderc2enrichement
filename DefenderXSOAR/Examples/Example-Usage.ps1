<#
.SYNOPSIS
    Example usage of DefenderXSOAR
.DESCRIPTION
    Demonstrates various ways to use DefenderXSOAR for security enrichment
#>

# Example 1: Basic Incident Enrichment
function Example1-BasicIncidentEnrichment {
    Write-Host "Example 1: Basic Incident Enrichment" -ForegroundColor Cyan
    
    $entities = @(
        @{
            Type = "User"
            UserPrincipalName = "john.doe@contoso.com"
            Name = "John Doe"
            ObjectId = "user-guid-here"
        },
        @{
            Type = "Device"
            HostName = "WORKSTATION-001"
        },
        @{
            Type = "IP"
            Address = "203.0.113.45"
        }
    )
    
    $result = ..\Functions\Start-DefenderXSOAROrchestration.ps1 `
        -ConfigPath "..\Config\DefenderXSOAR.json" `
        -IncidentId "INC-2024-0001" `
        -Entities $entities `
        -TenantId "your-tenant-id" `
        -Products @('MDE', 'MDC', 'EntraID')
    
    return $result
}

# Example 2: Phishing Email Investigation
function Example2-PhishingEmailInvestigation {
    Write-Host "Example 2: Phishing Email Investigation" -ForegroundColor Cyan
    
    $entities = @(
        @{
            Type = "MailMessage"
            NetworkMessageId = "message-id-here"
            Subject = "Urgent: Account Verification Required"
            Sender = "attacker@suspicious-domain.com"
        },
        @{
            Type = "URL"
            Url = "http://suspicious-domain.com/phishing"
        },
        @{
            Type = "User"
            UserPrincipalName = "victim@contoso.com"
        }
    )
    
    $result = ..\Functions\Start-DefenderXSOAROrchestration.ps1 `
        -ConfigPath "..\Config\DefenderXSOAR.json" `
        -IncidentId "INC-2024-0002" `
        -Entities $entities `
        -TenantId "your-tenant-id" `
        -Products @('MDO', 'EntraID', 'MCAS')
    
    return $result
}

# Main menu
function Show-Menu {
    Write-Host @"

╔═══════════════════════════════════════════════════════════════════╗
║              DefenderXSOAR Usage Examples                         ║
╚═══════════════════════════════════════════════════════════════════╝

Select an example to run:

1.  Basic Incident Enrichment
2.  Phishing Email Investigation

0.  Exit

"@ -ForegroundColor Cyan
    
    $choice = Read-Host "Enter your choice"
    
    switch ($choice) {
        "1" { Example1-BasicIncidentEnrichment }
        "2" { Example2-PhishingEmailInvestigation }
        "0" { return }
        default { Write-Host "Invalid choice" -ForegroundColor Red }
    }
}

# Run the menu
Show-Menu
