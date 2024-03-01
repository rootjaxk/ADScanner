function Invoke-ADScanner {
    <#
    .SYNOPSIS
    Scans Active Directory for common vulnerabilities and produces an intelligent report to support remediation of vulnerabilities.

    .DESCRIPTION
    Invoke-ADScanner primarily uses the Active Directory (AD) Powershell (PS) module to identify common and highly dangerous misconfigurations
    found in Enterprise Active Directory environments.

    .COMPONENT
    Invoke-ADScanner requires the AD & ADCS modules to be installed in the scope of the Current User. This will require the Remote System Administration
    Toolkit (RSAT) installed on the device. 
    If Locksmith does not identify RSAT installed, it will attempt to install the relevant modules, else will fail.

    .PARAMETER Scans
    Specify which scans you want to run. Available scans: 'All' or ADCS or Kerberos, or , or 'PromptMe'

    -Scans All
    Run all scans (default)

    -Scans PromptMe
    Presents a grid view of the available scan types that can be selected and run them after you click OK.

    .PARAMETER Domain
    Specify a domain to run the scan in to cater to more complex environments

    .PARAMETER OutputPath
    Specify the path where you want to save the report.

    .OUTPUTS
    Different report output types (compliance with different report formats):
    1. To console
    2. HTML

    .EXAMPLE 
    Invoke-ADScanner -Domain test.local -Scans All -Format html -OutputPath c:\temp\
    Invoke-ADScanner -Domain staging.test.local -Scans ADCS,Kerberos -Format csv -OutputPath c:\temp\

    #>

    [CmdletBinding()]
    Param(
        [Parameter()]
        [String]
        $Domain
    )

    #Colours for console output
    function to_red ($msg) {
        "$([char]0x1b)[91m$msg$([char]0x1b)[0m"
    }
    function to_yellow ($msg) {
        "$([char]0x1b)[93m$msg$([char]0x1b)[0m"
    }
    function to_cyan ($msg) {
        "$([char]0x1b)[36m$msg$([char]0x1b)[0m"
    }
    function to_green ($msg) {
        "$([char]0x1b)[92m$msg$([char]0x1b)[0m"
    }

    #First enter chatGPT API key (dynamically build from command to avoid hardcoding in script)
    #$APIkey = Read-Host "Enter your ChatGPT API key"


    #Add a check to see if RSAT is installed, if not, say to install it before importing AD module
    function Test-RSAT-Installed {
        $RSAT = Get-WindowsFeature -Name RSAT-AD-PowerShell
        if ($RSAT.Installed -eq $true) {
            return $true
        }
        else {
            return $false
        }
    }
    #required for esc7 check
    function Test-RSATADCS-Installed {
        $RSAT = Get-WindowsFeature -Name RSAT-ADCS
        if ($RSAT.Installed -eq $true) {
            return $true
        }
        else {
            return $false
        }
    }
    function Test-PSPKI-Installed {
        $PSPKI = Get-Module -ListAvailable -Name PSPKI
        if ($PSPKI -eq $null) {
            return $false
        }
        else {
            return $true
        }
    }

    if (Test-RSAT-Installed) {
        Write-Host "RSAT is installed. Importing ActiveDirectory module..."
        Import-Module ActiveDirectory
    }
    else {
        Write-Host "RSAT is not installed. Please install RSAT as an elevated user before running this script."
        Write-Host "Command: Install-WindowsFeature -Name RSAT-AD-PowerShell" #- only works on servers, on workstaions need to do Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online (see locksmith) - https://github.com/TrimarcJake/Locksmith/blob/main/Private/Install-RSATADPowerShell.ps1
        Write-Host "Command: Install-WindowsFeature -Name GPMC"         #For GPOs
        return
    }   
    
    if (Test-RSATADCS-Installed) {
        Write-Host "RSAT ADCS is installed."
        
    }
    else {
        Write-Host "RSAT is not installed. Please install RSAT as an elevated user before running this script."
        Write-Host "Command: Install-WindowsFeature -Name RSAT-ADCS"
        return
    }

    if (Test-PSPKI-Installed) {
            Write-Host "PSPKI is installed. Importing PSPKI module..."
            Import-Module PSPKI
        }
    else {
        Write-Host "PSPKI is not installed. Please install PSPKI as an elevated user before running this script."
        Write-Host "Command: Install-Module -Name PSPKI -Force"
        return
    }   
    

        # Display help menu if ran incorrectly
        if (-not $Domain) {
            Write-Host "Example Usage:  Invoke-ADScanner -Domain test.local -Scans All -Format html -OutputPath c:\temp\
                -Domain     The domain to scan. If don't know scanner will automatically use the current domain the system is joined to (Get-ADDomain)
                -Scans      The scan type to choose
                -Format     The report format
                -OutputPath The location to save the report
        " 
            return
        }

        #TO-DO - add functionality to do individual scans (for prioritised remediation)



    
        # Create variables to store the findings
        $DomainInfo = @()
        $Kerberos = @()
        $PKI = @()
        $RBAC = @()
        $ACLs = @()
        $MISC = @()
        $Legacy = @()

        #Perform vulnerability checks
        $startTime = Get-Date
        Write-Host '[*] Scanning AD...' -ForegroundColor Yellow 

        # Domain info
        $DomainInfo = Find-DomainInfo -Domain $Domain

        # Kerberos
        $Kerberos += Find-Kerberoast -Domain $Domain
        $Kerberos += Find-ASREProast -Domain $Domain
        $Kerberos += Find-Delegations -Domain $Domain
        $Kerberos += Find-GoldenTicket -Domain $Domain

        # PKI - ADCS
        $PKI += Find-ESC1 -Domain $Domain
        $PKI += Find-ESC2 -Domain $Domain
        $PKI += Find-ESC3 -Domain $Domain
        $PKI += Find-ESC4 -Domain $Domain
        $PKI += Find-ESC5 -Domain $Domain
        $PKI += Find-ESC6 -Domain $Domain
        $PKI += Find-ESC7 -Domain $Domain
        $PKI += Find-ESC8 -Domain $Domain

        # RBAC
        $RBAC += Find-PrivilegedGroups -Domain $Domain
        $RBAC += Find-AdminSDHolder -Domain $Domain | fl
        $RBAC += Find-InactiveAccounts -Domain $Domain | fl
        $RBAC += Find-AnonymousAccess -Domain $Domain

        # ACLs
        $ACLs += Find-ACLs -Domain $Domain

        # MISC
        $MISC += Find-MAQ -Domain $Domain
        $MISC += Find-OutboundAccess -Domain $Domain
        $MISC += Find-PasswordPolicy -Domain $Domain
        $MISC += Find-PwdNotRequired -Domain $Domain
        $MISC += Find-LAPS -Domain $Domain
        $MISC += Find-SMBSigning -Domain $Domain
        $MISC += Find-LDAPSigning -Domain $Domain
        $MISC += Find-Spooler -Domain $Domain
        $MISC += Find-WebDAV -Domain $Domain
        $MISC += Find-SensitiveInfo -Domain $Domain

        # Legacy
        $Legacy += Find-LegacyProtocols -Domain $Domain
        $Legacy += Find-UnsupportedOS -Domain $Domain | fl



        # Output all findings in separate sections
        Write-Host @"
#####################################################################################
#                                    Domain Info                                    #
#####################################################################################
"@
        $DomainInfo | Out-String

        Write-Host @"
#####################################################################################
#                                    Kerberos                                       #
#####################################################################################
"@
        $Kerberos | Out-String

        Write-Host @"
#####################################################################################
#                                       PKI                                         #
#####################################################################################
"@
        $PKI | Out-String

        Write-Host @"
#####################################################################################
#                                       RBAC                                        #
#####################################################################################
"@
        $RBAC | Out-String

        Write-Host @"
#####################################################################################
#                                       ACLs                                        #
#####################################################################################
"@
        $ACLs | Out-String

        Write-Host @"
#####################################################################################
#                                       MISC                                        #
#####################################################################################
"@
        $MISC | Out-String

        Write-Host @"
#####################################################################################
#                                       LEGACY                                      #
#####################################################################################
"@
        $Legacy | Out-String



        #Find-UserDescriptions -Domain $Domain -APIKey $APIkey


 
        #wont output to screen in order as different ones take different amount of time, but when testing this is ok. real will save to variable for use in report

        #Attribute risk score - maybe have own file - attribute it here or elsewhere?
  
        # Caclulate-risk-score

        #Get generative AI input


        #Produce report
        #Generate-Report

        #Calculate time to run
        $endTime = Get-Date
        $elapsedTime = $endTime - $startTime
        Write-Host "ADScanner took $($elapsedTime.TotalSeconds) seconds to run."
    }
