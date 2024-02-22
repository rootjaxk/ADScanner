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
    1. HTML
    2. CSV
    3. PDF

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

    #Add a check to see if RSAT is installed, if not, say to install it before importing AD module
    function Test-RSAT-Installed {
        $RSAT = Get-WindowsFeature -Name RSAT-AD-PowerShell
        if ($RSAT.Installed -eq $true) {
            return $true
        } else {
            return $false
        }
    }

    #required for esc7 check
    function Test-RSATADCS-Installed {
        $RSAT = Get-WindowsFeature -Name RSAT-ADCS
        if ($RSAT.Installed -eq $true) {
            return $true
        } else {
            return $false
        }
      }

      function Install-PSPKI {
        $PSPKI = Get-Module -ListAvailable -Name PSPKI
        if ($PSPKI -eq $null) {
            Install-Module -Name PSPKI -Force
        }
      }

    if (Test-RSAT-Installed) {
        Write-Host "RSAT is installed. Importing ActiveDirectory module..."
        Import-Module ActiveDirectory
    } else {
        Write-Host "RSAT is not installed. Please install RSAT as an elevated user before running this script."
        Write-Host "Command: Install-WindowsFeature -Name RSAT-AD-PowerShell"
        return
    }   
    
    if (Test-RSATADCS-Installed) {
        Write-Host "RSAT ADCS is installed."
        Install-PSPKI
    } else {
        Write-Host "RSAT is not installed. Please install RSAT as an elevated user before running this script."
        Write-Host "Command: Install-WindowsFeature -Name RSAT-ADCS"
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

    $startTime = Get-Date

    #Perform vulnerability checks
    Write-Host '[*] Scanning AD...' -ForegroundColor Yellow 
    Find-DomainInfo -Domain $Domain
    Find-Kerberoast -Domain $Domain
    Find-ASREProast -Domain $Domain
    Find-PwdNotRequired -Domain $Domain
    #wont output to screen in order as different ones take different amount of time, but when testing this is ok. real will save to variable for use in report

    #Attribute risk score - maybe have own file - attribute it here or elsewhere?
  
    # Caclulate-risk-score

    #Get generative AI input


    #Produce report
    Generate-Report


    #Calculate time to run
    $endTime = Get-Date
    $elapsedTime = $endTime - $startTime
    Write-Host "Script took $($elapsedTime.TotalSeconds) seconds to run."
}


#script may run better with local admin privileges (has permission to find more information), but is not required for 99% of findings