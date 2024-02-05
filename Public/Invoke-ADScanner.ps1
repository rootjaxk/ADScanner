function Invoke-ADScanner {
      <#
    .SYNOPSIS
    Scans Active Directory for common vulnerabilities and produces an intelligent report to support remediation of vulnerabilities.

    .DESCRIPTION
    Invoke-ADScanner uses the Active Directory (AD) Powershell (PS) module to identify X misconfigurations commonly found in Enterprise Active Directory environments.

    .COMPONENT
    Invoke-ADScanner requires the AD module (and potentially PSPKI module) to be installed in the scope of the Current User. This will require the Remote System Administration
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

    Import-Module ActiveDirectory

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

}
