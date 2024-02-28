function Find-UnsupportedOS {
    <#
  .SYNOPSIS
  Searches LDAP to return computers with an unsupported / obsolete Windows operating system within Active Directory. 
  These systems are no longer supported by the manufacturer and are vulnerable to critical CVEs. 

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-UnsupportedOS -Domain test.local

  #>
 
    #Add mandatory domain parameter
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [String]
        $Domain
    )

    Write-Host '[*] Finding unsupported operating systems...' -ForegroundColor Yellow
  
    #Dynamically produce searchbase from domain parameter
    $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
    $searchBase = $SearchBaseComponents -join ','

    #legacy OS as of 2024:
    #Windows 2000
    $win2000 = Get-ADComputer -SearchBase $searchBase -LDAPFilter '(&(objectCategory=Computer)(operatingSystem=Windows 2000))' -properties *
  
    #Windows XP
    $winXP = Get-ADComputer -SearchBase $searchBase -LDAPFilter '(&(objectCategory=Computer)(operatingSystem=Windows XP*))' -properties *

    #Windows Vista
    $winvista = Get-ADComputer -SearchBase $searchBase -LDAPFilter '(&(objectCategory=Computer)(operatingSystem=Windows Vista*))' -properties *

    #Windows 7
    $win7 = Get-ADComputer -SearchBase $searchBase -LDAPFilter '(&(objectCategory=Computer)(operatingSystem=Windows 7*))' -properties *

    #Windows 8
    $win8 = Get-ADComputer -SearchBase $searchBase -LDAPFilter '(&(objectCategory=Computer)(operatingSystem=Windows 8*))' -properties *

    #Windows Server 2003
    $winserver2003 = Get-ADComputer -SearchBase $searchBase -LDAPFilter '(&(objectCategory=Computer)(operatingSystem=Windows Server 2003*))' -properties *

    #Windows Server 2008/2008-R2
    $winserver2008 = Get-ADComputer -SearchBase $searchBase -LDAPFilter '(&(objectCategory=Computer)(operatingSystem=Windows Server 2008*))' -properties *

    #Windows Server 2012
    $winserver2012 = Get-ADComputer -SearchBase $searchBase -LDAPFilter '(&(objectCategory=Computer)(operatingSystem=Windows Server 2012*))' -properties *

    # Initialize the Issue PSCustomObject
    $Issue = [pscustomobject]@{
        Domain    = $Domain
        Issues    = ""
        Technique = ""
    }

    # Update PSCustomObject with any issues
    if ($win2000 -or $winXP -or $winvista -or $win7 -or $win8 -or $winserver2003 -or $winserver2008 -or $winserver2012) {
        $Issue.Issues = "The following outdated operating systems were found and should be upgraded:"

        #check for issues, computer disabled reduces risk as although can be remotely compromised - cannot log onto domain with
        if ($win2000) {
            if ($win2000.enabled -eq $true) {
                $Issue.Issues += "`r`n" + (to_red "[CRITICAL]") + " $($win2000.DistinguishedName) is enabled and running $($win2000.operatingsystem)"
                $Issue.Technique += (to_red "[CRITICAL]") + " Outdated Operating Systems found"
            }
            else {
                $Issue.Issues += "`r`n" + (to_yellow "[MEDIUM]") + " $($win2000.DistinguishedName) is running $($win2000.operatingsystem) but is disabled"
                $Issue.Technique += (to_yellow "[MEDIUM]") + " Outdated Operating Systems found"
            }
        }
        if ($winXP) {
            if ($winXP.enabled -eq $true) {
                $Issue.Issues += "`r`n" + (to_red "[CRITICAL]") + " $($winXP.DistinguishedName) is enabled and running $($winXP.operatingsystem)"
                $Issue.Technique += (to_red "[CRITICAL]") + " Outdated Operating Systems found"
            }
            else {
                $Issue.Issues += "`r`n" + (to_yellow "[MEDIUM]") + " $($winXP.DistinguishedName) running $($winXP.operatingsystem) but is disabled"
                $Issue.Technique += (to_yellow "[MEDIUM]") + " Outdated Operating Systems found"
            }
        }
        if ($winvista) {
            if ($winvista.enabled -eq $true) {
                $Issue.Issues += "`r`n" + (to_red "[CRITICAL]") + " $($winvista.DistinguishedName) is enabled and running $($winvista.operatingsystem)"
                $Issue.Technique += (to_red "[CRITICAL]") + " Outdated Operating Systems found"
            }
            else {
                $Issue.Issues += "`r`n" + (to_yellow "[MEDIUM]") + " $($winvista.DistinguishedName) running $($winvista.operatingsystem) but is disabled"
                $Issue.Technique += (to_yellow "[MEDIUM]") + " Outdated Operating Systems found"
            }
        }
        if ($win7) {
            if ($win7.enabled -eq $true) {
                $Issue.Issues += "`r`n" + (to_red "[CRITICAL]") + " $($win7.DistinguishedName) is enabled and running $($win7.operatingsystem)"
                $Issue.Technique += (to_red "[CRITICAL]") + " Outdated Operating Systems found"
            }
            else {
                $Issue.Issues += "`r`n" + (to_yellow "[MEDIUM]") + " $($win7.DistinguishedName) running $($win7.operatingsystem) but is disabled"
                $Issue.Technique += (to_yellow "[MEDIUM]") + " Outdated Operating Systems found"
            }
        }
        if ($win8) {
            if ($win8.enabled -eq $true) {
                $Issue.Issues += "`r`n" + (to_red "[CRITICAL]") + " $($win8.DistinguishedName) is enabled and running $($win8.operatingsystem)"
                $Issue.Technique += (to_red "[CRITICAL]") + " Outdated Operating Systems found"
            }
            else {
                $Issue.Issues += "`r`n" + (to_yellow "[MEDIUM]") + " $($win8.DistinguishedName) running $($win8.operatingsystem) but is disabled"
                $Issue.Technique += (to_yellow "[MEDIUM]") + " Outdated Operating Systems found"
            }
        }
        if ($winserver2003) {
            if ($winserver2003.enabled -eq $true) {
                $Issue.Issues += "`r`n" + (to_red "[CRITICAL]") + " $($winserver2003.DistinguishedName) is enabled and running $($winserver2003.operatingsystem)"
                $Issue.Technique += (to_red "[CRITICAL]") + " Outdated Operating Systems found"
            }
            else {
                $Issue.Issues += "`r`n" + (to_yellow "[MEDIUM]") + " $($winserver2003.DistinguishedName) running $($winserver2003.operatingsystem) but is disabled"
                $Issue.Technique += (to_red "[MEDIUM]") + " Outdated Operating Systems found"
            }
        }
        if ($winserver2008) {
            if ($winserver2008.enabled -eq $true) {
                $Issue.Issues += "`r`n" + (to_red "[CRITICAL]") + " $($winserver2008.DistinguishedName) is enabled and running $($winserver2008.operatingsystem)"
                $Issue.Technique += (to_red "[CRITICAL]") + " Outdated Operating Systems found"
            }
            else {
                $Issue.Issues += "`r`n" + (to_yellow "[MEDIUM]") + " $($winserver2008.DistinguishedName) running $($winserver2008.operatingsystem) but is disabled"
                $Issue.Technique += (to_yellow "[MEDIUM]") + " Outdated Operating Systems found"
            }
        }
        if ($winserver2012) {
            if ($winserver2012.enabled -eq $true) {
                $Issue.Issues += "`r`n" + (to_red "[CRITICAL]") + " $($winserver2012.DistinguishedName) is enabled and running $($winserver2012.operatingsystem)"
                $Issue.Technique += (to_red "[CRITICAL]") + " Outdated Operating Systems found"
            }
            else {
                $Issue.Issues += "`r`n" + (to_yellow "[MEDIUM]") + " $($winserver2012.DistinguishedName) running $($winserver2012.operatingsystem) but is disabled"
                $Issue.Technique += (to_yellow "[MEDIUM]") + " Outdated Operating Systems found"
            }
        }

        #work out total risk of technique
        if ($Issue.Technique -match "CRITICAL") {
            $Issue.Technique = (to_red "[CRITICAL]") + " Outdated Operating Systems found"
        } elseif ($Issue.Technique -match "MEDIUM") {
            $Issue.Technique = (to_yellow "[MEDIUM]") + " Outdated Operating Systems found"
        }
    }
    $Issue
}