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

    Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Finding unsupported operating systems..." -ForegroundColor Yellow
  
    #Dynamically produce searchbase from domain parameter
    $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
    $searchBase = $SearchBaseComponents -join ','

    #legacy OS as of 2024:
    $unsupportedOS = @("Windows NT*", "Windows ME*", "Windows 95*", "Windows 98*", "Windows XP*", "Windows 2000*", "Windows Vista*", "Windows 7*", "Windows 8*", "Windows Server 2003*", "Windows Server 2008*", "Windows Server 2012*")

    $Outdated_EnabledIssue = [pscustomobject]@{
        Risk             = (to_red "HIGH")
        Technique        = "Outdated Operating Systems found"
        Score            = 30
        OperatingSystems = ""
        VulnerableComputers = ""
        Count            = ""
        Enabled          = "True"
        Issues           = ""
    }

    $Outdated_DisabledIssue = [pscustomobject]@{
        Risk             = (to_yellow "MEDIUM")
        Technique        = "Outdated, but disabled, Operating Systems found"
        Score            = 10
        OperatingSystems = ""
        VulnerableComputers = ""
        Count            = ""
        Enabled          = "False"
        Issues           = ""
    }

    $UnsupportedenabledOScount = 0
    $UnsupportedisabledOScount = 0

    foreach ($os in $unsupportedOS) {
        $computers = Get-ADComputer -SearchBase $searchBase -LDAPFilter "(&(objectCategory=Computer)(operatingSystem=$os))" -properties *
        foreach ($computer in $computers) {
            if ($computer.enabled -eq $true) {
                if ($Outdated_EnabledIssue.OperatingSystems -eq '') {
                    $Outdated_EnabledIssue.VulnerableComputers += $computer.DistinguishedName
                    $Outdated_EnabledIssue.OperatingSystems += $computer.operatingsystem
                    $Outdated_EnabledIssue.Issues += "$($computer.DistinguishedName) is enabled and running $($computer.operatingsystem)"
                }
                else {
                    $Outdated_EnabledIssue.VulnerableComputers += "`r`n$($computer.DistinguishedName)"
                    $Outdated_EnabledIssue.OperatingSystems += "`r`n$($computer.operatingsystem)"
                    $Outdated_EnabledIssue.Issues += "`r`n$($computer.DistinguishedName) is enabled and running $($computer.operatingsystem)"

                }
                $UnsupportedenabledOScount++
            }
            else {
                if ($Outdated_DisabledIssue.OperatingSystems -eq '') {
                    $Outdated_DisabledIssue.VulnerableComputers += $computer.DistinguishedName
                    $Outdated_DisabledIssue.OperatingSystems += $computer.operatingsystem
                    $Outdated_DisabledIssue.Issues += "$($computer.DistinguishedName) is running $($computer.operatingsystem) but is disabled"
                }
                else {
                    $Outdated_DisabledIssue.VulnerableComputers += "`r`n$($computer.DistinguishedName)"
                    $Outdated_DisabledIssue.OperatingSystems += "`r`n$($computer.operatingsystem)"
                    $Outdated_DisabledIssue.Issues += "`r`n$($computer.DistinguishedName) is running $($computer.operatingsystem) but is disabled"
                }
                $UnsupportedisabledOScount++
            }
        }
    }

    #if present display issues
    if ($Outdated_EnabledIssue.OperatingSystems -ne "") {
        $Outdated_EnabledIssue.Issues += "`r`nAll of these operating systems have critical CVEs"
        $Outdated_EnabledIssue.Count = $UnsupportedenabledOScount
        $Outdated_EnabledIssue
    }
    if ($Outdated_DisabledIssue.OperatingSystems -ne "") {
        $Outdated_DisabledIssue.Issues += "`r`nAll of these operating systems have critical CVEs, but as they are disabled, although they can be trivially compromised they cannot be used to authenticate to the domain. These should remain disabled, and are likely left over objects in active directory from a decommission."
        $Outdated_DisabledIssue.Count = $UnsupportedisabledOScount
        $Outdated_DisabledIssue
    }
}