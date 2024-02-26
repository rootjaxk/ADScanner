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
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Finding unsupported operating systems...' -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  #legacy OS as of 2024:
  #Windows 2000
  $win2000 = Get-ADComputer -SearchBase $searchBase -LDAPFilter '(&(objectCategory=Computer)(operatingSystem=Windows 2000))'
  
  #Windows XP
  $winXP = Get-ADComputer -SearchBase $searchBase -LDAPFilter '(&(objectCategory=Computer)(operatingSystem=Windows XP*))'

  #Windows Vista
  $winvista = Get-ADComputer -SearchBase $searchBase -LDAPFilter '(&(objectCategory=Computer)(operatingSystem=Windows Vista*))'

  #Windows 7
  $win7 = Get-ADComputer -SearchBase $searchBase -LDAPFilter '(&(objectCategory=Computer)(operatingSystem=Windows 7*))'

  #Windows 8
  $win8 = Get-ADComputer -SearchBase $searchBase -LDAPFilter '(&(objectCategory=Computer)(operatingSystem=Windows 8*))'

  #Windows Server 2003
  $winserver2003 = Get-ADComputer -SearchBase $searchBase -LDAPFilter '(&(objectCategory=Computer)(operatingSystem=Windows Server 2003*))'

  #Windows Server 2008/2008R2
  $winserver2008 = Get-ADComputer -SearchBase $searchBase -LDAPFilter '(&(objectCategory=Computer)(operatingSystem=Windows Server 2008*))'

  #Windows Server 2012
  $winserver2012 = Get-ADComputer -SearchBase $searchBase -LDAPFilter '(&(objectCategory=Computer)(operatingSystem=Windows Server 2012*))'

  # Initialize the Issue PSCustomObject
  $Issue = [pscustomobject]@{
    Domain  = $Domain
    Issues = ""
    Technique = ""
  }

  # Update PSCustomObject with any issues
  if ($win2000 -or $winXP -or $winvista -or $win7 -or $win8 -or $winserver2003 -or $winserver2008 -or $winserver2012) {
    $Issue.Issues = "The following outdated operating systems were found:"
    $Issue.Technique = (to_red "[CRITICAL]") + " Outdated Operating Systems found"

    if ($win2000){
        $Issue.Issues += "`r`n" + (to_red "[HIGH]") + " $($win2000.DistinguishedName) is running Windows 2000."
    }
    if ($winXP){
        $Issue.Issues += "`r`n" + (to_red "[HIGH]") + " $($winXP.DistinguishedName) is running Windows XP."
    }
    if ($winvista){
        $Issue.Issues += "`r`n" + (to_red "[HIGH]") + " $($winvista.DistinguishedName) is running Windows Vista."
    }
    if ($win7){
        $Issue.Issues += "`r`n" + (to_red "[HIGH]") + " $($win7.DistinguishedName) is running Windows 7."
    }
    if ($win8){
        $Issue.Issues += "`r`n" + (to_red "[HIGH]") + " $($win8.DistinguishedName) is running Windows 8."
    }
    if ($winserver2003){
        $Issue.Issues += "`r`n" + (to_red "[HIGH]") + " $($winserver2003.DistinguishedName) is running Windows Server 2003."
    }
    if ($winserver2008){
        $Issue.Issues += "`r`n" + (to_red "[HIGH]") + " $($winserver2008.DistinguishedName) is running Windows Server 2008."
    }
    if ($winserver2012){
        $Issue.Issues += "`r`n" + (to_red "[HIGH]") + " $($winserver2012.DistingishedName) is running Windows Server 2012."
    }
  }
  $Issue
}