function Find-UnsupportedOS {
    <#
  .SYNOPSIS
  Searches LDAP to return computers with an unsupported / obsolete operating system within Active Directory. 
  These systems are no longer supported by the manufacturer and are vulnerable to remote code execution CVEs. 

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

  #need to store to a variable and select specific output 

  #Windows 2000
  Get-ADComputer -SearchBase $searchBase -LDAPFilter '(&(objectCategory=Computer)(operatingSystem=Windows 2000))'
  
  #Windows XP
  Get-ADComputer -SearchBase $searchBase -LDAPFilter '(&(objectCategory=Computer)(operatingSystem=Windows XP*))'

  #Windows Vista
  Get-ADComputer -SearchBase $searchBase -LDAPFilter '(&(objectCategory=Computer)(operatingSystem=Windows Vista*))'

  #Windows 7
  Get-ADComputer -SearchBase $searchBase -LDAPFilter '(&(objectCategory=Computer)(operatingSystem=Windows 7*))'

  #Windows 8
  Get-ADComputer -SearchBase $searchBase -LDAPFilter '(&(objectCategory=Computer)(operatingSystem=Windows 8*))'

  #Windows Server 2003
  Get-ADComputer -SearchBase $searchBase -LDAPFilter '(&(objectCategory=Computer)(operatingSystem=Windows Server 2003*))'

  #Windows Server 2008
  Get-ADComputer -SearchBase $searchBase -LDAPFilter '(&(objectCategory=Computer)(operatingSystem=Windows Server 2008*))'

  # for feedback to user
  if ($?) {
      Write-Host '[*] Unsupported operating systems found!' -ForegroundColor Green
  } else {
      Write-Host '[*] No unsupported operating systems found.' -ForegroundColor Green
  } 

#Account
#Enabled
#Active - if ($Account.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
#Admin account - if in privileged groups (DA/EA/built in administrators) - higher risk score!s
#Last logon
#SID
#Domain
#Dynamically produce domain within Invoke-ADScanner.ps1?

}