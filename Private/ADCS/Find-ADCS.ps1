function Find-ADCS {
    <#
  .SYNOPSIS
  Finds ADCS objects within a domain. 

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-ADCS -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Finding ADCS...' -ForegroundColor Yellow

  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','
  
  #Add searchbase where ADCS configuration is stored
  $CAsearchBase = 'CN=Public Key Services,CN=Services,CN=Configuration,' + $searchBase
 
  #Enumerate enterprise CA query LDAP - will return DNS hostname, CA name, certificate start/end date, templates etc.
  Get-ADObject -SearchBase $CAsearchBase -LDAPFilter '(&(objectCategory=pKIEnrollmentService))' -properties * |
  Select-Object DisplayName, dNSHostName, certificateTemplates


}