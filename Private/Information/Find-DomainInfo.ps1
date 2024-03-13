function Find-DomainInfo {
  <#
  .SYNOPSIS
  Searches LDAP for generic domain information. This information is not 'vulnerabiltiies', but is used to build an overview of the domain.

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-DomainInfo -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $true)]
    [String]
    $Domain
  )

  Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Extracting Domain information..." -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  #Domain name
  $domainname = Get-ADDomain # gets forest, domain 

  #Trusts
  $trusts = Get-ADTrust -Filter { TrustedDomain -eq $Domain }
  if ($null -eq $trusts) {
    $trusts = "None"
  }

  #Functional level
  $functionallevel = $domainname.DomainMode

  #Domain controllers
  $domaincontrollers = $domainname.ReplicaDirectoryServers

  #Users
  $numUsers = (Get-ADUser -SearchBase $searchBase -Filter *).Count

  #Groups - 48 is default
  $numGroups = (Get-ADGroup -SearchBase $searchBase -Filter *).Count

  #Computers
  $numComputers = (Get-ADComputer -SearchBase $searchBase -Filter *).Count

  #OUs 
  $numOU = (Get-ADOrganizationalUnit -SearchBase $searchBase -filter *).Count

  #GPOs
  $numGPO = (Get-GPO -All).Count

  # Ceritifcate Authority
  $adcsinfo = Find-ADCS -domain $domain
  if ($null -eq $adcsinfo) {
    $CAcomputer = "None"
    $CAname = "None"
    $numCAtemplates = "None"
    $CAtemplates = "None"
  }
  else {
    $CAcomputer = $adcsinfo.dnsHostName
    $CAname = $adcsinfo.DisplayName

    # Certificate Templates
    $numCAtemplates = $adcsinfo.certificateTemplates.count
    $CAtemplates = $adcsinfo.certificatetemplates
  }
 
  #Create object
  $Domaininfo = [pscustomobject]@{
    Domain                = $domain
    FunctionalLevel       = $functionallevel
    DomainControllers     = $domaincontrollers
    Users                 = $numUsers
    Groups                = $numGroups
    Computers             = $numComputers
    Trusts                = $trusts
    OUs                   = $numOU
    GPOs                  = $numGPO
    CertificateAuthority  = $CAcomputer, $CAname
    CAtemplates           = $numCAtemplates
    CertificateTemplates = $CAtemplates
  }
  $DomainInfo
}