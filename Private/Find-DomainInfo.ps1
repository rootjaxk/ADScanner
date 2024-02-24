function Find-DomainInfo {
  <#
  .SYNOPSIS
  Searches LDAP for generic domain information. This information is not 'vulnerabiltiies',
  but is used to build an overview of the domain and ways to make it more effecient (best practice). 

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

  Write-Host '[*] Extracting Domain information..' -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','


  #Domain name
  $domain = Get-ADDomain # gets forest, domain controller, dns hostnae, etc - more info

  #Trusts
  $trusts = Get-ADTrust -Filter { TrustedDomain -eq $Domain }

  #Functional level
  $functionallevel = $domain.DomainMode

  $domaincontrollers = $domain.ReplicaDirectoryServers


  #Users
  $numUsers = (Get-ADUser -Filter *).Count

  #Groups - 48 is default
  $numGroups = (Get-ADGroup -Filter *).count

  #Computers
  $numComputers = (Get-ADComputer -Filter *).Count


  #OUs 
  $numOU = (Get-ADOrganizationalUnit -filter *).count
  Write-Output "There are $numOU OUs within the domain"

  #OU efficiency improvements
  $emptyOU = Get-ADOrganizationalUnit -filter * -Properties * | Select-Object DistinguishedName, @{Name = "Length"; e = { $_.DistinguishedName.length } }, Name, @{Name = "numObject"; 
    Expression                                                                                                                                                          = { Get-ADObject -filter * -SearchBase $_.DistinguishedName | Where-Object { $_.objectclass -ne "organizationalunit" } | Measure-Object | Select-Object -ExpandProperty Count }
  } | Where-Object { $_.numObject -eq 0 } | Sort-Object -Property Length -Descending 
  $totalempty = $emptyOU.count

  if ($totalempty -eq 0) {
    Write-Output "There are no empty OUs!"
    return
  }
  else {
    Write-Output "There are $totalempty empty OUs within the domain"
    Write-Output "The domain size can be reduced by approximately $([math]::Round(($totalempty / $totalOU * 100), 2))%"
  }


  #GPOs
  $numGPO = (Get-GPO -All).count
  Write-Output "There are $numGPO GPOs within the domain"

  #GPO efficiency improvements
  Write-Output "Finding total number of unlinked GPOs (may take a while) ..."
  $GPOs = Get-GPO -All | Where-Object { $_ | Get-GPOReport -ReportType XML | Select-String -NotMatch "<LinksTo>" }
  $totalunlinked = $GPOs.count

  # Check if there are no unlinked GPOs (if script already executed)
  if ($totalunlinked -eq 0) {
    Write-Output "There are no unlinked GPOs!"
    return
  }
  else {
    Write-Output "There are $totalunlinked unlinked GPOs within the domain"
  }



  # Ceritifcate Authority - might need ADCS module?
  $CAcomputer = (Find-ADCS -domain test.local).dnsHostName
  $CAname = $CAcomputer.DisplayName
 
  # Certificate Templates
  $CAtemplates = (Find-ADCS -domain test.local).certificatetemplates

  #Create object
  $Domaininfo = [pscustomobject]@{
    Domain                 = $Domain
    Users                  = $numUsers
    Groups                 = $numGroups
    Computers              = $numComputers
    Trusts                 = $trusts
    FunctionalLevel        = $functionallevel
    DomainControllers      = $domaincontrollers
    OUs                    = $numOU
    GPOs                   = $numGPO
    $CertificateAuthority  = $CAcomputer, $CAname
    $CertificiateTemplates = $CAtemplates
  }
  $DomainInfo


  #Empty OU issue



  #Unlinked GPO issue


}


<#• 1 Domain – test.local
• X Users
• X Groups
• X Computers
• X Certificate Authority – CA.test.local, CN=CA-01-CA
• X Certificate Templates
• X OUs, Y empty
• X GPOs, Z unlinked
• X Trusts
• X Functional Level
• X Domain Controllers
#>
