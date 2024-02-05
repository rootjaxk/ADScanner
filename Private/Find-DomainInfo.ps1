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
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Extracting Domain information..' -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','


  #Domain name
  (Get-WmiObject Win32_ComputerSystem).Domain       #quick wmi way
  Get-ADDomain # gets forest, domain controller, dns hostnae, etc - more info

  #Trusts
  Get-ADTrust -Filter {TrustedDomain -eq $Domain}

  #Functional level
  (Get-ADDomain).DomainMode


  #Users
  # Active users
  (Get-ADComputer -Filter *).Count
  # Disabled users


  #Groups - 48 is default
  (Get-ADGroup -Filter *).count

  #Computers
  (Get-ADComputer -Filter *).Count


  #OUs 
  $totalOU = (Get-ADOrganizationalUnit -filter *).count
  Write-Output "There are $totalOU OUs within the domain"

  #OU efficiency improvements
  $emptyOU = Get-ADOrganizationalUnit -filter * -Properties * | Select-Object DistinguishedName, @{Name="Length"; e={$_.DistinguishedName.length}}, Name, @{Name="numObject"; 
  Expression = { Get-ADObject -filter * -SearchBase $_.DistinguishedName | Where-Object {$_.objectclass -ne "organizationalunit"} | Measure-Object | Select-Object -ExpandProperty Count }} | Where-Object {$_.numObject -eq 0} | Sort-Object -Property Length -Descending 
  $totalempty = $emptyOU.count

  if ($totalempty -eq 0) {
    Write-Output "There are no empty OUs!"
    return
  } else {
    Write-Output "There are $totalempty empty OUs within the domain"
    Write-Output "The domain size can be reduced by approximately $([math]::Round(($totalempty / $totalOU * 100), 2))%"
  }


  #GPOs
  $totalGPO = (Get-GPO -All).count
  Write-Output "There are $totalGPO GPOs within the domain"

  #GPO efficiency improvements
  Write-Output "Finding total number of unlinked GPOs (may take a while) ..."
  $GPOs = Get-GPO -All | Where-Object { $_ | Get-GPOReport -ReportType XML | Select-String -NotMatch "<LinksTo>" }
  $totalunlinked = $GPOs.count

  # Check if there are no unlinked GPOs (if script already executed)
  if ($totalunlinked -eq 0) {
    Write-Output "There are no unlinked GPOs!"
    return
  } else {
    Write-Output "There are $totalunlinked unlinked GPOs within the domain"
  }



 # Ceritifcate Authority


 # Certificate Templates





  #Search searchbase for descriptions from user / computer accounts 
  Get-ADObject -SearchBase $searchBase -LDAPFilter '(&(|(objectClass=user)(objectClass=computer))(description=*))' -properties * |
  Select-Object SamAccountName, Description

  #Send to generative AI for analysis

}
