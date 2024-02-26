function Find-DomainInfo {
  <#
  .SYNOPSIS
  Searches LDAP for generic domain information. This information is not 'vulnerabiltiies', but is used to build an overview of the domain and ways to make it more effecient (best practice). 

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

  Write-Host '[*] Extracting Domain information...' -ForegroundColor Yellow
  
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
    CertificiateTemplates = $CAtemplates
  }
  $DomainInfo


  #Empty OU issue
  Write-Host '[*] Finding empty OUs...' -ForegroundColor Yellow
  $emptyOU = Get-ADOrganizationalUnit -filter * -Properties * | Select-Object DistinguishedName, @{Name = "Length"; e = { $_.DistinguishedName.length } }, Name, @{Name = "numObject"; 
    Expression = { Get-ADObject -filter * -SearchBase $_.DistinguishedName | Where-Object { $_.objectclass -ne "organizationalunit" } | Measure-Object | Select-Object -ExpandProperty Count }
  } | Where-Object { $_.numObject -eq 0 } | Sort-Object -Property Length -Descending 

  if ($emptyOU) {
    $Issue = [pscustomobject]@{
      Forest    = $Domain
      EmptyOUs  = $emptyOU.count
      Issue     = "There are $($emptyOU.count) empty OUs within the domain. The domain structure can be reduced by approximately $([math]::Round(($emptyOU.count / $numOU * 100), 2))%. Removing complexity eases administration and reduces risk of misconfigurations"
      Technique =  (to_cyan "[INFORMATIONAL]") + " Domain effiency impprovement - empty Organizational Units"
    }
    $Issue  
  }
    foreach ($empty in $emptyOU) {
    $emptyIssue = [pscustomobject]@{
      Forest    = $Domain
      OU        = $empty.DistinguishedName
      Issue     = "The OU $($empty.Name) is empty and can be removed"
      Technique =  (to_cyan "[INFORMATIONAL]") + " Domain effiency impprovement - empty Organizational Units"
    }
    $emptyIssue
  }


  #Unlinked GPO issue
  Write-Host '[*] Finding unlinked GPOs...' -ForegroundColor Yellow
  $GPOs = Get-GPO -All | Where-Object { $_ | Get-GPOReport -ReportType XML | Select-String -NotMatch "<LinksTo>" }
  $totalunlinked = $GPOs.count

  #Loop through for issues
  if ($GPOs) {
    foreach ($GPO in $GPOs) {
      $Issue = [pscustomobject]@{
        Domain        = $Domain
        Totalunlinked = $totalunlinked
        'GPO name'    = $GPO.DisplayName
        Issue         = "$($GPO.DisplayName) is not linked to any OUs within the domain. Unlinked GPOs are not used and can be removed to reduce complexity and reduce risk of misconfigurations"
        Technique     = (to_cyan "[INFORMATIONAL]")  + " Domain effiency impprovement - unlinked GPOs"
      }
      $Issue
    }
  }
}