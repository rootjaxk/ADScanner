function Find-EfficiencyImprovements {
    <#
    .SYNOPSIS
    Searches for ways to make the domain smaller in size and more effient, to reduce the administrative management and risk of future misconfigurations. 
  
    .PARAMETER Domain
    The domain to run against, in case of a multi-domain environment
  
    .EXAMPLE 
    Find-EfficiencyImprovements -Domain test.local
  
    #>
   
    #Add mandatory domain parameter
    [CmdletBinding()]
    Param(
      [Parameter(Mandatory = $true)]
      [String]
      $Domain
    )
  
    Write-Host '[*] Finding Efficiency Improvements...' -ForegroundColor Yellow
  
    #Dynamically produce searchbase from domain parameter
    $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
    $searchBase = $SearchBaseComponents -join ','
   
    #Empty OU issue
    $numOU = (Get-ADOrganizationalUnit -SearchBase $searchBase -filter *).Count
  
    Write-Host '[*] Finding empty OUs...' -ForegroundColor Yellow
    $emptyOU = Get-ADOrganizationalUnit -filter * -Properties * | Select-Object DistinguishedName, @{Name = "Length"; e = { $_.DistinguishedName.length } }, Name, @{Name = "numObject"; 
      Expression                                                                                                                                                          = { Get-ADObject -filter * -SearchBase $_.DistinguishedName | Where-Object { $_.objectclass -ne "organizationalunit" } | Measure-Object | Select-Object -ExpandProperty Count }
    } | Where-Object { $_.numObject -eq 0 } | Sort-Object -Property Length -Descending 
  
    if ($emptyOU) {
      $Issue = [pscustomobject]@{
        Forest    = $Domain
        EmptyOUs  = $emptyOU.count
        Issue     = "There are $($emptyOU.count) empty OUs within the domain. The domain structure can be reduced by approximately $([math]::Round(($emptyOU.count / $numOU * 100), 2))%. Removing complexity eases administration and reduces risk of misconfigurations"
        Technique = (to_cyan "[INFORMATIONAL]") + " Domain effiency improvement - empty Organizational Units"
      }
      $Issue  
    }
    foreach ($empty in $emptyOU) {
      $emptyIssue = [pscustomobject]@{
        Forest    = $Domain
        OU        = $empty.DistinguishedName
        Issue     = "The OU $($empty.Name) is empty and can be removed"
        Technique = (to_cyan "[INFORMATIONAL]") + " Domain effiency improvement - empty Organizational Units"
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
          Technique     = (to_cyan "[INFORMATIONAL]") + " Domain effiency improvement - unlinked GPOs"
        }
        $Issue
      }
    }
  }