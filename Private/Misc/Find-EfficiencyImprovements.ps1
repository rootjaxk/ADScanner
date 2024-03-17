function Find-EfficiencyImprovements {
  <#
    .SYNOPSIS
    Searches for ways to make the domain smaller in size and more efficient, to reduce the administrative management and risk of future misconfigurations. 
  
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
  
  Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Finding Efficiency Improvements..." -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','
   
  #Empty OU issue
  $numOU = (Get-ADOrganizationalUnit -SearchBase $searchBase -filter *).Count
  
  Write-Host "Finding empty OUs..." -ForegroundColor Yellow
  $emptyOU = Get-ADOrganizationalUnit -filter * -Properties * | Select-Object DistinguishedName, @{Name = "Length"; e = { $_.DistinguishedName.length } }, Name, @{Name = "numObject"; 
    Expression                                                                                                                                                          = { Get-ADObject -filter * -SearchBase $_.DistinguishedName | Where-Object { $_.objectclass -ne "organizationalunit" } | Measure-Object | Select-Object -ExpandProperty Count }
  } | Where-Object { $_.numObject -eq 0 } | Sort-Object -Property Length -Descending 
  

  if ($emptyOU) {
    $emptyOUissue = [pscustomobject]@{
      Risk        = (to_cyan "INFORMATIONAL")
      Technique   = "Domain effiency improvement - empty Organizational Units"
      Score       = 1
      NumEmptyOUs = $emptyOU.count
      EmptyOUs    = ""
      Issue       = "There are $($emptyOU.count) empty OUs within the domain. The domain structure can be reduced by approximately $([math]::Round(($emptyOU.count / $numOU * 100), 2))%. Removing complexity eases administration and reduces risk of misconfigurations"
    }

    foreach ($empty in $emptyOU) {
      if ($emptyOUissue.EmptyOUs -eq '') {
        $emptyOUissue.EmptyOUs += $empty.DistinguishedName
      }
      else {
        $emptyOUissue.EmptyOUs += "`r`n$($empty.DistinguishedName)"
      }
    }
    $emptyOUissue
  }
  
  #Unlinked GPO issue
  Write-Host "Finding unlinked GPOs..." -ForegroundColor Yellow
  $GPOs = Get-GPO -All | Where-Object { $_ | Get-GPOReport -ReportType XML | Select-String -NotMatch "<LinksTo>" }
  
  #Loop through for issues
  if ($GPOs) {
    $emptyGPOissue = [pscustomobject]@{
      Risk         = (to_cyan "INFORMATIONAL")
      Technique    = "Domain effiency improvement - unlinked GPOs"
      Score        = 1
      NumUnlinked  = $GPOs.count
      UnlinkedGPOs = ""
      Issue        = "There are $($GPOs.count) GPOs not linked to any OUs within the domain. Unlinked GPOs are not used and can be removed to reduce complexity and reduce risk of misconfigurations"
    }
    foreach ($GPO in $GPOs) {
      if ($emptyGPOissue.UnlinkedGPOs -eq '') {
        $emptyGPOissue.UnlinkedGPOs += $GPO.DisplayName
      }
      else {
        $emptyGPOissue.UnlinkedGPOs += "`r`n$($GPO.DisplayName)"
      }
    }
    $emptyGPOissue
  }
}