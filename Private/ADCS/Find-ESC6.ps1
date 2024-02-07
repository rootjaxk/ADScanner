function Find-ESC6 {
    <#
  .SYNOPSIS
  Finds ESC6 (explanation of the vulnerability here). Uses remote registry to check if the EDITF_ATTRIBUTESUBJECTALTNAME2 flag is set. If it is, the CA is vulnerable to ESC6.

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-ESC6 -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  #Retrieve CA info
  $ADCSinfo = Find-ADCS -Domain $Domain
  
  Write-Host '[*] Finding ESC6...' -ForegroundColor Yellow

  #Check if CA is vulnerable to ESC6
  $ESC6 = certutil -config "$($ADCSinfo.dnshostname)\$($ADCSinfo.DisplayName)" -getreg "policy\EditFlags"

  #Check if the EDITF_ATTRIBUTESUBJECTALTNAME2 flag is set
  $pattern = 'EDITF_ATTRIBUTESUBJECTALTNAME2'
  $match = $ESC6 | Select-String -Pattern $pattern -allmatches | ForEach-Object { $_.Matches.Groups[0].value}

  if ($match -eq $pattern) {
    Write-Host "$($ADCSinfo.DisplayName) is vulnerable to ESC6"
  } else {
    Write-Host "CA is not vulnerable to ESC6"
  }
  

}
