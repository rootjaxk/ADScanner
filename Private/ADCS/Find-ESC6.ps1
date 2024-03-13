function Find-ESC6 {
  <#
  .SYNOPSIS
  Searches ADCS for misconfigured CA with the ESC6 EDITF_ATTRIBUTESUBJECTALTNAME2 flag. This flag allows the enrollee to specify an arbitrary SAN on all certificates despite 
  a certificate template's configuration, meaning any certificate permitting client authentication can be exploited for ESC1.
  Function uses remote registry to check if the EDITF_ATTRIBUTESUBJECTALTNAME2 flag is set. If it is, the CA is vulnerable to ESC6.

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-ESC6 -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $true)]
    [String]
    $Domain
  )

  #Retrieve CA info
  $ADCSinfo = Find-ADCS -Domain $Domain
  
  Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Finding ESC6..." -ForegroundColor Yellow

  #Check if CA is vulnerable to ESC6
  $ESC6 = certutil -config "$($ADCSinfo.dnshostname)\$($ADCSinfo.DisplayName)" -getreg "policy\EditFlags"

  #Check if the EDITF_ATTRIBUTESUBJECTALTNAME2 flag is set - put output in similar $Issue variable?
  $pattern = 'EDITF_ATTRIBUTESUBJECTALTNAME2'
  $match = $ESC6 | Select-String -Pattern $pattern -allmatches | ForEach-Object { $_.Matches.Groups[0].value }

  if ($match -eq $pattern) {
    $Issue = [pscustomobject]@{
      Risk       = (to_red "[CRITICAL]")
      Technique  = "ESC6"
      Score      = 50
      CAName     = $ADCSinfo.displayname
      CAhostname = $ADCSinfo.dnshostname
      Issue      = "$(($ADCSinfo).DisplayName) has the 'EDITF_ATTRIBUTESUBJECTALTNAME2' flag set"
    }
    $Issue
  } 
}
