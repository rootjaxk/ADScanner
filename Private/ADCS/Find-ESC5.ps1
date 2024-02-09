function Find-ESC5 {
  <#
  .SYNOPSIS
  Finds ESC5 (explanation of the vulnerability here). Vulnerable PKI Object Access Control. ESC5 relates to vulnerable PKI objects such as the CA object in AD, or any object within
  CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=local

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-ESC5 -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Finding ESC5...' -ForegroundColor Yellow
  

}