function Find-ESC1 {
    <#
  .SYNOPSIS
  Finds ESC1 (explanation of the vulnerability here). 

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-ESC1 -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Finding ESC1...' -ForegroundColor Yellow
  

}