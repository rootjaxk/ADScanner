function Find-ESC5 {
    <#
  .SYNOPSIS
  Finds ESC5 (explanation of the vulnerability here). 

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