function Find-ESC3 {
    <#
  .SYNOPSIS
  Finds ESC3 (explanation of the vulnerability here). 

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-ESC3 -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Finding ESC3...' -ForegroundColor Yellow
  

}