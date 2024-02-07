function Find-ESC4 {
    <#
  .SYNOPSIS
  Finds ESC4 (explanation of the vulnerability here). 

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-ESC4 -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Finding ESC4...' -ForegroundColor Yellow
  

}