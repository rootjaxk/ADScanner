function Find-ESC7 {
    <#
  .SYNOPSIS
  Finds ESC7 (explanation of the vulnerability here). 

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-ESC7 -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Finding ESC7...' -ForegroundColor Yellow
  

}
