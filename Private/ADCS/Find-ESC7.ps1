function Find-ESC7 {
  <#
  .SYNOPSIS
  Searches ADCS for misconfigured certificate authorites vulnerable to ESC7. ESC7 relates to when a user has the Manage CA or Manage Certificates access right on a CA, they can issue
  failed certificate requests. The SubCA certificate template is vulnerable to ESC1, but only administrators can enroll in the template. 
  A user can request to enroll in the SubCA - which will be denied - but then issued by the manager afterwards escalating through ESC1.

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
