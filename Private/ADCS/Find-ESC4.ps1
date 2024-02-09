function Find-ESC4 {
  <#
  .SYNOPSIS
  Searches ADCS for misconfigured certificate templates vulnerable to ESC4. Certificate templates are securable objects in AD, meaning they have a security descriptor that
specifies which AD principals have specific permissions over the template.

  ESC4 relates to insecure permissions on certificate templates. This allows a low-privileged user to edit security settings on a certificate template and escalate their privileges.

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