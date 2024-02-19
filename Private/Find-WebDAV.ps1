function Find-WebDAV {
    <#
  .SYNOPSIS
  Searches for machines where the WebClient service (WebDAV) is enabled. The WebClient service on exposes the named pipe - \\<netbiosname>\pipe\DAV RPC SERVICE for WebDAV-based 
  programs and features to work. The WebClient service can be indirectly abused by attackers to coerce authentications.

  If WebDAV is enabled and LDAP signing us not enabled - high risk - any machine running webdav server can be remotely taken over via rbcd / shadow credentials

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-WebDAV -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Finding WebDAV..' -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  #Get computers
  $Computers = (Get-ADComputer -SearchBase $searchBase -filter *).dnshostname

  #Array to store multiple machine having WebDAV enabled
  $results = @()

  #Check each for presence of the spooler named pipe
  foreach ($computer in $Computers) {
    try {
        $webdav = Get-ChildItem "\\$computer\pipe\DAV RPC SERVICE" -ErrorAction Ignore

         # If the webdav exists, add a custom object with hostname and spooler status to results
         if ($webdav) {
            $results += [pscustomobject]@{
                Hostname = $computer
                WebDAVEnabled = $true
            }
        }
    } catch{
       Write-Error $_
    }
  }
  $results
}