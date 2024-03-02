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

  Write-Host '[*] Finding WebDAV...' -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  #Get computers
  $Computers = (Get-ADComputer -SearchBase $searchBase -filter *).dnshostname
  $Computers = $Computers | ? { $_ }

  #Array to store multiple machine having WebDAV enabled
  $results = @()

  #check if ldap signing not required & webdav enabled (to accurately assess risk) - HIGH high risk, else low risk - might move to invoke-adscanner.ps1
  $checkldapsigning = Find-LDAPSigning -Domain $Domain

  #Check each for presence of the WebDAV named pipe
  foreach ($computer in $Computers) {
    try {
        Write-Host "Checking \\$computer\pipe\DAV RPC SERVICE" -ForegroundColor Yellow
        $webdav = Get-ChildItem "\\$computer\pipe\DAV RPC SERVICE" -ErrorAction Ignore

         # If the webdav exists check for severity of issue
         if ($webdav) {
            #check if ldap signing returns true
            if($checkldapsigning){
              $Issue = [pscustomobject]@{
                  Domain    = $domain
                  Hostname = $computer
                  WebDAVEnabled = $true
                  Issue     = "WebDAV is enabled and LDAP signing is not required. $computer can be remotely be fully compromised via WebDAV to LDAP to RBCD authentication relay"
                  Technique = (to_red "[HIGH]") + " Admin compromise of $computer via WebDAV to LDAP to RBCD authentication relay"
              }
            } else{
              $Issue = [pscustomobject]@{
                  Domain    = $domain
                  Hostname = $computer
                  WebDAVEnabled = $true
                  Issue     = "$computer has WebDAV is enabled but LDAP signing is required mitigating relaying attacks. Check if the WebClient service is required as unnecessary services should be disabled"
                  Technique = (to_green "[LOW]") + " WebDAV service is running - this is the default on workstations"
              }
            }
            $Issue
        }
    } catch{
       Write-Error $_
    }
  }
}