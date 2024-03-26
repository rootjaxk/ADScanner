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
    [Parameter(Mandatory = $true)]
    [String]
    $Domain
  )
  
  Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Finding WebDAV..." -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  #Get computers
  $Computers = (Get-ADComputer -SearchBase $searchBase -filter *).dnshostname
  $Computers = $Computers | ? { $_ }

  #check if ldap signing not required & webdav enabled (to accurately assess risk) - HIGH high risk, else low risk - might move to invoke-adscanner.ps1
  $checkldapsigning = Find-LDAPSigning -Domain $Domain

  #Initliase object
  $WebDAVIssue = [pscustomobject]@{
    Risk          = ""
    Technique     = ""
    Score         = ""
    Computers     = ""
    WebDAVEnabled = "$true"
    Issue         = ""
  }
  $WebDAVcount = 0

  $timeout = 1
  
  #Get active computers
  foreach ($computer in $Computers) {
    $ping = New-Object System.Net.NetworkInformation.Ping
    $reply = $ping.Send($computer, $Timeout * 1000)
  
    #If host is active, search for named pipes
    if ($reply.Status -eq 'Success') {
      try {
        Write-Host "Checking \\$computer\pipe\DAV RPC SERVICE" -ForegroundColor Yellow
        $webdav = Get-ChildItem "\\$computer\pipe\DAV RPC SERVICE" -ErrorAction Ignore

        # If the webdav exists check for severity of issue
        if ($webdav) {
          if ($WebDAVIssue.Computers -eq '') {
            $WebDAVIssue.Computers += $computer
          }
          else {
            $WebDAVIssue.Computers += "`r`n$computer"
          }
          $WebDAVcount++
        }
      }
      catch {
        Write-Error $_
      }
    }
  }
  #if issue is present, return the object
  if ($WebDAVIssue.Computers -ne '') {
    #check if ldap signing returns true
    if ($checkldapsigning) {
      $WebDAVIssue.Risk= (to_red "HIGH")
      $WebDAVIssue.Score = 35
      $WebDAVIssue.Technique = "Admin compromise of computer is possible via WebDAV to LDAP to RBCD authentication relay"
      $WebDAVIssue.Issue = "WebDAV is enabled on $WebDAVcount computers and LDAP signing is not required. Each computer actively running the WebClient service can be remotely be fully compromised via a WebDAV HTTP to LDAP on a domain controller to RBCD authentication relay, unless LDAP signing and channel binding if encorced on all domain controllers."
    }
    else {
      $WebDAVIssue.Risk= (to_green "LOW")
      $WebDAVIssue.Score = 5
      $WebDAVIssue.Technique = "WebDAV service is running on computers - this is the default on workstations"
      $WebDAVIssue.Issue = "WebDAV is enabled on $WebDAVcount computers but LDAP signing is required mitigating relaying attacks. Check if the WebClient service is required as unnecessary services should be disabled."
    }
    $WebDAVIssue
  }
}