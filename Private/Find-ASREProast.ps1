function to_red ($msg) {
  "$([char]0x1b)[91m$msg$([char]0x1b)[0m"
}
function to_green ($msg) {
  "$([char]0x1b)[92m$msg$([char]0x1b)[0m"
}

function Find-ASREProast {
  <#
  .SYNOPSIS
  Searches LDAP to return accounts that do not require Kerberos pre-authentication within Active Directory. 

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-ASREProast -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $true)]
    [String]
    $Domain
  )

  Write-Host '[*] Finding ASREProastable Accounts...' -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  #Search searchbase for user accounts with "Do Not require Kerberos preauthentication" set in their useraccountcontrol
  $ASREPusers = Get-ADUser -SearchBase $searchBase -LDAPFilter '(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' -properties *

  #define privileged groups to check for ASREP-roastable users
  $privilegedgroups = @("Administrators", "Enterprise Admins", "Domain Admins", "DnsAdmins", "Backup Operators",
    "Server Operators", "Account Operators", "Print Operators", "Remote Desktop Users", "Schema Admins", "Cert Publishers")
  
  foreach ($ASREPuser in $ASREPusers) {
    # Check if user is disabled first
    if ($ASREPuser.Enabled -eq $false) {
      $Issue = [pscustomobject]@{
        Domain    = $Domain
        User      = $ASREPuser.SamAccountName
        Enabled   = $ASREPuser.Enabled
        Issue     = "$($ASREPuser.SamAccountName) does not require Kerberos pre-authentication but is disabled"
        Technique = (to_green "[Low]") + " Disabled ASREP-roastable user"
      }
      $Issue
    }
    # Then check if user is a member of a privileged group
    else {
      $IsPrivileged = $false
      foreach ($group in $privilegedgroups) {
        if ($ASREPuser.MemberOf -match $group) {
          $IsPrivileged = $true
          break
        }
      }
          
      if ($IsPrivileged) {
        $Issue = [pscustomobject]@{
          Domain           = $Domain
          User             = $ASREPuser.SamAccountName
          Enabled          = $ASREPuser.Enabled
          Privilegedgroups = $ASREPuser.memberof
          Issue            = "$($ASREPuser.SamAccountName) does not require Kerberos pre-authentication and is a member of a privileged group"
          Technique        = (to_red "[CRITICAL]") + " Highly privileged ASREP-roastable user"
        }
        $Issue
      }
      else {
        $Issue = [pscustomobject]@{
          Domain    = $Domain
          User      = $ASREPuser.SamAccountName
          Enabled   = $ASREPuser.Enabled
          Issue     = "$($ASREPuser.SamAccountName) does not require Kerberos pre-authentication, but is not a member of privileged groups"
          Technique = (to_red "[HIGH]") + " Standard ASREP-roastable user"
        }
        $Issue
      }
    }
  }
}