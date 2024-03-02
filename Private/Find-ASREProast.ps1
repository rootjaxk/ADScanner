function Find-ASREProast {
  <#
  .SYNOPSIS
  Searches LDAP to return accounts that do not require Kerberos pre-authentication within Active Directory. 
  There is no reason in a modern environment for a user account to not require Kerberos pre-authentication.  

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

  #get password policy length
  $PwdPolicyLength = (Get-ADDefaultDomainPasswordPolicy -Identity $Domain).MinPasswordlength

  #define weak service account password
  if ($PwdPolicyLength -lt 24){
    $WeakPwdPolicy = $true
  }
  
  foreach ($ASREPuser in $ASREPusers) {
    # Check if user is disabled first
    if ($ASREPuser.Enabled -eq $false) {
      $Issue = [pscustomobject]@{
        Domain    = $Domain
        User      = $ASREPuser.SamAccountName
        Enabled   = $ASREPuser.Enabled
        Issue     = "$($ASREPuser.SamAccountName) does not require Kerberos pre-authentication but is disabled"
        Technique = (to_green "[LOW]") + " Disabled ASREP-roastable user"
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
       #if privileged & weak password
      if ($IsPrivileged -and $WeakPwdPolicy) {
        $Issue = [pscustomobject]@{
          Domain           = $Domain
          User             = $ASREPuser.SamAccountName
          Enabled          = $ASREPuser.Enabled
          Privilegedgroups = $ASREPuser.memberof
          Issue            = "$($ASREPuser.SamAccountName) does not require Kerberos pre-authentication, has a weak password, and is a member of a privileged group"
          Technique        = (to_red "[CRITICAL]") + " Highly privileged ASREP-roastable user with a weak password"
        }
        $Issue
      }
      #privileged but strong password
      elseif ($IsPrivileged -and !$WeakPwdPolicy) {
          $Issue = [pscustomobject]@{
            Domain           = $Domain
            User             = $ASREPuser.SamAccountName
            Enabled          = $ASREPuser.Enabled
            Privilegedgroups = $ASREPuser.memberof
            Issue            = "$($ASREPuser.SamAccountName) does not require Kerberos pre-authentication, and is a member of a privileged group but has a strong password set. A threat actor with unlimited computation power can compromise this account"
            Technique        = (to_red "[HIGH]") + " Highly privileged ASREP-roastable user with a strong password"
          }
          $Issue
        }
      #not privileged & weak password
      elseif ($WeakPwdPolicy) {
        $Issue = [pscustomobject]@{
          Domain    = $Domain
          User      = $ASREPuser.SamAccountName
          Enabled   = $ASREPuser.Enabled
          Issue     = "$($ASREPuser.SamAccountName) does not require Kerberos pre-authentication and has a weak password. This account allows an attacker a foothold into the domain and should be assumed compromised"
          Technique = (to_red "[HIGH]") + " Low privileged ASREP-roastable user with a weak password"
        }
        $Issue
      }
      #low privileged, strong password
      else {
        $Issue = [pscustomobject]@{
          Domain    = $Domain
          User      = $ASREPuser.SamAccountName
          Enabled   = $ASREPuser.Enabled
          Issue     = "$($ASREPuser.SamAccountName) does not require Kerberos pre-authentication, but is not a member of a privileged group and has a strong password set. However a threat actor with unlimited computation power can compromise this account"
          Technique = (to_red "[HIGH]") + " Low privileged ASREP-roastable user, but strong password set"
        }
        $Issue
      }
    }
  }
}