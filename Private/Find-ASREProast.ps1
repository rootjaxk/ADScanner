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

  #define weak asrep account password
  if ($PwdPolicyLength -lt 24) {
    $WeakPwdPolicy = $true
  }

  #Initalise issues
  $ASREPDisabled = [pscustomobject]@{
    Technique = (to_green "[LOW]") + " Disabled ASREP-roastable user"
    Users     = ""
    Enabled   = "False"
    Issue     = "Users do not require Kerberos pre-authentication but are disabled"
  }

  $ASREPprivileged_weakpwd = [pscustomobject]@{
    Technique = (to_red "[CRITICAL]") + " Highly privileged ASREP-roastable user with a weak password"
    Users     = ""
    Memberof  = ""
    Enabled   = "True"
    Issue     = "Users do not require Kerberos pre-authentication, have a weak password, and are a member of a privileged group"
  }

  $ASREPprivileged_strongpwd = [pscustomobject]@{
    Technique = (to_red "[HIGH]") + " Highly privileged ASREP-roastable user with a strong password"
    Users     = ""
    Memberof  = ""
    Enabled   = "True"
    Issue     = "Users do not require Kerberos pre-authentication, have a strong password, and are a member of a privileged group but has a strong password set. A threat actor with unlimited computation power can compromise this account"
  }
 
  $ASREPlowprivileged_weakpwd = [pscustomobject]@{
    Technique = (to_red "[HIGH]") + " Low privileged ASREP-roastable user with a weak password"
    Users     = ""
    Enabled   = "True"
    Issue     = "Users do not require Kerberos pre-authentication and have a weak password. These accounts allow an attacker a foothold into the domain and should be assumed compromised"
  }

  $ASREPlowprivileged_strongpwd = [pscustomobject]@{
    Technique = (to_red "[HIGH]") + " Low privileged ASREP-roastable user with a strong password set"
    Users     = ""
    Enabled   = "True"
    Issue     = "Users do not require Kerberos pre-authentication, but are not a member of a privileged group and has a strong password set. However a threat actor with unlimited computation power can compromise this account"
  }

  foreach ($ASREPuser in $ASREPusers) {
    # Check if user is disabled first
    if ($ASREPuser.Enabled -eq $false) {
      if ($ASREPDisabled.Users -eq '') {
        $ASREPDisabled.Users += $ASREPuser.SamAccountName
      }
      else {
        $ASREPDisabled.Users += "`r`n$($ASREPuser.SamAccountName)"
      }
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
        if ($ASREPprivileged_weakpwd.Users -eq '') {
          $ASREPprivileged_weakpwd.Users += $ASREPuser.SamAccountName
          $ASREPprivileged_weakpwd.MemberOf += $ASREPuser.memberof
        }
        else {
          $ASREPprivileged_weakpwd.Users += "`r`n$($ASREPuser.SamAccountName)"
          $ASREPprivileged_weakpwd.MemberOf += "`r`n$($ASREPuser.memberof)"
        }
      }
      #privileged but strong password
      elseif ($IsPrivileged -and !$WeakPwdPolicy) {
        if ($ASREPprivileged_strongpwd.Users -eq '') {
          $ASREPprivileged_strongpwd.Users += $ASREPuser.SamAccountName
          $ASREPprivileged_strongpwd.MemberOf += $ASREPuser.memberof
        }
        else {
          $ASREPprivileged_strongpwd.Users += "`r`n$($ASREPuser.SamAccountName)"
          $ASREPprivileged_strongpwd.MemberOf += "`r`n$($ASREPuser.memberof)"
        } 
      }
      #not privileged & weak password
      elseif ($WeakPwdPolicy) {
        if ($ASREPlowprivileged_weakpwd.Users -eq '') {
          $ASREPlowprivileged_weakpwd.Users += $ASREPuser.SamAccountName
        }
        else {
          $ASREPlowprivileged_weakpwd.Users += "`r`n$($ASREPuser.SamAccountName)"
        }
      }
      #low privileged, strong password
      else {
        if ($ASREPlowprivileged_strongpwd.Users -eq '') {
          $ASREPlowprivileged_strongpwd.Users += $ASREPuser.SamAccountName
        }
        else {
          $ASREPlowprivileged_strongpwd.Users += "`r`n$($ASREPuser.SamAccountName)"
        }
      }
    }
  }

  #output if users are present in any of the issues in order of severity
  if ($ASREPprivileged_weakpwd.Users) {
    $ASREPprivileged_weakpwd
  }
  if ($ASREPprivileged_strongpwd.Users) {
    $ASREPprivileged_strongpwd
  }
  if ($ASREPlowprivileged_weakpwd.Users) {
    $ASREPlowprivileged_weakpwd
  }
  if ($ASREPlowprivileged_strongpwd.Users) {
    $ASREPlowprivileged_strongpwd #| ft -AutoSize -Wrap
  }
  if ($ASREPDisabled.Users) {
    $ASREPDisabled
  }
  
}