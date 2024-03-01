function Find-Kerberoast {
    <#
  .SYNOPSIS
  Searches LDAP returning service accounts containing Service Principal Names (SPNs) set within Active Directory. Will exclude krbtgt that has a SPN set by default. 
  Will combine finding with password policy length and privileged group membership to accurately asses risk of the kerberoastable account

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-Kerberoast -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Finding Kerberoastable Accounts...' -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  #Search searchbase for user accounts with SPNs
  $kerberoastableusers = Get-ADUser -SearchBase $searchBase -LDAPFilter '(&(objectCategory=user)(servicePrincipalName=*)(!(SamAccountName=krbtgt)))' -properties *

  #define privileged groups to check for kerberoastable users
  $privilegedgroups = @("Administrators", "Enterprise Admins", "Domain Admins", "DnsAdmins", "Backup Operators",
    "Server Operators", "Account Operators", "Print Operators", "Remote Desktop Users", "Schema Admins", "Cert Publishers")
  
  #get password policy length
  $PwdPolicyLength = (Get-ADDefaultDomainPasswordPolicy -Identity $Domain).MinPasswordlength

  #define weak service account password
  if ($PwdPolicyLength -lt 24){
    $WeakPwdPolicy = $true
  }

  foreach ($kerberoastableuser in $kerberoastableusers) {
    # Check if user is disabled first
    if ($kerberoastableuser.Enabled -eq $false) {
      $Issue = [pscustomobject]@{
        Domain    = $Domain
        User      = $kerberoastableuser.SamAccountName
        Enabled   = $kerberoastableuser.Enabled
        Issue     = "$($kerberoastableuser.SamAccountName) has an SPN set but is disabled"
        Technique = (to_green "[LOW]") + " Disabled kerberoastable account"
      }
      $Issue
    }
    # Then check if user is a member of a default privileged group
    else {
      $IsPrivileged = $false
      foreach ($group in $privilegedgroups) {
        if ($kerberoastableuser.MemberOf -match $group) {
          $IsPrivileged = $true
          break
        }
      }
      #if privileged & weak password
      if ($IsPrivileged -and $WeakPwdPolicy) {
        $Issue = [pscustomobject]@{
          Domain           = $Domain
          User             = $kerberoastableuser.SamAccountName
          Enabled          = $kerberoastableuser.Enabled
          Privilegedgroups = $kerberoastableuser.memberof
          Issue            = "$($kerberoastableuser.SamAccountName) has an SPN set with a weak password and is a member of a privileged group"
          Technique        = (to_red "[CRITICAL]") + " Highly privileged kerberoastable user with a weak password"
        }
        $Issue
      }
      #privileged but strong pasword
      elseif($Isprivileged -and !$WeakPwdPolicy){
        $Issue = [pscustomobject]@{
          Domain           = $Domain
          User             = $kerberoastableuser.SamAccountName
          Enabled          = $kerberoastableuser.Enabled
          Privilegedgroups = $kerberoastableuser.memberof
          Issue            = "$($kerberoastableuser.SamAccountName) has an SPN set and is a member of a privileged group but has a strong pssword set. A threat actor with unlimited computation power can compromise this account"
          Technique        = (to_red "[HIGH]") + " Highly privileged kerberoastable user"
        }
        $Issue
      }
      #not privileged & weak password
      elseif($WeakPwdPolicy){
        $Issue = [pscustomobject]@{
          Domain    = $Domain
          User      = $kerberoastableuser.SamAccountName
          Enabled   = $kerberoastableuser.Enabled
          Issue     = "$($kerberoastableuser.SamAccountName) has an SPN and a weak password set. This service wont facilitate direct domain privilege escalation but allows full compromise of the service"
          Technique = (to_red "[HIGH]") + " Low privileged kerberoastable user with a weak password"
        }
        $Issue
      }
      #low privileged, with strong password
      else {
        $Issue = [pscustomobject]@{
          Domain    = $Domain
          User      = $kerberoastableuser.SamAccountName
          Enabled   = $kerberoastableuser.Enabled
          Issue     = "$($kerberoastableuser.SamAccountName) has an SPN set but is not a member of a privileged group and has a strong password set"
          Technique = (to_green "[LOW]") + " Low privileged kerberoasable user, but strong password set"
        }
        $Issue
      }
    }
  }
}
