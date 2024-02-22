function to_red ($msg) {
  "$([char]0x1b)[91m$msg$([char]0x1b)[0m"
}
function to_green ($msg) {
  "$([char]0x1b)[92m$msg$([char]0x1b)[0m"
}

function Find-Kerberoast {
    <#
  .SYNOPSIS
  Searches LDAP returning service accounts containing Service Principal Names (SPNs) set within Active Directory. Will exclude krbtgt that has a SPN set by default 
  [TO-DO] Also will combine finding with password policy and privileged group membership to better reflect risk

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

  Write-Host '[*] Finding Kerberoastable Accounts..' -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  #Search searchbase for user accounts with SPNs
  $kerberoastableusers = Get-ADUser -SearchBase $searchBase -LDAPFilter '(&(objectCategory=user)(servicePrincipalName=*)(!(SamAccountName=krbtgt)))' -properties *

  #define privileged groups to check for kerberoastable users
  $privilegedgroups = @("Administrators", "Enterprise Admins", "Domain Admins", "DnsAdmins", "Backup Operators",
    "Server Operators", "Account Operators", "Print Operators", "Remote Desktop Users", "Schema Admins", "Cert Publishers")
  
  foreach ($kerberoastableuser in $kerberoastableusers) {
    # Check if user is disabled first
    if ($kerberoastableuser.Enabled -eq $false) {
      $Issue = [pscustomobject]@{
        Domain    = $Domain
        User      = $kerberoastableuser.SamAccountName
        Enabled   = $kerberoastableuser.Enabled
        Issue     = "$($kerberoastableuser.SamAccountName) has an SPN set but is disabled"
        Technique = (to_green "[Low]") + " Disabled kerberoastable account"
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
      if ($IsPrivileged) {
        $Issue = [pscustomobject]@{
          Domain           = $Domain
          User             = $kerberoastableuser.SamAccountName
          Enabled          = $kerberoastableuser.Enabled
          Privilegedgroups = $kerberoastableuser.memberof
          Issue            = "$($kerberoastableuser.SamAccountName) has an SPN set and is a member of a privileged group"
          Technique        = (to_red "[CRITICAL]") + " Highly privileged kerberoastable user"
        }
        $Issue
      }
      #else standard kerberoastable user
      else {
        $Issue = [pscustomobject]@{
          Domain    = $Domain
          User      = $kerberoastableuser.SamAccountName
          Enabled   = $kerberoastableuser.Enabled
          Issue     = "$($kerberoastableuser.SamAccountName) has an SPN set but is not a member of a privileged group"
          Technique = (to_red "[HIGH]") + " Standard kerberoasable user"
        }
        $Issue
      }
    }
  }
  
#Also need to check for password policy to increase risk finding
}
