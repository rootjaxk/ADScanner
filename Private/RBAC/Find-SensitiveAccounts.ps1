function Find-SensitiveAccounts {
    <#
  .SYNOPSIS
  Searches for privileged accounts which do not have the account is sentiive and cannot be delegated configured.

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-SensitiveAccounts -Domain test.local

  #>
 
    #Add mandatory domain parameter
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [String]
        $Domain
    )
    
    Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Finding Sensitive Accounts..." -ForegroundColor Yellow

    $members = @()
    $privilegedmemberproperties = @()

    #Get members of privileged groups
    $privilegedgroups = @("Administrators", "Enterprise Admins", "Domain Admins", "DnsAdmins", "Backup Operators",
        "Server Operators", "Account Operators", "Print Operators", "Remote Desktop Users", "Schema Admins")

    foreach ($group in $privilegedgroups) {
        $members += (Get-ADGroupMember -Identity $group -Recursive).SamAccountName
    }

    #remove repeated users
    $members = $members | Sort-Object -Unique

    #Get user properties
    foreach ($user in $members) {
        $privilegedmemberproperties += Get-ADUser -Identity $user -properties *
    }

    #Initialise issue
    $sensitiveIssue = [pscustomobject]@{
        Risk                = (to_yellow "MEDIUM")
        Technique           = "Highly privileged account does not have the 'Account is sensitive and cannot be delegated' flag set"
        Score               = 19
        Users               = ""
       # MemberOf            = ""
        AccountNotDelegated = $False
        Issue               = ""
    }
    $sensitiveaccountcount = 0

    #See if the user has the account is sensitive and cannot be delegated flag set
    foreach ($user in $privilegedmemberproperties) {
        if ($user.AccountNotDelegated -eq $False) {
            if ($sensitiveIssue.Users -eq '') {
                $sensitiveIssue.Users += $user.SamAccountName
              #  $sensitiveIssue.MemberOf += $user.MemberOf   
            }
            else {
                $sensitiveIssue.Users += "`r`n$($user.SamAccountName)"
               # $sensitiveIssue.MemberOf += "`r`n$($user.MemberOf)"    
            }
            $sensitiveaccountcount++
        }
    }
    #If issue output it
    if ($sensitiveIssue.Users) {
        $sensitiveIssue.Issue = "$sensitiveaccountcount privileged users do not have the 'Account is sensitive and cannot be delegated' flag set. Enabling this on all administrative accounts ensures their credentials cannot forwarded to other computers or services on the network by a trusted application. This prevents account impersonation by a malicious threat actor meaning attacks such as constrained delegation will fail."
        $sensitiveIssue
    }
}
