# Anonymous / open shares - try and list shares with no credentials
# Anonymous RPC - equivalent to RPCclient on windows? - only works with rpcclient
# Anonymous LDAP - bind with no credentials - only works with ldapsearch
  
function Find-AnonymousAccess {
    <#
    .SYNOPSIS
    Searches for anonymous access to domain and local systems (e.g. open file shares) that can be facilitated by the Guest account. 
    The Guest account is a default local account that has limited access to the computer and is disabled by default. By default, the Guest account password is left blank. A blank password allows the Guest account to be accessed without requiring the user to enter a password.
  
    .PARAMETER Domain
    The domain to run against, in case of a multi-domain environment
  
    .EXAMPLE 
    Find-AnonymousAccess -Domain test.local
  
    #>
   
    #Add mandatory domain parameter
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [String]
        $Domain
    )
  
    
    Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Finding Anonymous Access..." -ForegroundColor Yellow
    
    #Dynamically produce searchbase from domain parameter
    $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
    $searchBase = $SearchBaseComponents -join ','
  

    #Domain guest account
    $domainGuest = Get-ADUser -SearchBase $searchBase -LDAPFilter '(&(objectCategory=user)(SamAccountName=guest))'

    if ($domainGuest.enabled -eq $true) {
        $Issue = [pscustomobject]@{
            Risk      = (to_red "HIGH")
            Technique = "Domain anonymous access is permitted allowing anonymous access to the domain"
            Score     = 20
            Account   = $domainguest.distinguishedname
            Issue     = "The domain Guest account is enabled, facilitating anonymous access to the domain."
        }
        $Issue
    }
    
    #Built-in guest account
    $localguest = Get-LocalUser -Name "Guest"

    #Get hostname for local account
    $hostname = (Get-ADComputer -Identity $env:COMPUTERNAME).dnshostname
    
    if ($localguest.enabled -eq $true) {
        $Issue = [pscustomobject]@{
            Risk      = (to_red "HIGH")
            Technique = "Local anonymous access is permitted allowing anonymous access to the system"
            Score     = 20
            Account   = "$Hostname\$($localguest.name)"
            Issue     = "The BUILTIN Guest account is enabled, facilitating anonymous access to the local system."
        }
        $Issue
    }
}