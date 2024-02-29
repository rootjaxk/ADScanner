function Find-UserDescription {
  <#
  .SYNOPSIS
  Searches LDAP returning accounts containing user / computer descriptions. Generative AI will then determine if descriptions may contain sensitive information 

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-UserDescription -Domain test.local

  #>
 
  #Add mandatory domain parameter & APIkey
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $true)]
    [String]
    $APIkey,

    [Parameter(Mandatory = $true)]
    [String]
    $Domain
  )

  Write-Host '[*] Extracting User Descriptions..' -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  #Search searchbase for descriptions from user / computer accounts 
  $userswithdescription = Get-ADObject -SearchBase $searchBase -LDAPFilter '(&(|(objectClass=user)(objectClass=computer))(description=*))' -properties *

  $descriptions = $userswithdescription.description

  #Send to generative AI for analysis
  $prompt = "which of these descriptions contain password information which should not be readable by all users? `r`n$descriptions If no passwords are found return only 'No passwords found'" #chatgpt stuff

  #send to API
  $userdescriptionresponse = Connect-ChatGPT -APIkey $APIkey -Prompt $prompt

  if ($userdescriptionresponse -notmatch "No passwords found") {
    #match description back to user
    foreach($pwd in $userdesscriptionresponse){
      $user = $userswithdescription | Where-Object { $_.description -match $pwd }
      $Issue = [pscustomobject]@{
        Domain    = $Domain
        User      = $user.SamAccountName
        Description = $user.description
        Issue     = "$($user.SamAccountName) has the description $($user.description) which contains a password"
        Technique = (to_red "[CRITICAL]") + " plaintext credentials found in Active Directory description field"
      }
      $Issue
    }
  }
}

#test how accurately GPT finds sensitive information in descriptions