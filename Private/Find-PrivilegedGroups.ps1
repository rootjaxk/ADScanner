# Privileged groups - assess against baseline

#Administrators
#Enterprise Admins
#Domain Admins
#DNS Admins
#Backup Operators
#Server Operators
#Account Operators
#Print Operators
#Remote Desktop Users
#Schema Admins
#Cert Publishers

# Define a hashtable to store group members
$groupMembers = @{}

$groups = @("Administrators", "Enterprise Admins", "Domain Admins", "DnsAdmins", "Backup Operators",
            "Server Operators", "Account Operators", "Print Operators", "Remote Desktop Users",
            "Schema Admins", "Cert Publishers")

#Recursive to get all members of the group (including nested groups)
foreach ($group in $groups) {
    $members = Get-ADGroupMember -Identity $group -Recursive | Select-Object Name, SamAccountName, DistinguishedName
    $groupMembers[$group] = $members
}

# Assign each group's members to a separate variable
foreach ($group in $groups) {
    $variableName = "${group}"
    New-Variable -Name $variableName -Value $groupMembers[$group] -Force
}

# Count number of users in each group
foreach ($group in $groupMembers.GetEnumerator()) {
    $groupName = $group.Key
    $userCount = $group.Value.Count
    Write-Host "Group: $groupName"
    Write-Host "Number of users: $userCount"
    Write-Host ""
}




# How many inactive?
# Set the number of days since last logon
$DaysInactive = 90
$InactiveDate = (Get-Date).Adddays(-($DaysInactive))


$totalusers = (Get-ADUser -filter *).count

# Find stale users (will also find never logged on users)
$staleusers = Search-ADAccount -AccountInactive -DateTime $InactiveDate -UsersOnly | Select-Object @{ Name="Username"; Expression={$_.SamAccountName} }, Name, LastLogonDate, DistinguishedName

# Find total number of users that are stale
$totalstale = $staleusers.count

# Check if there are no stale users (if script already executed)
if ($totalstale -eq 0) {
  Write-Output "There are no inactive users!"
  return
} else {
  Write-Output "There are $totalstale inactive users within the domain"
}


# When last logged in?




