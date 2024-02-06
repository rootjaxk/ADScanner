function Generate-Report {
    Write-Host '[*] Generating report...' -ForegroundColor Yellow
}

# Generic report info

$EnvironmentTable = [PSCustomObject]@{
    "Ran as User" = "$env:USERDNSDOMAIN\$env:USERNAME"
    "Ran on Host" = $env:computername + '.' + $env:USERDNSDOMAIN
    "Date and Time" = Get-Date
}



# Table of contents

# Executive summary
# Risk score
# Priority list

# General domain info

# Findings - mix of manual & chatGPT expalanations

# Attack demo - images

# Recommendations - chatGPT



#Possible to-do - automated remediation?

