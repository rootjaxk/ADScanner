function Generate-Passwordshtml {  
    param (
        [array]$Passwords
    )
    if (!$Passwords) {
        $html = @"
        <div class="finding-header">RBAC</div>
        <h2 class="novuln">No vulnerabilities found!</h2>
"@
    }
    else {
        $html = @"
        <div class="finding-header">RBAC</div>
        <div class="finding-container">
        <table>
            <thead>
                <tr>
                    <th class="table-header">Issue</th>
                    <th class="table-header">Risk</th>
                </tr>
            </thead>
            <tbody>
"@
        foreach ($finding in $Passwords) {
            if ($finding.Technique -match "LAPS") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
            elseif ($finding.Technique -eq "Password complexity requirement is not enabled") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
            elseif ($finding.Technique -eq "Password length requirement is less than 12 characters") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
            elseif ($finding.Technique -eq "Account lockout threshold is greator than 10") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
            elseif ($finding.Technique -eq "The minimum password age is less than 1 day") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
            elseif ($finding.Technique -eq "The maximum password age is less than 365 days") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
            elseif ($finding.Technique -eq "The password history count is less than 24") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
            elseif ($finding.Technique -eq "The account lockout duration is less than 15 minutes") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
            elseif ($finding.Technique -eq "Reversible encryption is enabled") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
            elseif ($finding.Technique -match "does not require a password") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
            elseif ($finding.Technique -eq "Plaintext credentials found readable by low privileged user") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
            elseif ($finding.Technique -match "user's Active Directory description field") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
        }
        $html += "</tbody></table></div>"
    }
    return $html
}