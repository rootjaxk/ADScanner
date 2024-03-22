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
    <tr>
        <td class="toggle" id="$nospaceid"><u>$($finding.Technique)</u></td>
        <td class="finding-risk$($finding.Risk)">$($finding.Risk)</td>
    </tr>
    <tr class="finding">
        <td colspan="3">
            <div class="finding-info">
                <table>
                    <tbody>
                        <tr>
                            <th>Issue</th>
                            <th>MITRE ATT&CK ref</th>
                            <th>Score</th>
                        </tr>
                        <tr>
"@
                if ($finding.Technique -eq "LAPS is not utilized on all computers.") {
                    $html += "<td>LAPS is not installed meaning local admin password reuse is probable.</td>"
                }
                else {
                    $html += "<td>A low-privileged user can escalate to local admin priviliges by readint the LAPS password.</td>"
                }
                $html += @"
                            <td>T-15940</td>
                            <td>+$($finding.Score)</td>
                        </tr>
                    </tbody>
                </table>
                <table>
                    <tbody>
                        <tr>
                            <th>Relevant info</th>
                            <th>Issue explanation</th>
                        </tr>
                        <tr>
                            <td class="relevantinfo"><table>
"@
                if ($finding.Technique -eq "LAPS is not utilized on all computers.") {
                    $html += @"
                    <tr><td class="grey">Computer</td><td>$($finding.Computer)</td></tr>
                    <tr><td class="grey">LAPS installed</td><td>False</td></tr>
"@
                }
                else {
                    $html += @"
                    <tr><td class="grey">IdentityReference</td><td>$($finding.IdentityReference)</td></tr>
                    <tr><td class="grey">LAPS computers</td><td>$($finding.LAPScomputer -replace "`r?`n", "<br>")</td></tr>
"@
                }
                $html += @"      
                            </table></td>
                            <td class="explanation">
                                <p>The Local Administrator Password Solution (LAPS) is Microsoft’s solution for managing the credentials of a local administrator account on every machine, either the default RID 500 or a custom account. It ensures that the password for each account is different, random, and automatically changed on a defined schedule (default – 30 days). It periodically changes the local administrator's password when it expires. Permission to request and reset the credentials can be delegated, which is also auditable.
                                Installing LAPS requires an update to the schema, where the ms-Mcs-AdmPwd and ms-Mcs-AdmPwdExpirationTime attributes will be added containing the respective LAPS account password and expiration time for accounts. Only groups with delegated permission can read the LAPS password, e.g. Domain Admins, which is random and different across every local admin. Reading the password and then logging into systems via the LAPS local admin accounts also prevents the need to log into systems with other privileged accounts, e.g. domain admins, and avoids caching these credentials in memory on the system, further reducing the attack surface.</p>
                                <p>$($finding.Issue).</p> 
                                <p class="links"><b>Further information:</b></p>
                                <p><a href="https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview">Link 1</a></p>
                                <p><a href="https://www.hackingarticles.in/credential-dumpinglaps/">Link 2</a></p>
                            </td>
                        </tr>
                    </tbody>
                </table>
                
"@
                if ($finding.Technique -eq "LAPS is not utilized on all computers.") {
                    $html += @"
                    <table>
                    <tbody>
                        <tr>
                            <th>Attack explanation</th>
                        </tr>
                        <tr>
                            <td>
                                <div class="attack-container">
                                    <div class="attack-text">
                                        <p>1. If LAPS is not in use, there is a high chance of lateral movement opportunities by reusing the local administrator password. If an attacker manages to compromise one system and dump the local admin password, they can reuse this hash and laterally move to all other systems sharing the same local admin password.</p>
                                        <p class="code">nxc smb 192.168.10.147-205 -u administrator -p 'Password123!' --local-auth</p>
                                    </div>
                                    <span class="image-cell">
                                        <img src="/Private/Report/Images/Passwords/LAPS-not-in-use.png" alt="Local admin password reuse">
                                    </span>
                                </div>
                            </td>
                        </tr>
                    </tbody>
                </table>
                <table>
                    <tbody>
                        <tr>
                            <th>Remediation (GPT to contextualize)</th>
                        </tr>
                        <tr>
                            <td>
                                <p>Install and setup LAPS for all systems</p>
                                <p>run command 1</p>
                                <p>run command 2</p>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </td>
    </tr>
"@
                }
                else {
                    $html += @"
                    <table>
                    <tbody>
                        <tr>
                            <th>Attack explanation</th>
                        </tr>
                        <tr>
                            <td>
                                <div class="attack-container">
                                    <div class="attack-text">
                                        <p>1. Any low-privileged user can remotely enumerate systems that users can read the LAPS password for using bloodhound.</p>
                                    </div>
                                    <span class="image-cell">
                                        <img src="/Private/Report/Images/Passwords/LAPS-1.png" alt="Finding systems where can read the LAPS password">
                                    </span>
                                </div>
                                <hr>
                                <div class="attack-container">
                                <div class="attack-text">
                                    <p>2. An adversary can then simply read the plaintext LAPS password from the target computers ms-Mcs-AdmPwd property from Active Directory, and escalate their privileges to local admins.</p>
                                    <p class="code">nxc ldap dc.test.local -u test -p 'Password123!' -M laps</p>
                                </div>
                                <span class="image-cell">
                                    <img src="/Private/Report/Images/Passwords/LAPS-2" alt="Reading the LAPS password">
                                </span>
                            </div>
                            </td>
                        </tr>
                    </tbody>
                </table>
                <table>
                    <tbody>
                        <tr>
                            <th>Remediation (GPT to contextualize)</th>
                        </tr>
                        <tr>
                            <td>
                                <p>Delegate who can read LAPS password to administrators only</p>
                                <p>run command 1</p>
                                <p>run command 2</p>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </td>
    </tr>
"@
                }              
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
                <tr>
                    <td class="toggle" id="$nospaceid"><u>$($finding.Technique)</u></td>
                    <td class="finding-risk$($finding.Risk)">$($finding.Risk)</td>
                </tr>
                <tr class="finding">
                    <td colspan="3">
                        <div class="finding-info">
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Issue</th>
                                        <th>MITRE ATT&CK ref</th>
                                        <th>Score</th>
                                    </tr>
                                    <tr>
                                        <td>Active Directory description fields are readable by any low-privileged user in the domain.</td>
                                        <td>T-15940</td>
                                        <td>+$($finding.Score)</td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Relevant info</th>
                                        <th>Issue explanation</th>
                                    </tr>
                                    <tr>
                                        <td class="relevantinfo"><table>
"@
                if($finding.Technique = "Plaintext credentials found in a standard user's Active Directory description field") {
                    $html += @"
                                <tr><td class="grey">User</td><td>$($finding.User -replace "`r?`n", "<br>")</td></tr>
                                <tr><td class="grey">Description</td><td>$($finding.Description)</td></tr>
"@
                } else{
                    $html += @"
                                <tr><td class="grey">User</td><td>$($finding.User -replace "`r?`n", "<br>")</td></tr>
                                <tr><td class="grey">MemberOf</td><td>$($finding.MemberOf -replace "`r?`n", "<br>")</td></tr>
                                <tr><td class="grey">Description</td><td>$($finding.Description -replace "`r?`n", "<br>")</td></tr>
"@
                }
                $html += @"
                                        </table></td>
                                        <td class="explanation">
                                            <p>Whilst storing user passwords in Active Directory description fields may seem convient, doing this exposes the user's credentials to all users in the domain as any user can read any user's description field within AD.</p>
                                            <p>$($finding.issue) .</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://hackdefense.com/publications/wachtwoorden-in-het-omschrijvingen-veld/">Link 1</a></p>
                                            <p><a href="https://medium.com/beyond-the-helpdesk/easily-configure-confidential-attributes-in-active-directory-769bd2b9d12c">Link 2</a></p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Attack explanation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>1. Any low-privileged user can read all active directory descripion fields to find sensitive information like passwords.</p>
                                                    <p class="code">ldapsearch -H ldap://dc.test.local -x -b "DC=test,DC=local" -D 'test' -w 'Password123!' "(&(objectClass=user)(samaccountname=jack))"</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Passwords/Userdescription.png" alt="Reading AD description field">
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation (GPT to contextualize)</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>Remove sensitive info from AD description field, confidential attributes can be used in the schema alternatively</p>
                                            <p>run command 1</p>
                                            <p>run command 2</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@  
            }
        }
        $html += "</tbody></table></div>"
    }
    return $html
}