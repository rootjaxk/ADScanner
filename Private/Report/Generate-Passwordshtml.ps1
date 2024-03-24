function Generate-Passwordshtml {  
    param (
        [array]$Passwords
    )
    if (!$Passwords) {
        $html = @"
        <div class="finding-header">Passwords</div>
        <h2 class="novuln">No vulnerabilities found!</h2>
"@
    }
    else {
        $html = @"
        <div class="finding-header">Passwords</div>
        <div class="domain-info">
            <p>This section contains technical vulnerability details relating to password issues.</p>
        </div>
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
             #replace console colours 
             if($finding.Risk -match "critical"){
                $finding.Risk = "CRITICAL"
            } elseif ($finding.Risk -match "high"){
                $finding.Risk = "HIGH"
            } elseif ($finding.Risk -match "medium"){
                $finding.Risk = "MEDIUM"
            } elseif ($finding.Risk -match "low"){
                $finding.Risk = "LOW"
            } elseif ($finding.Risk -match "informational"){
                $finding.Risk = "INFORMATIONAL"
            }
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
                    $html += "<td>TA0006, TA0008</td>"
                }
                else {
                    $html += "<td>A low-privileged user can escalate to local admin priviliges by reading the LAPS password.</td>"
                    $html += "<td>TA0006, TA0008, T1552</td>"
                }
                $html += @"
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
                                    <img src="/Private/Report/Images/Passwords/LAPS-2.png" alt="Reading the LAPS password">
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
                                        <td>Weak passwords are permitted by the password policy.</td>
                                        <td>TA0001, TA0006</td>
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
                                            <tr><td class="grey">ComplexityEnabled</td><td>$($finding.ComplexityEnabled)</td></tr>
                                        
                                        </table></td>
                                        <td class="explanation">
                                            <p>A weak domain password policy allow users to set weak passwords that can be easily guessed by attackers to compromise their accounts.</p>
                                            <p>$($finding.issue)</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://www.netwrix.com/password-policy-best-practices.html">Link 1</a></p>
                                            <p><a href="https://learn.microsoft.com/en-GB/entra/identity/authentication/concept-password-ban-bad-on-premises">Link 2</a></p>
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
                                                    <p>1. Low-privileged users can enumerate the password policy for the domain. If complexity is not enforced, attackers can passwordspray common passwords to gain access to user accounts.</p>
                                                    <p class="code">nxc smb dc.test.local -u test -p 'Password123!' --pass-pol</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Passwords/passwordpolicy.png" alt="Finding weak password policy">
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
                                            <p>Improve the password policy</p>
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
            elseif ($finding.Technique -eq "Password length requirement is less than 12 characters") {
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
                                        <td>Weak passwords are permitted by the password policy.</td>
                                        <td>TA0001, TA0006</td>
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
                                            <tr><td class="grey">Minimum password length</td><td>$($finding.Length)</td></tr>
                                        
                                        </table></td>
                                        <td class="explanation">
                                            <p>A weak domain password policy allow users to set weak passwords that can be easily guessed by attackers to compromise their accounts.</p>
                                            <p>$($finding.issue)</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://www.netwrix.com/password-policy-best-practices.html">Link 1</a></p>
                                            <p><a href="https://learn.microsoft.com/en-GB/entra/identity/authentication/concept-password-ban-bad-on-premises">Link 2</a></p>
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
                                                    <p>1. Low-privileged users can enumerate the password policy for the domain. If the password length is short, attackers can passwordspray common weak passwords to gain access to user accounts.</p>
                                                    <p class="code">nxc smb dc.test.local -u test -p 'Password123!' --pass-pol</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Passwords/passwordpolicy.png" alt="Finding weak password policy">
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
                                            <p>Improve the password policy</p>
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
            elseif ($finding.Technique -eq "Account lockout threshold is greater than 10") {
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
                                        <td>Account passwords can be bruteforced due to a large lockout threshold.</td>
                                        <td>TA0001, TA0006</td>
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
                                            <tr><td class="grey">Account lockout threshold</td><td>$($finding.LockoutThreshold)</td></tr>
                                        
                                        </table></td>
                                        <td class="explanation">
                                            <p>A weak domain password policy allow users to set weak passwords that can be easily guessed by attackers to compromise their accounts.</p>
                                            <p>$($finding.issue)</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://www.netwrix.com/password-policy-best-practices.html">Link 1</a></p>
                                            <p><a href="https://learn.microsoft.com/en-GB/entra/identity/authentication/concept-password-ban-bad-on-premises">Link 2</a></p>
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
                                                    <p>1. Low-privileged users can enumerate the password policy for the domain. If a lockout threshold is too large, attackers can bruteforce an unlimited number (e.g. millions) of passwords against an account to guess the password.</p>
                                                    <p class="code">nxc smb dc.test.local -u test -p 'Password123!' --pass-pol</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Passwords/passwordpolicy.png" alt="Finding weak password policy">
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
                                            <p>Improve the password policy</p>
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
            elseif ($finding.Technique -eq "The minimum password age is less than 1 day") {
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
                                        <td>Weak password policy permits user to set an old password.</td>
                                        <td>TA0006</td>
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
                                            <tr><td class="grey">Minimum password age</td><td>$($finding.MinPasswordAge)</td></tr>
                                        
                                        </table></td>
                                        <td class="explanation">
                                            <p>A weak domain password policy allow users to set weak passwords that can be easily guessed by attackers to compromise their accounts.</p>
                                            <p>$($finding.issue)</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://www.netwrix.com/password-policy-best-practices.html">Link 1</a></p>
                                            <p><a href="https://learn.microsoft.com/en-GB/entra/identity/authentication/concept-password-ban-bad-on-premises">Link 2</a></p>
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
                                                    <p>1. Low-privileged users can enumerate the password policy for the domain. If a minimum password age is not set, a user can reset their password multiple times cycling through the passwordhistory and set an older password, which may be reused across other systems and is more likely to be compromised.</p>
                                                    <p class="code">nxc smb dc.test.local -u test -p 'Password123!' --pass-pol</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Passwords/passwordpolicy.png" alt="Finding weak password policy">
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
                                            <p>Improve the password policy</p>
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
            elseif ($finding.Technique -eq "The maximum password age is less than 365 days") {
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
                                        <td>Weak password policy forces users to reset their passwords too often.</td>
                                        <td>TA0006</td>
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
                                            <tr><td class="grey">Maximum password age</td><td>$($finding.MaxPasswordAge)</td></tr>
                                        
                                        </table></td>
                                        <td class="explanation">
                                            <p>A weak domain password policy allow users to set weak passwords that can be easily guessed by attackers to compromise their accounts.</p>
                                            <p>$($finding.issue)</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://www.netwrix.com/password-policy-best-practices.html">Link 1</a></p>
                                            <p><a href="https://learn.microsoft.com/en-GB/entra/identity/authentication/concept-password-ban-bad-on-premises">Link 2</a></p>
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
                                                    <p>1. Low-privileged users can enumerate the password policy for the domain. If the minimum password age is too short users are more likely to set easy to remember, weak passwords, that are thereby easier for an attacker to guess.</p>
                                                    <p class="code">nxc smb dc.test.local -u test -p 'Password123!' --pass-pol</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Passwords/passwordpolicy.png" alt="Finding weak password policy">
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
                                            <p>Improve the password policy</p>
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
            elseif ($finding.Technique -eq "The password history count is less than 24") {
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
                                        <td>Weak password policy permits user to set an old password.</td>
                                        <td>TA0006</td>
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
                                            <tr><td class="grey">PasswordHistoryCount</td><td>$($finding.PasswordHistoryCount)</td></tr>
                                        
                                        </table></td>
                                        <td class="explanation">
                                            <p>A weak domain password policy allow users to set weak passwords that can be easily guessed by attackers to compromise their accounts.</p>
                                            <p>$($finding.issue)</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://www.netwrix.com/password-policy-best-practices.html">Link 1</a></p>
                                            <p><a href="https://learn.microsoft.com/en-GB/entra/identity/authentication/concept-password-ban-bad-on-premises">Link 2</a></p>
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
                                                    <p>1. Low-privileged users can enumerate the password policy for the domain. If a low password history is not set, a user can reset their password multiple times cycling through the passwordhistory and set an older password, which may be reused across other systems and is more likely to be compromised.</p>
                                                    <p class="code">nxc smb dc.test.local -u test -p 'Password123!' --pass-pol</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Passwords/passwordpolicy.png" alt="Finding weak password policy">
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
                                            <p>Improve the password policy</p>
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
            elseif ($finding.Technique -eq "The account lockout duration is less than 15 minutes") {
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
                                        <td>Account passwords can be bruteforced due to a short account lockout duration.</td>
                                        <td>TA0001, TA0006</td>
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
                                            <tr><td class="grey">Account lockout duration</td><td>$($finding.LockoutDuration)</td></tr>
                                        
                                        </table></td>
                                        <td class="explanation">
                                            <p>A weak domain password policy allow users to set weak passwords that can be easily guessed by attackers to compromise their accounts.</p>
                                            <p>$($finding.issue)</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://www.netwrix.com/password-policy-best-practices.html">Link 1</a></p>
                                            <p><a href="https://learn.microsoft.com/en-GB/entra/identity/authentication/concept-password-ban-bad-on-premises">Link 2</a></p>
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
                                                    <p>1. Low-privileged users can enumerate the password policy for the domain. If a lockout duration is too short, attackers can try a number of password attempts for an account, wait the short period for the lockout duration to expire, then try another set of password attempts whichc an be automated by a determined attacker.</p>
                                                    <p class="code">nxc smb dc.test.local -u test -p 'Password123!' --pass-pol</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Passwords/passwordpolicy.png" alt="Finding weak password policy">
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
                                            <p>Improve the password policy</p>
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
            elseif ($finding.Technique -eq "Reversible encryption is enabled") {
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
                                        <td>Passwords are stored in memory in plaintext.</td>
                                        <td>T1556.005, TA0006</td>
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
                                            <tr><td class="grey">Reverse encryption enabled</td><td>$($finding.ReverseEncryption)</td></tr>
                                        
                                        </table></td>
                                        <td class="explanation">
                                            <p>A weak domain password policy allow users to set weak passwords that can be easily found by attackers to compromise their accounts.</p>
                                            <p>$($finding.issue)</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://www.netwrix.com/password-policy-best-practices.html">Link 1</a></p>
                                            <p><a href="https://learn.microsoft.com/en-GB/entra/identity/authentication/concept-password-ban-bad-on-premises">Link 2</a></p>
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
                                                    <p>1. Low-privileged users can enumerate the password policy for the domain. If passwords are stored with reversible encryption they can be extracted from a computer's system memory by an attacker.</p>
                                                    <p class="code">nxc smb dc.test.local -u test -p 'Password123!' --pass-pol</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Passwords/passwordpolicy.png" alt="Finding weak password policy">
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
                                            <p>Improve the password policy</p>
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
            elseif ($finding.Technique -match "does not require a password") {
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
                                        <td>User account may have a blank password set (PASSWD_NOTREQD).</td>
                                        <td>TA0001, TA0006</td>
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
                                        <tr><td class="grey">Users</td><td>$($finding.Users -replace "`r?`n", "<br>")</td></tr>
"@
                if ($finding.Technique -match "Highly privileged"){
                    $html += @"
                    <tr><td class="grey">MemberOf</td><td>$($finding.MemberOf -replace "`r?`n", "<br>")</td></tr>
"@
                }
                $html += @"
                    <tr><td class="grey">PASSWD_NOTREQD</td><td>True</td></tr>
                    <tr><td class="grey">Enabled</td><td>$($finding.Enabled)</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>Users with the PASSWD_NOTREQD attribute set in Active Directory may have a blank password set This means simply knowing the account username will be enough to login and authenticte as that user, providing an attacker unauthenticatd access to the domain.</p>
                                            <p>$($finding.issue)</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://specopssoft.com/blog/find-ad-accounts-using-password-not-required-blank-password/">Link 1</a></p>
                                            <p><a href="https://activedirectorypro.com/find-accounts-with-password-not-required-blank-password/">Link 2</a></p>
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
                                                    <p>1. An unauthenticated attacker can spray empty passwords against users in the hopes that some have blank passwords set. This allows an unauthorised attacker access to the same domain resources as an authenticated user, giivng a foothold to escalate within the domain.</p>
                                                    <p class="code">nxc smb dc.test.local -u emptypasswd -p '' --shares</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Passwords/pwdnotrequired.png" alt="Finding users without a password required">
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
                                            <p>Remove PASSWD_NOTREQD attribute from all users</p>
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
            elseif ($finding.Technique -eq "Plaintext credentials found readable by low privileged user") {
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
                                        <td>Files within SYSVOL can be read by any low-privileged user.</td>
                                        <td>TA0006, T1552</td>
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
                                            <tr><td class="grey">File</td><td>$($finding.File -replace "`r?`n", "<br>")</td></tr>
                                            <tr><td class="grey">Credential</td><td>$($finding.Credential -replace "`r?`n", "<br>")</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>Files within SYSVOL such as logon scripts often store hardcoded credentials used for things like mounting drives or running administrative tasks. What is not so well known is these files are readable and can be accessed by any low-privileged user.</p>
                                            <p>$($finding.issue)</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://www.sentinelone.com/blog/credentials-harvesting-from-domain-shares/">Link 1</a></p>
                                            <p><a href="https://offsec.blog/hidden-menace-how-to-identify-misconfigured-and-dangerous-logon-scripts/">Link 2</a></p>
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
                                                    <p>1. Low-privileged users can search for sensitive information like passwords in any file stored on SYSVOL which often finds passwords hardcoded in logon scripts.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Passwords/Sensitiveinfo.png" alt="Finding sensitive infomation in SYSVOL">
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
                                            <p>Remove hardcoded credentials from SYSVOL</p>
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
                                        <td>TA0006, T1552</td>
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
                                            <p>Whilst storing passwords within description fields in AD may seem convenient, however it should be noted that by default any authenticated user can read the description for any domain user, so storing passwords here effectively shares the password with everyone in the network.</p>
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