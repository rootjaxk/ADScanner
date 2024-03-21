function Generate-RBAChtml {  
    param (
        [array]$RBAC
    )
    if (!$RBAC) {
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
        foreach ($finding in $RBAC) {
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
                                <tr><td class="grey">MachineAccountQuota</td><td>$($finding.MachineAccountQuota)</td></tr>
                                <tr><td class="grey">Permission to add workstations</td><td>$($finding.PermissiontoAddWorkstations)</td></tr>
                            </table></td>
                            <td class="explanation">
                                <p>By default, in Active Directory any authenticated domain user can add a total of 10 computers (machine accounts) to the domain. The number of computers is controlled by the 'ms-DS-MachineAccountQuota' property of the domain, and permission for who can add computers is controlled within the 'Default Domain Controllers Policy' GPO. Computers accounts added by users can be used in attacks such as RBCD or relaying attacks where the computer account can be configured in a way that gives an attacker administrative control by permitting delegation to other critical servers, allowing low-privileged users to escalate their privileges. This default configuration represents a security issue as basic users shouldn't be able to create such accounts and this task should be handled by administrators.</p>
                                <p>$($finding.Issue).</p> 
                                <p class="links"><b>Further information:</b></p>
                                <p><a href="https://www.thehacker.recipes/a-d/movement/domain-settings/machineaccountquota">Link 1</a></p>
                                <p><a href="https://sid-500.com/2017/09/09/securing-active-directory-who-can-add-computers-to-the-domain-only-the-domain-admin-are-you-sure/">Link 2</a></p>
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
                                        <p>1. Any low-privileged user can enumerate the 'ms-DS-MachineAccountQuota' property to view how many computers they can add to the domain. By default this is set to 10.</p>
                                        <p class="code">nxc ldap dc.test.local -u test -p 'Password123!' -M maq</p>
                                    </div>
                                    <span class="image-cell">
                                        <img src="/Private/Report/Images/MISC/MAQ-1.png" alt="Finding the machineaccountquota">
                                    </span>
                                </div>
                                <hr>
                                <div class="attack-container">
                                    <div class="attack-text">
                                        <p>2. Any low-privileged user can add a computer account to the domain choosing the credentials for the computer they desire.</p>
                                        <p class="code">impacket-addcomputer -computer-name 'attackerComputer$' -computer-pass 'h4x' test.local/test:'Password123!'</p> 
                                        <p>The added computer can be use to authenticate to resources such as file shares just as a low-privileged user can.</p> 
                                        <p class="code">nxc smb dc.test.local -u 'attackerComputer$' -p 'h4x' --shares</p>          
                                    </div>
                                    <span class="image-cell">
                                        <img src="/Private/Report/Images/MISC/MAQ-2.png" alt="Adding and using the computer account">
                                    </span>
                                </div>
                                <hr>
                                <div class="attack-container">
                                    <div class="attack-text">
                                        <p>3. The added computer can be seen joined to the domain.</p>           
                                    </div>
                                    <span class="image-cell">
                                        <img src="/Private/Report/Images/MISC/MAQ-3.png" alt="Viewing the added machine">
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
                                <p>Change the MAQ to 0</p>
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
            elseif ($finding.Technique -match "anonymous access is permitted") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
            elseif ($finding.Technique -match "Inactive/stale") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
            elseif ($finding.Technique -match "Administrators group") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
            elseif ($finding.Technique -match "Domain Admins group") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
            elseif ($finding.Technique -match "Enterprise Admins group") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
            elseif ($finding.Technique -match "DnsAdmins group") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
            elseif ($finding.Technique -match "Backup Operators group") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
            elseif ($finding.Technique -match "Server Operators group") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
            elseif ($finding.Technique -match "Account Operators group") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
            elseif ($finding.Technique -match "Print Operators group") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
            elseif ($finding.Technique -match "Remote Desktop Users group") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
            elseif ($finding.Technique -match "Remote Management Users group") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
            elseif ($finding.Technique -match "Schema Admins group") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
            elseif ($finding.Technique -match "Protected Users group") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
            elseif ($finding.Technique -match "Account is sensitive") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
"@
            }
        }
        $html += "</tbody></table></div>"
    }
    return $html
}