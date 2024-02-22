function to_red ($msg) {
    "$([char]0x1b)[91m$msg$([char]0x1b)[0m"
}
function Find-LegacyProtocols {
    <#
  .SYNOPSIS
  Searches for legacy protocols within AD that are no longer considered secure. These protocols include LLMNR, NBT-NS, and MDNS, NTLMv1 and SMBv1
  LLMNR, NBT-NS and mDNS are registry checks as should be disabled on all devices via GPO.
  NTLMv1 and SMBv1 are checked via GPOs to see if they are disabled.


  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-LegacyProtocols -Domain test.local

  #>
 
    #Add mandatory domain parameter
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [String]
        $Domain
    )

    Write-Host '[*] Finding legacy protocols..' -ForegroundColor Yellow
  
    #Dynamically produce searchbase from domain parameter
    $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
    $searchBase = $SearchBaseComponents -join ','


    #########
    # LLMNR #
    #########
    try {
        $llmnr = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -name EnableMulticast -ErrorAction Ignore
        if ($llmnr.EnableMulticast -ne 0) {
            $Issue = [pscustomobject]@{
                Domain    = $Domain
                Issue     = "LLMNR is a legacy name resolution protocol not disabled in $domain via GPO"
                Technique = (to_red "[HIGH]") + " LLMNR is vulnerable to layer 2 poisoning attacks"
            }
            $Issue
        }
    }
    catch {
        Write-Error $_  #LLMNR is not configured
    }

    ##########
    # NBT-NS #
    ##########
    $nbtns = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\netbt\Parameters\interfaces\tcpip_*' -name NetBiosOptions -ErrorAction Ignore
    if ($nbtns.NetBiosOptions -ne 2) {
        $Issue = [pscustomobject]@{
            Domain    = $Domain
            Issue     = "NBT-NS is a legacy name resolution protocol not disabled in $domain via GPO"
            Technique = (to_red "[HIGH]") + " NBT-NS is vulnerable to layer 2 poisoning attacks"
        }
        $Issue
    }
    else {
        #NBT-NS is configured - maybe include in report as good thing
    }

    ########
    # mDNS #
    ########
    try {
        $mdns = Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\' -name EnableMDNS -ErrorAction Ignore
        if ($mdns.EnableMulticast -ne 0) {
            $Issue = [pscustomobject]@{
                Domain    = $Domain
                Issue     = "mDNS is a legacy name resolution protocol not disabled in $domain via GPO"
                Technique = (to_red "[HIGH]") + " mDNS is vulnerable to layer 2 poisoning attacks"
            }
            $Issue
        } 
    }
    catch {
        Write-Error $_    #mDNS is not configured
    }

    ##########
    # NTLMv1 #   
    ##########
    #LMCompatibilityLevel likely to be set in these GPOs, if configured
    $report = Get-GPOReport -Name 'Default Domain Controllers Policy' -ReportType html
    $report += Get-GPOReport -Name 'Default Domain Policy' -ReportType html
    
    # Use regex to find the line containing "the LMCompatiilitylevel" and extract content within <td> tags
    $pattern = 'Network security: LAN Manager authentication level<\/td><td>(.*?)<\/td>'
    $LMcompatibilitylevel = $report | Select-String -Pattern $pattern -AllMatches | ForEach-Object { $_.Matches.Groups[1].Value }

    #check if NTLMv1 is refused
    if ($LMcompatibilitylevel -ne "Send NTLMv2 response only. Refuse LM &amp; NTLM" ) {
        $Issue = [pscustomobject]@{
            Domain               = $Domain
            LMCompatibilityLevel = $LMcompatibilitylevel
            Issue                = "NTLMv1 is permitted for authentication neogiration with domain controllers. The LM Compatibility level is not set to 'Send NTLMv2 response only. Refuse LM & NTLM' in the Default Domain Controllers GPO"
            Technique            = (to_red "[HIGH]") + " NTLMv1 is not disabled on domain controllers"
        }
        $Issue
    }#if not configured, can be permitted depending on the OS version
    elseif ($LMcompatibilitylevel -not $present -and $dcOS -le 2016 )
    $Issue = [pscustomobject]@{
        Domain               = $Domain
        LMCompatibilityLevel = "Default"
        DomainControllerOS   = $dcOS
        Issue                = "NTLMv1 is permitted by default for authentication negotiation with domain controllers. The LM Compatibility level is not set to 5 via the Default Domain Controllers GPO, taking the insecure default to accept NTLMv1 negotiations"
        Technique            = (to_red "[HIGH]") + " NTLMv1 is not disabled on domain controllers"
    }
    $Issue


    #########
    # SMBv1 #
    #########
