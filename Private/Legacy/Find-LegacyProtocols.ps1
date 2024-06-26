function Find-LegacyProtocols {
    <#
  .SYNOPSIS
  Searches for legacy protocols within AD that are no longer considered secure. These protocols include LLMNR, NBT-NS, and MDNS, NTLMv1 and SMBv1
  LLMNR, NBT-NS and mDNS are registry checks as should be disabled on all devices via GPO.
  NTLMv1 is checked if the LMcompatibilitylevel via GPO
  SMBv1 is checked by negotiating an SMB connection which each domain computer, inspired from https://github.com/tmenochet/PowerScan/blob/master/Recon/Get-SmbStatus.ps1


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

    Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Finding legacy protocols..." -ForegroundColor Yellow
  
    #Dynamically produce searchbase from domain parameter
    $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
    $searchBase = $SearchBaseComponents -join ','

    #########
    # LLMNR #
    #########
    Write-Host "Checking LLMNR..." -ForegroundColor Yellow
    try {
        $llmnr = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -name EnableMulticast -ErrorAction Ignore
        if ($llmnr.EnableMulticast -ne 0) {
            $Issue = [pscustomobject]@{
                Risk        = (to_red "HIGH")
                Technique   = "LLMNR is not disabled"
                Score       = 25
                RegistryKey = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMultiCast"
                CorrectValue = "0"
                Issue       = "LLMNR is a legacy name resolution protocol that is vulnerable to layer 2 poisoning attacks and is not disabled in $domain via GPO"
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
    Write-Host "Checking NBT-NS..." -ForegroundColor Yellow
    $nbtns = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\netbt\Parameters\interfaces\tcpip_*' -name NetBiosOptions -ErrorAction Ignore
    if ($nbtns.NetBiosOptions -ne 2) {
        $Issue = [pscustomobject]@{
            Risk        = (to_red "HIGH")
            Technique   = "NBT-NS is not disabled"
            Score       = 25
            RegistryKey = "HKLM:\SYSTEM\CurrentControlSet\Services\netbt\Parameters\interfaces\tcpip_*\NetBiosOptions"
            CorrectValue = "2"
            Issue       = "NBT-NS is a legacy name resolution protocol that is vulnerable to layer 2 poisoning attacks and is not disabled in $domain via GPO"
        }
        $Issue
    }
    else {
        #NBT-NS is configured - maybe include in report as good thing
    }

    ########
    # mDNS #
    ########
    Write-Host "Checking mDNS..." -ForegroundColor Yellow
    try {
        $mdns = Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\' -name EnableMDNS -ErrorAction Ignore
        if ($mdns.EnableMulticast -ne 0) {
            $Issue = [pscustomobject]@{
                Risk        = (to_red "HIGH")
                Technique   = "mDNS is not disabled"
                Score       = 25
                RegistryKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableMDNS"
                CorrectValue = "0"
                Issue       = "mDNS is a legacy name resolution protocol that is vulnerable to layer 2 poisoning attacks and is not disabled in $domain via GPO"
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
    Write-Host "Checking NTLMv1..." -ForegroundColor Yellow
    #LMCompatibilityLevel likely to be set in these GPOs, if configured
    $report = Get-GPOReport -Name 'Default Domain Controllers Policy' -ReportType html
    $report += Get-GPOReport -Name 'Default Domain Policy' -ReportType html
    
    # Use regex to find the line containing "the LMCompatiilitylevel" and extract content within <td> tags
    $pattern = 'Network security: LAN Manager authentication level<\/td><td>(.*?)<\/td>'
    $LMcompatibilitylevel = $report | Select-String -Pattern $pattern -AllMatches | ForEach-Object { $_.Matches.Groups[1].Value }

    #Get domain controllers OS version
    Get-ADDomainController -Filter * | ForEach-Object {
        $dcOS = $_.OperatingSystem
    }

    #if not explitly configured, NTLMv1 can be permitted depending on the OS version
    if ($null -eq $LMcompatibilitylevel -and ($dcOS -notmatch "2016" -and $dcOS -notmatch "2019" -and $dcOS -notmatch "2022" )) {
        $Issue = [pscustomobject]@{
            Risk                 = (to_red "CRITICAL")
            Technique            = "NTLMv1 is not disabled on domain controllers"
            Score                = 50
            LMCompatibilityLevel = "Default 1/2"
            DomainControllerOS   = $dcOS
            Issue                = "NTLMv1 is permitted by default for authentication negotiation with domain controllers. The LM Compatibility level is not set to 5 via the Default Domain Controllers GPO, taking the insecure default to accept NTLMv1 negotiations"
        }
        $Issue
    }
    #check if NTLMv1 is refused
    elseif ($null -ne $LMcompatibilitylevel -and $LMcompatibilitylevel -notmatch "Send NTLMv2 response only" ) {
        $Issue = [pscustomobject]@{
            Risk                 = (to_red "CRITICAL")
            Technique            = "NTLMv1 is not disabled"
            Score                = 50
            LMCompatibilityLevel = $LMcompatibilitylevel
            Issue                = "NTLMv1 is permitted for authentication negotiation with domain controllers. The LM Compatibility level is not set to 'Send NTLMv2 response only. Refuse LM & NTLM' in the Default Domain Controllers GPO"
        }
        $Issue
    }
    
    #####################################################
    # SMBv1  - modified version of SMB signing function #
    #####################################################
    function Get-SMBv1 {
        Param (
            $ComputerName, 
            $Timeout
        )
        $SMBv1 = Get-SmbVersionStatus -ComputerName $ComputerName -SmbVersion 'SMB1' -Timeout $Timeout
        return $SMBv1
    }

    #convert raw SMB packet to byte array
    function ConvertFrom-PacketOrderedDictionary ($packet_ordered_dictionary) {
        $byte_array = @()
        foreach ($field in $packet_ordered_dictionary.Values) {
            $byte_array += $field
        }
        return $byte_array
    }

    function Get-PacketNetBIOSSessionService {
        Param (
            $packet_header_length,
            $packet_data_length
        )
        [Byte[]] $packet_netbios_session_service_length = [BitConverter]::GetBytes($packet_header_length + $packet_data_length)
        $packet_NetBIOS_session_service_length = $packet_netbios_session_service_length[2..0]
        $packet_NetBIOSSessionService = New-Object Collections.Specialized.OrderedDictionary
        $packet_NetBIOSSessionService.Add("NetBIOSSessionService_Message_Type", [Byte[]](0x00))
        $packet_NetBIOSSessionService.Add("NetBIOSSessionService_Length", $packet_netbios_session_service_length)
        return $packet_NetBIOSSessionService
    }

    #get SMB header
    function Get-PacketSMBHeader {
        Param (
            $packet_command,
            $packet_flags,
            $packet_flags2,
            $packet_tree_ID,
            $packet_process_ID,
            $packet_user_ID
        )

        $packet_SMBHeader = New-Object Collections.Specialized.OrderedDictionary
        $packet_SMBHeader.Add("SMBHeader_Protocol", [Byte[]](0xff, 0x53, 0x4d, 0x42))
        $packet_SMBHeader.Add("SMBHeader_Command", $packet_command)
        $packet_SMBHeader.Add("SMBHeader_ErrorClass", [Byte[]](0x00))
        $packet_SMBHeader.Add("SMBHeader_Reserved", [Byte[]](0x00))
        $packet_SMBHeader.Add("SMBHeader_ErrorCode", [Byte[]](0x00, 0x00))
        $packet_SMBHeader.Add("SMBHeader_Flags", $packet_flags)
        $packet_SMBHeader.Add("SMBHeader_Flags2", $packet_flags2)
        $packet_SMBHeader.Add("SMBHeader_ProcessIDHigh", [Byte[]](0x00, 0x00))
        $packet_SMBHeader.Add("SMBHeader_Signature", [Byte[]](0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))
        $packet_SMBHeader.Add("SMBHeader_Reserved2", [Byte[]](0x00, 0x00))
        $packet_SMBHeader.Add("SMBHeader_TreeID", $packet_tree_ID)
        $packet_SMBHeader.Add("SMBHeader_ProcessID", $packet_process_ID)
        $packet_SMBHeader.Add("SMBHeader_UserID", $packet_user_ID)
        $packet_SMBHeader.Add("SMBHeader_MultiplexID", [Byte[]](0x00, 0x00))
        return $packet_SMBHeader
    }
    #negotiate SMB version
    function Get-PacketSMBNegotiateProtocolRequest ($packet_version) {
        if ($packet_version -eq 'SMB1') {
            [Byte[]] $packet_byte_count = 0x0c, 0x00
        }
        else {
            [Byte[]] $packet_byte_count = 0x22, 0x00
        }
        $packet_SMBNegotiateProtocolRequest = New-Object Collections.Specialized.OrderedDictionary
        $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_WordCount", [Byte[]](0x00))
        $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_ByteCount", $packet_byte_count)
        $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat", [Byte[]](0x02))
        $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name", [Byte[]](0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00))
        if ($packet_version -ne 'SMB1') {
            $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat2", [Byte[]](0x02))
            $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name2", [Byte[]](0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x30, 0x30, 0x32, 0x00))
            $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat3", [Byte[]](0x02))
            $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name3", [Byte[]](0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x3f, 0x3f, 0x3f, 0x00))
        }
        return $packet_SMBNegotiateProtocolRequest
    }
    #get SMB version from SMB negotiation
    function Get-SmbVersionStatus {
        Param (
            $ComputerName,
            $SmbVersion = 'SMB2',
            $Timeout
        )

        $process_ID = [Diagnostics.Process]::GetCurrentProcess() | Select-Object -ExpandProperty Id
        $process_ID = [BitConverter]::ToString([BitConverter]::GetBytes($process_ID))
        $process_ID = $process_ID.Replace("-00-00", "")
        [Byte[]] $process_ID_bytes = $process_ID.Split("-") | ForEach-Object { [Char][Convert]::ToInt16($_, 16) }

        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.ReceiveTimeout = $Timeout

        try {
            $tcpClient.Connect($ComputerName, "445")
            if ($tcpClient.connected) {
                $SMB_relay_challenge_stream = $tcpClient.GetStream()
                $SMB_client_receive = New-Object Byte[] 1024
                $SMB_client_stage = 'NegotiateSMB'

                while ($SMB_client_stage -ne 'exit') {
                    switch ($SMB_client_stage) {
                        'NegotiateSMB' {
                            $packet_SMB_header = Get-PacketSMBHeader 0x72 0x18 0x01, 0x48 0xff, 0xff $process_ID_bytes 0x00, 0x00
                            $packet_SMB_data = Get-PacketSMBNegotiateProtocolRequest $SmbVersion
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                            $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                            $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                            $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                            $SMB_relay_challenge_stream.Write($SMB_client_send, 0, $SMB_client_send.Length) > $null
                            $SMB_relay_challenge_stream.Flush()
                            $SMB_relay_challenge_stream.Read($SMB_client_receive, 0, $SMB_client_receive.Length) > $null
                            if ([BitConverter]::ToString($SMB_client_receive[4..7]) -eq 'ff-53-4d-42') {
                                $SmbVersion = 'SMB1'
                                $SMB_client_stage = 'NTLMSSPNegotiate'
                                $SMBv1_enabled = $true
                            }
                            else {
                                $SMB_client_stage = 'NegotiateSMB2'
                            }
                            $tcpClient.Close()
                            $SMB_client_receive = $null
                            $SMB_client_stage = 'exit'
                        }
                    }
                }
            }
        }

        catch { return "Unable to connect" }
        finally { $tcpClient.Close() }
        return $SMBv1_enabled
    }
    
    #Get all computers in domain to check for smbsigning
    $ADComputers = (Get-ADComputer -SearchBase $SearchBase -LDAPFilter '(objectCategory=computer)').dnshostname
 
    #Remove any null values (as will make SMB checks run for a long time)
    $ADComputers = $ADComputers | ? { $_ }

    #Intialise issue
    $SMBv1Issue = [pscustomobject]@{
        Risk           = (to_red "HIGH")
        Technique      = "SMBv1 is not disabled on computers"
        Score          = 25
        SMBv1Computers = ""
        Count          = ""
        Issue          = ""
    }
    $SMBv1count = 0

    $timeout = 1
    #check all active computers in domain for SMBv1
    foreach ($computer in $ADComputers) {
        $ping = New-Object System.Net.NetworkInformation.Ping
        $reply = $ping.Send($computer, $Timeout * 1000)
  
        #If host is active, try SMBv1 negotiation
        if ($reply.Status -eq 'Success') {
            Write-Host "Checking $computer for SMBv1... " -ForegroundColor Yellow
            $GetSMBv1 = Get-SMBv1 -ComputerName $computer -Timeout 2 
        
            if ($GetSMBv1 -eq $true) {
                if ($SMBv1Issue.SMBv1Computers -eq '') {
                    $SMBv1Issue.SMBv1Computers += $computer
                }
                else {
                    $SMBv1Issue.SMBv1Computers += "`r`n$computer"
                }
                $SMBv1count++
            }
        }
    }
    if ($SMBv1Issue.SMBv1Computers -ne '') {
        $SMBv1issue.Issue = "SMBv1 is enabled on $SMBv1count computers. All of these computers could be vulnerable to EternalBlue and other SMBv1 exploits facilitating DoS and RCE"
        $SMBv1issue.Count = $SMBV1count
        $SMBv1Issue
    }
}