function Find-SMBSigning {
    <#
  .SYNOPSIS
  Searches all computers / servers in AD to find those that do not not require SMB signing
  Inspired from https://github.com/tmenochet/PowerScan/blob/master/Recon/Get-SmbStatus.ps1

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-SMBSigning -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Finding SMB signing...' -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  
  #Get all computers in domain to check for smbsigning
  $ADComputers = (Get-ADComputer -SearchBase $SearchBase -LDAPFilter '(objectCategory=computer)').dnshostname
 
  #Remove any null values (as will make SMBsigning run for a very long time)
  $ADComputers = $ADComputers | ? { $_ }

  function Get-SMBSigning {
    Param ([string]$ComputerName, $Timeout)

    $SMB1 = Get-SmbVersionStatus -ComputerName $ComputerName -SmbVersion 'SMB1' -Timeout $Timeout
    $SMB2 = Get-SmbVersionStatus -ComputerName $ComputerName -SmbVersion 'SMB2' -Timeout $Timeout

    if ($SMB1.SigningStatus -or $SMB2.SigningStatus) {
        $Signing = "required" 
    } else { $Signing = "not required" }
    return $Signing
    }

    function ConvertFrom-PacketOrderedDictionary ($packet_ordered_dictionary) {
        $byte_array = @()
        foreach ($field in $packet_ordered_dictionary.Values) {
            $byte_array += $field
        }
        return $byte_array
    }

    function Get-PacketNetBIOSSessionService {
        Param (
            [Int] $packet_header_length,
            [Int] $packet_data_length
        )

        [Byte[]] $packet_netbios_session_service_length = [BitConverter]::GetBytes($packet_header_length + $packet_data_length)
        $packet_NetBIOS_session_service_length = $packet_netbios_session_service_length[2..0]
        $packet_NetBIOSSessionService = New-Object Collections.Specialized.OrderedDictionary
        $packet_NetBIOSSessionService.Add("NetBIOSSessionService_Message_Type", [Byte[]](0x00))
        $packet_NetBIOSSessionService.Add("NetBIOSSessionService_Length", $packet_netbios_session_service_length)
        return $packet_NetBIOSSessionService
    }

    function Get-PacketSMBHeader {
        Param (
            [Byte[]] $packet_command,
            [Byte[]] $packet_flags,
            [Byte[]] $packet_flags2,
            [Byte[]] $packet_tree_ID,
            [Byte[]] $packet_process_ID,
            [Byte[]] $packet_user_ID
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

    function Get-SmbVersionStatus {
        Param (
            [string] $ComputerName,
            [string] $SmbVersion = 'SMB2',
            $Timeout
        )

        $signingStatus = $false

        $process_ID = [Diagnostics.Process]::GetCurrentProcess() | Select-Object -ExpandProperty Id
        $process_ID = [BitConverter]::ToString([BitConverter]::GetBytes($process_ID))
        $process_ID = $process_ID.Replace("-00-00", "")
        [Byte[]] $process_ID_bytes = $process_ID.Split("-") | ForEach-Object { [Char][Convert]::ToInt16($_, 16) }

        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.ReceiveTimeout = $Timeout

        try {
            $tcpClient.Connect($ComputerName, "445")
            if ($tcpClient.connected) {
                $serviceStatus = $true

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
                            }
                            else {
                                $SMB_client_stage = 'NegotiateSMB2'
                            }
                            if (($SmbVersion -eq 'SMB1' -and [BitConverter]::ToString($SMB_client_receive[39]) -eq '0f') -or ($SmbVersion -ne 'SMB1' -and [BitConverter]::ToString($SMB_client_receive[70]) -eq '03')) {
                                $signingStatus = $true
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
        return ([PSCustomObject]@{SigningStatus = $signingStatus })
    }
    $Signing = $null
    foreach ($computer in $ADComputers){
        Write-Host "Checking $computer..." -ForegroundColor Yellow
        $a = Get-SMBSigning -ComputerName $computer -Timeout 2           # timeout doesn't seem to work
        if ($a -eq "not required"){       #do need to return signing == true?
            $Issue = [pscustomobject]@{
                Forest                = $Domain
                Computer              = $computer
                Issue                 = "SMB signing not enforced on $computer"
                Technique             = "[MEDIUM] SMB signing is not enforced"
            }
            $Issue
        }
      }
}






function Find-LDAPSigning {
    <#
  .SYNOPSIS
  Tests to see if LDAP signing & channel binding is required for LDAP binds to on the domain controller. Search GPO domain controllers policy?
  Inspired from https://evotec.xyz/testing-ldap-and-ldaps-connectivity-with-powershell/ 

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-LDAPSigning -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Finding LDAP signing & channel binding...' -ForegroundColor Yellow

  $GCPortLDAP = '3268'
  $GCPortLDAPSSL = '3269'
  $PortLDAP = '389'
  $PortLDAPS = '636'

  #get domain controllers
  $ServerName = (Get-ADDomainController).hostname

  function Test-LDAPPorts {
    [CmdletBinding()]
    param(
        [string] $ServerName,
        [int] $Port
        )
        #try to bind to ldap using COM interface (ADSI) on specified port
        try {
            $LDAP = "LDAP://" + $ServerName + ':' + $Port
            $Connection = [ADSI]($LDAP)
            $Connection.Close()
            return $true
        } catch {
            if ($_.Exception.ToString() -match "The server is not operational") {
                Write-Warning "Can't open $ServerName`:$Port."
            } else {
                Write-Warning -Message $_
            }
        }
        return $False
    }
   
    #account for multiple domain controllers, but binds will be consistent (as set via GPO)
    foreach ($dc in $ServerName){
        $GlobalCatalogSSL = Test-LDAPPorts -ServerName $dc -Port $GCPortLDAPSSL
        $GlobalCatalogNonSSL = Test-LDAPPorts -ServerName $dc -Port $GCPortLDAP
        $ConnectionLDAPS = Test-LDAPPorts -ServerName $dc -Port $PortLDAPS
        $ConnectionLDAP = Test-LDAPPorts -ServerName $dc -Port $PortLDAP
        
        $LDAPinfo = [pscustomobject]@{
            ComputerFQDN       = $dc
            GlobalCatalogLDAP  = $GlobalCatalogNonSSL
            GlobalCatalogLDAPS = $GlobalCatalogSSL
            LDAP               = $ConnectionLDAP
            LDAPS              = $ConnectionLDAPS
        }
        $LDAPinfo
        if ($globalcatalogLDAP -eq $true -or $connectionLDAP -eq $true){
            $Issue = [pscustomobject]@{
                Forest                = $Domain
                DomainController      = $dc
                Issue                 = "LDAP bind without SSL was not rejected by $dc"
                Technique             = "[Medium] LDAP signing or channel binding is not enforced"
            }
            $Issue
        }
    }
 }