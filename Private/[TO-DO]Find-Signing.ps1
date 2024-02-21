# LDAP / SMB signing

#SMB
#Function Get-SMBSigning {
    Param ([string]$ComputerName, $Timeout)

    $SMB1 = Get-SmbVersionStatus -ComputerName $ComputerName -SmbVersion 'SMB1' -Timeout $Timeout
    $SMB2 = Get-SmbVersionStatus -ComputerName $ComputerName -SmbVersion 'SMB2' -Timeout $Timeout

    if ($SMB1.SigningStatus -or $SMB2.SigningStatus) { "Signing Required" } else { "Signing not Required" }
}


#LDAP