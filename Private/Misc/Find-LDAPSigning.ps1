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
        [Parameter(Mandatory = $true)]
        [String]
        $Domain
    )

    Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Finding LDAP signing & channel bindings..." -ForegroundColor Yellow

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
        }
        catch {
            if ($_.Exception.ToString() -match "The server is not operational") {
                Write-Warning "Can't open $ServerName`:$Port."
            }
            else {
                Write-Warning -Message $_
            }
        }
        return $False
    }
   
    #account for multiple domain controllers, but binds will be consistent (as set via GPO)
    foreach ($dc in $ServerName) {
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
       # $LDAPinfo - if want to output or not in domain info section
        if ($globalcatalogLDAP -eq $true -or $connectionLDAP -eq $true) {
            $Issue = [pscustomobject]@{
                Risk             = (to_yellow "MEDIUM")
                Technique        = "LDAP signing or channel binding is not enforced"
                Score            = 19
                DomainController = $dc
                Issue            = "LDAP bind without SSL was not rejected by $dc"
            }
            $Issue
            return $true
        }
    }
    #return for use in WebDAV function
    return $false
}

#could also parse the default domain policy to check for domain controller LDAP signing requirements

# unit tests for documentation 
#ldap signing - true
#ldap channel binding - true
#not ldap signing - false
#not ldap channel binding - false