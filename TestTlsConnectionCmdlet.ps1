# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

enum ConnectTestResult {
    FailedNetwork = 2
    FailedTls = 1
    Connected = 0
}

function TryToSecureConnect
{
    param($connectHost, $port, $askedProtocols)
    $client = New-Object Net.Sockets.TcpClient
    try 
    {        
        try 
        {
            $client.Connect($connectHost, $port) # if we fail here, it is not SSL/TLS issue
        }
        catch # case of network/DNS error (no TLS problem)
        {
            return ([ConnectTestResult]::FailedNetwork)
        }
        $stream = New-Object Net.Security.SslStream $client.GetStream(), $true, ([System.Net.Security.RemoteCertificateValidationCallback]{ $true })
        $remoteEndpoint = $client.Client.RemoteEndPoint
        try
        {
            if ($askedProtocols -eq [System.Security.Authentication.SslProtocols]::None) { $stream.AuthenticateAsClient($connectHost, $null, $false) }
            else { $stream.AuthenticateAsClient($connectHost, $null, $askedProtocols, $false) }
            
            return ([ConnectTestResult]::Connected, $remoteEndpoint, $stream.SslProtocol, $null)
        }
        catch [System.IO.IOException],[System.ComponentModel.Win32Exception],[System.Security.Authentication.AuthenticationException] # cases of failed TLS negotation
        {
            # Seen exceptions here:
            #   Error: The client and server cannot communicate, because they do not possess a common algorithm.
            #   Error: Unable to read data from the transport connection: An existing connection was forcibly closed by the remote host.

            return ([ConnectTestResult]::FailedTls, $remoteEndpoint, $null, $_)
        }        
        finally {$stream.Dispose()}
    }
    finally 
    {
        $client.Dispose()
    }    
}

function Test-TlsConnection
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, HelpMessage="Computer name (host name).")] 
        [string]$ComputerName,
        [Parameter(Mandatory=$false, HelpMessage="Port (default is 443).")] 
        [ValidateRange(0,65535)]
        [int]$Port = 443,
        [Parameter(Mandatory=$false, HelpMessage="TLS version to test (default is Tls12).")] 
        [ValidateSet("Default", “Tls10”,”Tls11”,”Tls12”,”Tls13”, “Tls10+”,”Tls11+”,”Tls12+”)]
        [string]$TlsVersion = "Default"
    )
    
    Write-Verbose "Probing..."
    
    $askedProtocols = [System.Security.Authentication.SslProtocols]::None # this is the "Default" option
    if ($TlsVersion -match "tls13|tls10\+|tls11\+|tls12\+") {$askedProtocols += [System.Security.Authentication.SslProtocols](12288)}
    if ($TlsVersion -match "tls12|tls10\+|tls11\+") {$askedProtocols += [System.Security.Authentication.SslProtocols](3072)}
    if ($TlsVersion -match "tls11|tls10\+") {$askedProtocols += [System.Security.Authentication.SslProtocols](768)}
    if ($TlsVersion -match "tls10") {$askedProtocols += [System.Security.Authentication.SslProtocols](192)}    
    
    ($connectResult, $remoteAddress, $negotiatedProtocol, $handshakeException) = TryToSecureConnect $ComputerName $Port $askedProtocols
    switch ($connectResult)
    {
        ([ConnectTestResult]::Connected) { Write-Host "SUCCESS: TCP connected, secure channel negotiated using $(if ($negotiatedProtocol -eq [System.Security.Authentication.SslProtocols]::Tls) { "Tls10" } else { $negotiatedProtocol })" }
        ([ConnectTestResult]::FailedTls) { Write-Warning "TCP connected, failed to negotiate secure channel in mode $TlsVersion (Internal error: $handshakeException)" }
        ([ConnectTestResult]::FailedNetwork) { Write-Warning "Failed to reach the destination. This is connectivity or DNS problem, not TLS issue (Internal error: $handshakeException)" }
    }

    $res = [ordered]@{
        ConnectResult = $connectResult
        ConnectedRemoteAddress = $remoteAddress
        SecureChannelProtocol = $negotiatedProtocol
    }
    $resObject = New-Object PSObject -Property $res
    return $resObject
}


function Test-TlsConnectivity
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, HelpMessage="Computer name (host name).")] 
        [string]$ComputerName,
        [Parameter(Mandatory=$false, HelpMessage="Port (default is 443).")] 
        [ValidateRange(0,65535)]
        [int]$Port = 443
    )

    $ping = Test-NetConnection -ComputerName $ComputerName -Port $Port
    $ping | Write-Output

    $result = [ordered]@{}
    if ($ping.TcpTestSucceeded)
    {
        @("Tls10", "Tls11", "Tls12", "Tls13").ForEach({ 
            $res = Test-TlsConnection $ComputerName -Port $Port -TlsVersion $_ 
            $result[$_] = $res.ConnectResult
        })

        $res = Test-TlsConnection $ComputerName -Port $Port
        $result["Default"] = $res.ConnectResult
    }
    else
    {
        Write-Error "Failed to ping the target."
    }

    $resObject = New-Object PSObject -Property $result
    return $resObject
}