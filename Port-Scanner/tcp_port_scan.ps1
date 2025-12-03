# Port Scanner Script
# This script scans a specified IP address for open TCP ports.
# Usage: .\port_scan.ps1 -Address <IP_Address> -Ports <Port_List> -Timeout <Milliseconds>

# Default parameters
param(
    [string]$Address = "127.0.0.1",
    [int[]]$Ports = @(20, 21, 3389, 2222, 5900, 8080,
                    3306, 5432, 6379, 27017, 22, 23,
                    25, 80, 110, 143, 443, 445, 993,
                    995, 636, 465, 587),
    [int]$Timeout = 200 # Timeout in milliseconds
)

Write-Host "`nBeginning port scan on $($Address)`n"

$openPorts = @() # Array to hold open ports

# Function to test if a port is open on a given IP address
function Test-Port {
    # Parameters
    param(
        [string]$Ip,
        [int]$Port,
        [int]$Timeout
    )
    # Create a TCP client and attempt to connect
    $client = New-Object System.Net.Sockets.TcpClient
    $async = $client.BeginConnect($Ip, $Port, $null, $null)
    # Wait for the connection attempt to complete or timeout
    $wait  = $async.AsyncWaitHandle.WaitOne($Timeout)

    # If the wait timed out, the port is closed
    if (-not $wait) {
        $client.Close()
        return $false
    }

    # Complete the connection attempt
    try {
        $client.EndConnect($async)
        $client.Close()
        return $true
    } catch {
        return $false
    }
}

# Scan each port in the list
foreach ($port in $Ports) {
    # Test if the port is open
    if (Test-Port -Ip $Address -Port $port -Timeout $Timeout) {
        Write-Host "$($Address):$($port) is open"
        # Add the open port to the list
        $openPorts += $port
    }
}

Write-Host ""

# Check if any open ports were found and display results
if ($openPorts.Count -eq 0) {
    Write-Host "No open ports found."
} else {
    [PSCustomObject]@{
        Address = $Address
        OpenPorts = $openPorts -join ", "
    } | Format-Table -AutoSize -Wrap
}

Write-Host "`nPort scan complete.`n"
