# --------------------------------------------
# ICMP payload script
# --------------------------------------------

# Global variables
$global:chunk_size = 32
$global:wait = 0.5
$global:file = ""
$global:destination = ""

# Help function
function Get-Help {
    Write-Host ""
    Write-Host "    Description:"
    Write-Host "        icmp.ps1 is a project and proof of concept for my own learning of PowerShell scripting."
    Write-Host "        This is a crossover script from my bash script nothingtosee.sh."
    Write-Host "        It demonstrates how ICMP Echo packets can be used to transport data."
    Write-Host "        Use tools such as Wireshark or tcpdump to inspect the ICMP payload."
    Write-Host ""
    Write-Host "    Usage:"
    Write-Host "        ./icmp.ps1 -f <file> [-t <float>] [-s <integer>] <destination>"
    Write-Host ""
    Write-Host "    Options:"
    Write-Host "        --file, -f              REQUIRED        Input file containing data to send"
    Write-Host "        --time-delay, -t        OPTIONAL        Time delay between packets (default 0.5s)"
    Write-Host "        --payload-size, -s      OPTIONAL        Payload size of the ASCII characters sent through"
    Write-Host "                                                each ICMP packet (default 32)"
    Write-Host ""
    Write-Host "    Examples:"
    Write-Host "        ./icmp.ps1 -f text.txt 192.168.1.1"
    Write-Host "        ./icmp.ps1 -f text.txt -t 30 10.0.2.5"
    Write-Host ""
    
}
<#
  ------------------------------------------------------------
    ICMP Echo Sender (Full Payload Control)
    PowerShell + .NET raw sockets
  ------------------------------------------------------------
#>

# Build checksum for ICMP packets
function Get-Checksum {
    param([byte[]]$Data)
    $sum = 0

    for ($i = 0; $i -lt $Data.Length; $i += 2) {
        $word = $Data[$i] -shl 8
        if ($i + 1 -lt $Data.Length) {
            $word += $Data[$i + 1]
        }
        $sum += $word
    }

    while ($sum -gt 0xFFFF) {
        $sum = ($sum -band 0xFFFF) + ($sum -shr 16)
    }

    # Final checksum (1’s complement)
    return ((-bnot $sum) -band 0xFFFF)
}

# ------------------------------------------------------------
# Send ICMP Echo Request
# ------------------------------------------------------------
function Send-ICMP {
    param(
        [string]$Target,
        [byte[]]$Payload
    )

    # ICMP Header
    $Type  = 8     # Echo Request
    $Code  = 0
    $ID    = 0x1234
    $Seq   = 1

    # Build the packet
    $packet = New-Object byte[] (8 + $Payload.Length)

    $packet[0] = $Type
    $packet[1] = $Code
    $packet[2] = 0       # checksum placeholder
    $packet[3] = 0
    $packet[4] = ($ID -shr 8) -band 0xFF
    $packet[5] = $ID -band 0xFF
    $packet[6] = ($Seq -shr 8) -band 0xFF
    $packet[7] = $Seq -band 0xFF

    # Copy Payload
    [Array]::Copy($Payload, 0, $packet, 8, $Payload.Length)

    # Calculate checksum
    $checksum = Get-Checksum $packet
    $packet[2] = ($checksum -shr 8) -band 0xFF
    $packet[3] = $checksum -band 0xFF

    # Create RAW socket (ADMIN ONLY)
    $socket = New-Object System.Net.Sockets.Socket `
        ([System.Net.Sockets.AddressFamily]::InterNetwork,
         [System.Net.Sockets.SocketType]::Raw,
         [System.Net.Sockets.ProtocolType]::Icmp)

    $socket.Connect($Target, 0)

    # Send ICMP packet
    $socket.Send($packet)

    $socket.Close()
}

# --------------------------------------------
#   Main
# --------------------------------------------
function Main {
    
    $text = Get-Content $global:file -Raw # Read file content
    $buffer = "" # Create empty buffer
    $count = 0 # Character counter
    $total_len = $text.Length # Total length of text

    Write-Host ""
    Write-Host "Sending file: $file"
    Write-Host "Total characters: $total_len"
    Write-Host "Sending in intervals of ${wait} seconds..."
    Write-Host ""

    # Process each character
    for ($i = 0; $i -lt $total_len; $i++) {
        $char = $text[$i] # Get character
        $buffer += $char # Append to buffer
        $count++ # Increment counter

        # Send when chunk size is reached
        if ($count -eq $global:chunk_size) {
            # Convert buffer to hex
            $hex = ([System.Text.Encoding]::ASCII.GetBytes($buffer) | ForEach-Object { $_.ToString("x2") }) -join ""
            Write-Host "`nChunk:  $buffer"
            Write-Host "Hex:     $hex"
            # Convert hex to byte array
            $bytes = ($hex -replace '..', '$& ').Trim().Split(' ') |
                        ForEach-Object { [Convert]::ToByte($_, 16) }
            # Send ICMP packet
            Send-ICMP -Target $global:destination -Payload $bytes
            $count = 0 # Reset counter
            $buffer = "" # Clear buffer
            Start-Sleep -Seconds $global:wait # Wait between packets
        }
        # Add progress bar later
    }

    # Leftover bytes
    if ($buffer.Length -gt 0) {
        $padding = $global:chunk_size - $buffer.Length # Calculate padding
        $buffer += "1" * $padding # Pad with '1's until chunk size is met
        $hex = ([System.Text.Encoding]::ASCII.GetBytes($buffer) | ForEach-Object { $_.ToString("x2") }) -join ""
        Write-Host "`nChunk:  $buffer"
        Write-Host "Hex:     $hex"
        $bytes = ($hex -replace '..', '$& ').Trim().Split(' ') |
                    ForEach-Object { [Convert]::ToByte($_, 16) }
        Send-ICMP -Target $global:destination -Payload $bytes

        Write-Host "`nDone"

        # Add progress bar later
    }
}

# Argument parsing
$i = 0
while ($i -lt $args.Count) {
    # Parse command-line arguments
    switch ($args[$i]) {

        { $_ -eq "-h" -or $_ -eq "--help" } {
            Get-Help
            exit 0
        }

        { $_ -eq "-f" -or $_ -eq "--file" } {
            if ($i + 1 -ge $args.Count) {
                Write-Host "Error: Missing file argument."
                exit 1
            }

            $global:file = $args[$i + 1]
            # Check if file exists
            if (-not (Test-Path $global:file)) {
                Write-Host "Error: File not found."
                exit 1
            }

            $i += 2
            continue
        }

        { $_ -eq "-t" -or $_ -eq "--time-delay" } {
            if ($i + 1 -ge $args.Count) {
                Write-Host "Error: Missing time-delay argument."
                exit 1
            }
            # Validate float
            if ($args[$i + 1] -notmatch "^[0-9]+([.][0-9]+)?$") {
                Write-Host "Error: Time delay must be a number."
                exit 1
            }

            $global:wait = [double]$args[$i + 1]
            $i += 2
            continue
        }

        { $_ -eq "-s" -or $_ -eq "--payload-size" } {
            if ($i + 1 -ge $args.Count) {
                Write-Host "Error: Missing payload-size argument."
                exit 1
            }
            # Validate integer
            if ($args[$i + 1] -notmatch "^[0-9]+$") {
                Write-Host "Error: Payload size must be an integer."
                exit 1
            }

            $global:chunk_size = [int]$args[$i + 1]
            $i += 2
            continue
        }

        default {
            # Check if argument is an IP address
            if ($args[$i] -match "^[0-9]{1,3}(\.[0-9]{1,3}){3}$") {
                $global:destination = $args[$i]
                $i++
                continue
            }

            Write-Host "Error: Invalid argument '$($args[$i])'"
            exit 1
        }
    }
}

Main
