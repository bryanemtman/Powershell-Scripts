
$global:id = 4625 # Failed login event ID
$global:last_boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime # Gets the last boot time
$global:seven_days = (Get-Date).AddDays(-7) # DateTime for 7 days ago
$global:addresses = New-Object System.Collections.Generic.List[string] # To store IP addresses from logs
$global:geo_info = @() # To store geolocation information


# Get failed logon events since last boot and extract IP addresses
function Get-FailedLogons {

    # Determine the later date between last boot and 7 days ago
    if ($last_boot -gt $seven_days) {
        $from_date = $last_boot
    } else {
        $from_date = $seven_days
    }
    # Retrieve failed logon events from Security log since last boot
    $events = Get-WinEvent -FilterHashtable @{
        LogName = "Security"
        Id = $id
        ProviderName = "Microsoft-Windows-Security-Auditing"
    } -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -ge $from_date }
    # Check if any events were found
    if (!$events) {
        Write-Host "No 4625 logs found since last boot."
        return
    }
    # Extract IP addresses from the events
    foreach ($evt in $events) {

        # Logon Failure: Remote host field
        $ip = $evt.Properties[19].Value
        # Filter out empty or localhost addresses
        if ($ip -and $ip -ne "::1" -and $ip -ne "127.0.0.1") {
            $global:addresses.Add($ip)
        }
    }
}


# Find geolocation information for unique IP addresses
function Find-GeoLocation {

    $unique = $addresses | Sort-Object -Unique
    $occurs = $addresses | Group-Object | Sort-Object Count -Descending | Select-Object Count, Name

    # Query geolocation API for each unique IP address
    foreach ($ip in $unique) {
        # Call ip-api.com for geolocation data
        try {
            $ipinfo = Invoke-RestMethod -Method Get -Uri "http://ip-api.com/json/$($ip)?fields=50709"
            # Check if the API returned a successful response
            if ($ipinfo.status -eq "success") {
                # Store relevant geolocation information
                $global:geo_info += [pscustomobject]@{
                    IP      = $ip
                    Country = $ipinfo.country
                    Region  = $ipinfo.regionName
                    City    = $ipinfo.city
                    ISP     = $ipinfo.isp
                    Org     = $ipinfo.org
                }
            } else {
                # Store error message if API call was not successful
                $global:geo_info += [pscustomobject]@{
                    IP      = $ip
                    Error   = $ipinfo.message
                }
            }
        }
        catch {
            # Store error message if API call fails
            $global:geo_info += [pscustomobject]@{
                IP      = $ip
                Error   = "Exception: $($_.Exception.Message)"
            }
        }

        Start-Sleep -Seconds 2  # API rate-limit protection (max 45 requests per minute)
    }

    return $occurs
}


# Main execution function
function Main {
    # Retrieve failed logon events and extract IP addresses
    Get-FailedLogons
    # If any IP addresses were found, get geolocation info and display results
    if ($addresses.Count -gt 0) {
        $duplicates = Find-GeoLocation
        Write-Host "`n=== Login Attempt Counts ===`n"
        $duplicates | Format-Table -AutoSize

        Write-Host "`n=== Geo Information ===`n"
        $geo_info | Format-Table -AutoSize
    } else {
        Write-Host "No IP addresses extracted from failed login events."
    }
}

Main

# Add functionality to send reports through email or log to file as needed
