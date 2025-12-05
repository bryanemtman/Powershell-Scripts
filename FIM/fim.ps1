# =====================================================================
#  FILE INTEGRITY MONITOR (FIM) SCRIPT
#  Tests files and directories for changes using SHA256 hashes
# =====================================================================

# Set Global Baseline Path
$global:BaselinePath = "$PSScriptRoot\baseline.json"
# Designate files or directories to monitor
# Set the paths you want to monitor here
$global:ItemsToMonitor = @(
    "C:\Users\emtma\test\file1.txt",
    "C:\Users\emtma\test\file2.txt",
    "C:\Users\emtma\test\file3.txt",
    "C:\Users\emtma\test\testdir" # Contains testfile1.txt, testfile2.txt, testfile3.txt, and testfile4.txt
)

# ---------------------------------------------------------------------
#  Compute Recursive Hash for a Directory or single File
#  Returns an array of PSCustomObject: @{ Path = FullPath; Hash = sha256 }
# ---------------------------------------------------------------------
function Get-DirectoryHash {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        Write-Host "Invalid path: $Path"
        return $null
    }

    # Get the item (file or directory)
    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    # If it's a single file, return one object
    if (-not $item.PSIsContainer) {
        try {
            $h = Get-FileHash -Path $item.FullName -Algorithm SHA256 -ErrorAction Stop
            return ,([PSCustomObject]@{ Path = $item.FullName; Hash = $h.Hash })
        } catch {
            Write-Host "Failed to hash file: $($item.FullName) - $_"
            return $null
        }
    }

    # Directory: enumerate files recursively
    $files = Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue
    $list = @()
    foreach ($f in $files) {
        try {
            $h = Get-FileHash -Path $f.FullName -Algorithm SHA256 -ErrorAction Stop
            $list += [PSCustomObject]@{ Path = $f.FullName; Hash = $h.Hash }
        } catch {
            Write-Host "Failed to hash: $($f.FullName) - $_"
        }
    }

    return $list
}

# ---------------------------------------------------------------------
#  Save Baseline Hashes to JSON (single well-formed array)
#  - Collect all entries across monitored items
#  - Remove duplicates (if same file appears from multiple roots)
# ---------------------------------------------------------------------
function Set-Baseline {

    $seen = @{} # hashtable to prevent duplicates
    $all = @()
    # Build full list across all monitored items
    foreach ($Path in $global:ItemsToMonitor) {
        if (-not (Test-Path $Path)) {
            Write-Host "`nInvalid path in monitor list: $Path"
            continue
        }
        # Get hashes for this path
        $hashData = Get-DirectoryHash -Path $Path
        if ($null -eq $hashData) { continue }
        # Add to master list, avoiding duplicates
        foreach ($entry in $hashData) {
            # Only add if not seen already
            if (-not $seen.ContainsKey($entry.Path)) {
                $seen[$entry.Path] = $true
                $all += [PSCustomObject]@{
                    Path = $entry.Path
                    Hash = $entry.Hash
                }
            }
        }
    }

    # Sort for deterministic baseline output
    $all = $all | Sort-Object Path

    # Write single JSON array (UTF8)
    $json = $all | ConvertTo-Json -Depth 6
    $json | Out-File -FilePath $global:BaselinePath -Encoding UTF8

    Write-Host "`nBaseline saved to: $($global:BaselinePath) (`n$total = $($all.Count) entries`)"
}

# ---------------------------------------------------------------------
#  Load Baseline Hashes from baseline JSON file
#  Returns array of PSCustomObject: @{ Path = FullPath; Hash = sha256 }
# ---------------------------------------------------------------------
function Load-Baseline {
    if (-not (Test-Path $global:BaselinePath)) {
        Write-Host "No baseline found. Create one first."
        return $null
    }

    # ConvertFrom-Json will return array of objects
    $content = Get-Content -LiteralPath $global:BaselinePath -Raw -ErrorAction Stop
    try {
        $obj = $content | ConvertFrom-Json -ErrorAction Stop
        return $obj
    } catch {
        Write-Host "Baseline JSON parse failed: $_"
        return $null
    }
}

# ---------------------------------------------------------------------
#  Get File Metadata & ACL
#  Returns PSCustomObject of file details
# ---------------------------------------------------------------------
function Get-FileDetails {
    param(
        [string]$FilePath
    )

    if (-not (Test-Path $FilePath)) { return $null }
    
    $item = Get-Item -LiteralPath $FilePath -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }

    # Try to get ACL
    try {
        $acl = Get-Acl -LiteralPath $FilePath -ErrorAction Stop
        $owner = $acl.Owner
        $aclEntries = $acl.Access | Select-Object IdentityReference, FileSystemRights, AccessControlType, IsInherited
    } catch {
        $owner = "Unknown (no access)"
        $aclEntries = @()
    }

    # Directory length/size: leave as 0 (or could compute cumulative size if desired)
    $size = if ($item.PSIsContainer) { 0 } else { $item.Length }

    $details = [PSCustomObject]@{
        Path           = $item.FullName
        Type           = if ($item.PSIsContainer) { "Directory" } else { "File" }
        SizeBytes      = $size
        Created        = $item.CreationTime
        Modified       = $item.LastWriteTime
        LastAccess     = $item.LastAccessTime
        Owner          = $owner
        ACL            = $aclEntries
    }

    return $details
}

# ---------------------------------------------------------------------
#  Compare Current Hashes Against Baseline
#  Works across all monitored roots, and detects added/removed/modified
# ---------------------------------------------------------------------
function Check-FileChanges {
    $baseline = Load-Baseline
    if ($null -eq $baseline) { return }

    # Convert baseline to hashtable for quick lookup
    $stored = @{}
    foreach ($b in $baseline) { $stored[$b.Path] = $b.Hash }

    # Build current set across monitored items, avoiding duplicates
    $seen = @{}
    $currentList = @()
    foreach ($Path in $global:ItemsToMonitor) {
        if (-not (Test-Path $Path)) {
            Write-Host "Monitor path missing: $Path"
            continue
        }

        $hashData = Get-DirectoryHash -Path $Path
        if ($null -eq $hashData) { continue }

        foreach ($entry in $hashData) {
            if (-not $seen.ContainsKey($entry.Path)) {
                $seen[$entry.Path] = $true
                $currentList += [PSCustomObject]@{ Path = $entry.Path; Hash = $entry.Hash }
            }
        }
    }

    # Convert current to hashtable
    $current = @{}
    foreach ($c in $currentList) { $current[$c.Path] = $c.Hash }

    Write-Host "`n--- FILE CHANGE CHECK ---`n"

    # Check for modified or unchanged or new files
    foreach ($path in $current.Keys | Sort-Object) {
        if ($stored.ContainsKey($path)) {
            if ($stored[$path] -ne $current[$path]) {
                Write-Host "   CHANGE DETECTED: $path" -ForegroundColor Yellow
                Write-Host "      OLD HASH: $($stored[$path])"
                Write-Host "      NEW HASH: $($current[$path])"

                $info = Get-FileDetails -FilePath $path
                if ($info) {
                    Write-Host "`n--- FILE DETAILS ---"
                    $info | Select-Object Path, Type, SizeBytes, Created, Modified, LastAccess, Owner | Format-List

                    Write-Host "`n--- ACL ---"
                    if ($info.ACL) {
                        $info.ACL | Format-Table -AutoSize
                    } else {
                        Write-Host "   (No ACL information available)"
                    }
                    Write-Host "`n"
                }
            } else {
                Write-Host "OK: No change: $path"
            }
        } else {
            Write-Host "   NEW FILE DETECTED: $path" -ForegroundColor Green
        }
    }

    # Check for removed files (in baseline but not in current)
    foreach ($oldPath in $stored.Keys | Sort-Object) {
        if (-not $current.ContainsKey($oldPath)) {
            Write-Host "   FILE REMOVED: $oldPath" -ForegroundColor Red
        }
    }

    Write-Host "`n--- CHECK COMPLETE ---`n"
}

# ---------------------------------------------------------------------
#  Auto-Monitor Mode (repeat checks)
#  Default interval 10 seconds
# ---------------------------------------------------------------------
function Auto-Monitor {
    # Made to be changeable by user input from menu
    # However, I liked the simplicity of a fixed interval
    param(
        [int]$IntervalSeconds = 10
    )

    Write-Host "`n[Auto Monitor] Running checks every $IntervalSeconds seconds"
    Write-Host "Press Ctrl+C to stop.`n"

    while ($true) {
        Check-FileChanges
        Start-Sleep -Seconds $IntervalSeconds
    }
}

# ---------------------------------------------------------------------
#  MAIN
# ---------------------------------------------------------------------
function Main {
    while ($true) {
        Write-Host "==============================="
        Write-Host " FILE INTEGRITY MONITOR MENU"
        Write-Host "==============================="
        Write-Host "1. Set New Baseline Hashes"
        Write-Host "2. Check for File/Directory Changes"
        Write-Host "3. Display Current Baseline"
        Write-Host "4. Start Auto-Monitor Mode"
        Write-Host "5. Exit"
        Write-Host "==============================="

        $choice = Read-Host "Select an option"

        switch ($choice) {
            "1" {
                Set-Baseline
            }
            "2" {
                Check-FileChanges
            }
            "3" {
                $baseline = Load-Baseline
                if ($baseline) {
                    Write-Host "`n--- BASELINE CONTENT ---"
                    # Show a concise table (Path may be long)
                    $baseline | Select-Object Path, Hash | Format-Table -AutoSize
                }
            }
            "4" {
                Auto-Monitor
            }
            "5" { 
                return
            }
            default {
                Write-Host "Invalid choice."
            }
        }
    }
}

Main
