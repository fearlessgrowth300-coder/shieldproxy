# Show both ShieldProxy installs: Android user, UID, and the last exit IP each one logged.
# Open ShieldProxy in each profile and run a proxy check first. Lines are logcat tag ShieldProfile.
$ErrorActionPreference = "Continue"
$Pkg = "com.privacyshield.proxy"
$Adb = if ($env:ADB) { $env:ADB } else { "adb" }

Write-Output "Android users"
& $Adb shell pm list users
Write-Output ""
Write-Output "Package users and UIDs"
$dump = & $Adb shell dumpsys package $Pkg
$uid = ""
foreach ($line in $dump) {
    if ($line -match "userId=([0-9]+)") { $uid = $Matches[1] }
    if ($line -match "User ([0-9]+):" -and $uid -ne "") {
        Write-Output ("user {0} uid {1}" -f $Matches[1], $uid)
    }
}
Write-Output ""
Write-Output "Last exit published by each profile (logcat)"
$log = & $Adb logcat -d -s "ShieldProfile:I"
$rows = @{}
foreach ($line in $log) {
    if ($line -notmatch "user=") { continue }
    $user = if ($line -match "user=([0-9]+)") { $Matches[1] } else { "" }
    $managed = if ($line -match "managed=(\S+)") { $Matches[1] } else { "" }
    $id = if ($line -match "uid=([0-9]+)") { $Matches[1] } else { "" }
    $exit = if ($line -match "exitIp=(\S+)") { $Matches[1] } else { "" }
    if ($user -ne "") {
        $rows[$user] = "user $user managed $managed uid $id exitIp $exit"
    }
}
if ($rows.Count -eq 0) {
    Write-Output "No ShieldProfile lines. Open the app in each profile and check a proxy."
} else {
    $rows.Values | ForEach-Object { Write-Output $_ }
}
Write-Output ""
Write-Output "Same-exit check"
$byUser = @{}
foreach ($line in $log) {
    if ($line -match "user=([0-9]+)" -and $line -match "exitIp=(\S+)" -and $Matches[2] -ne "") {
        # second match overwrites $Matches; parse explicitly
    }
    $u = [regex]::Match($line, "user=([0-9]+)")
    $e = [regex]::Match($line, "exitIp=(\S+)")
    if ($u.Success -and $e.Success -and $e.Groups[1].Value -ne "") {
        $byUser[$u.Groups[1].Value] = $e.Groups[1].Value
    }
}
$keys = @($byUser.Keys)
if ($keys.Count -lt 2) {
    Write-Output "Fewer than two profiles have published an exit. Open ShieldProxy in the other profile and run a proxy check."
} else {
    $same = $false
    for ($i = 0; $i -lt $keys.Count; $i++) {
        for ($j = $i + 1; $j -lt $keys.Count; $j++) {
            if ($byUser[$keys[$i]] -eq $byUser[$keys[$j]]) {
                Write-Output ("WARNING user {0} and user {1} last published exit {2}" -f $keys[$i], $keys[$j], $byUser[$keys[$i]])
                $same = $true
            }
        }
    }
    if (-not $same) { Write-Output "The published exits differ." }
}
