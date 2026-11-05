#!/bin/sh
# Show both ShieldProxy installs: Android user, UID, and the last exit IP each one logged.
# Exit lines come from logcat tag ShieldProfile. Open ShieldProxy in each profile first
# so a proxy check has written user=, uid=, and exitIp=.
set -u
PKG=com.privacyshield.proxy
ADB=${ADB:-adb}

echo "Android users"
$ADB shell pm list users
echo
echo "Package users and UIDs"
$ADB shell dumpsys package "$PKG" | awk '
  /userId=/ {
    line=$0
    sub(/^.*userId=/,"",line)
    split(line, a, " ")
    uid=a[1]
  }
  /User [0-9]+:/ {
    if (uid != "") print "user "$2" uid "uid
  }
'
echo
echo "Last exit published by each profile (logcat)"
$ADB logcat -d -s ShieldProfile:I | awk '
  /user=/ {
    user=""; uid=""; exitIp=""; managed=""
    n=split($0, f, " ")
    for (i=1; i<=n; i++) {
      if (f[i] ~ /^user=/) { sub(/^user=/,"",f[i]); user=f[i] }
      if (f[i] ~ /^uid=/) { sub(/^uid=/,"",f[i]); uid=f[i] }
      if (f[i] ~ /^exitIp=/) { sub(/^exitIp=/,"",f[i]); exitIp=f[i] }
      if (f[i] ~ /^managed=/) { sub(/^managed=/,"",f[i]); managed=f[i] }
    }
    if (user != "") row[user]=sprintf("user %s managed %s uid %s exitIp %s", user, managed, uid, exitIp)
  }
  END {
    for (u in row) print row[u]
  }
'
echo
echo "Same-exit check"
$ADB logcat -d -s ShieldProfile:I | awk '
  /exitIp=/ {
    user=""; exitIp=""
    n=split($0, f, " ")
    for (i=1; i<=n; i++) {
      if (f[i] ~ /^user=/) { sub(/^user=/,"",f[i]); user=f[i] }
      if (f[i] ~ /^exitIp=/ && f[i] != "exitIp=") { sub(/^exitIp=/,"",f[i]); exitIp=f[i] }
    }
    if (user != "" && exitIp != "") last[user]=exitIp
  }
  END {
    n=0
    for (u in last) { users[n]=u; ips[n]=last[u]; n++ }
    same=0
    for (i=0; i<n; i++) for (j=i+1; j<n; j++) if (ips[i]==ips[j]) {
      print "WARNING user "users[i]" and user "users[j]" last published exit "ips[i]
      same=1
    }
    if (n<2) print "Fewer than two profiles have published an exit. Open ShieldProxy in the other profile and run a proxy check."
    else if (!same) print "The published exits differ."
  }
'
echo
echo "Per-user status file (works when the app is debuggable)"
users=$($ADB shell pm list users | sed -n "s/.*UserInfo{\([0-9][0-9]*\):.*/\1/p")
for u in $users; do
  echo "-- user $u"
  $ADB shell run-as "$PKG" cat "files/profile_status.txt" 2>/dev/null || true
done
