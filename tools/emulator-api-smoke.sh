#!/bin/sh
# Host-side smoke test. android-emulator-runner invokes this with adb already pointing
# at the booted AVD. Artifacts land in emulator-artifacts/.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
OUT="$ROOT/emulator-artifacts"
mkdir -p "$OUT"
: > "$OUT/socks-a.log"
: > "$OUT/socks-b.log"
API=$(adb shell getprop ro.build.version.sdk | tr -d '\r')
echo "api=$API" | tee "$OUT/result.txt"

fail() {
  echo "FAIL $*" | tee -a "$OUT/result.txt"
  adb logcat -d -v threadtime > "$OUT/logcat.txt" || true
  adb shell ls /data/tombstones > "$OUT/tombstones.txt" 2>/dev/null || true
  exit 1
}

python3 "$ROOT/tools/test_socks.py" 18080 "$OUT/socks-a.log" &
SOCK_A=$!
python3 "$ROOT/tools/test_socks.py" 18081 "$OUT/socks-b.log" &
SOCK_B=$!
trap 'kill "$SOCK_A" "$SOCK_B" 2>/dev/null || true' EXIT

adb_do() {
  timeout 30 "$@"
}

adb_retry() {
  i=0
  while [ "$i" -lt 5 ]; do
    if "$@"; then
      return 0
    fi
    i=$((i + 1))
    sleep 3
  done
  return 1
}

adb_retry timeout 120 adb install -r -t "$ROOT/app/build/outputs/apk/debug/app-debug.apk" || fail "could not install ShieldProxy"
adb_retry timeout 120 adb install -r -t "$ROOT/probe/build/outputs/apk/debug/probe-debug.apk" || fail "could not install probe"
if [ "$API" -ge 33 ]; then
  adb shell pm grant com.privacyshield.proxy android.permission.POST_NOTIFICATIONS || true
fi
adb shell appops set com.privacyshield.proxy ACTIVATE_VPN allow || true

smoke() {
  adb shell am start -n com.privacyshield.proxy/.EmulatorSmokeActivity \
    --es cmd "$1" --ei proxyPort "$2"
}

wait_file() {
  pkg=$1
  name=$2
  i=0
  while [ "$i" -lt 40 ]; do
    if adb shell run-as "$pkg" cat "files/$name" > "$OUT/$name" 2>/dev/null; then
      if [ -s "$OUT/$name" ]; then
        return 0
      fi
    fi
    i=$((i + 1))
    sleep 1
  done
  return 1
}

vpn_up() {
  # Match the interface row. "Device tun0 does not exist" also contains the name
  # and made API 31 look like the VPN was still up after stop.
  adb_do adb shell 'grep -q "^ *tun0:" /proc/net/dev'
}

wait_vpn() {
  want=$1
  i=0
  while [ "$i" -lt 45 ]; do
    got=$(adb_do adb shell run-as com.privacyshield.proxy cat files/engine_ready.txt 2>/dev/null | tr -d '\r\n ' || true)
    if vpn_up && [ "$got" = "$want" ]; then
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  return 1
}

wait_vpn_down() {
  i=0
  while [ "$i" -lt 20 ]; do
    if ! vpn_up; then
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  return 1
}

connects() {
  n=$(grep -c 'CONNECT 203.0.113.10 9' "$1" 2>/dev/null || true)
  echo "${n:-0}"
}

probe() {
  log=$1
  before=$(connects "$log")
  adb shell run-as com.privacyshield.proxy.probe rm files/probe_result.txt >/dev/null 2>&1 || true
  adb shell am start -S -n com.privacyshield.proxy.probe/.ProbeActivity --es host 203.0.113.10 --ei port 9
  i=0
  while [ "$i" -lt 30 ]; do
    now=$(connects "$log")
    if [ "$now" -gt "$before" ]; then
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  wait_file com.privacyshield.proxy.probe probe_result.txt || true
  fail "SOCKS did not see the probe. probe=$(cat "$OUT/probe_result.txt" 2>/dev/null || echo missing)"
}

count_log() {
  if [ -f "$1" ]; then
    wc -l < "$1" | tr -d ' '
  else
    echo 0
  fi
}

echo "start" | tee -a "$OUT/result.txt"
START=$(date +%s)
adb shell run-as com.privacyshield.proxy rm files/smoke_result.txt >/dev/null 2>&1 || true
smoke start 18080
wait_file com.privacyshield.proxy smoke_result.txt || fail "smoke activity produced no result"
grep -q '^started ' "$OUT/smoke_result.txt" || fail "VPN consent or startup failed: $(cat "$OUT/smoke_result.txt")"
wait_vpn 18080 || fail "VPN service did not stay up"
ELAPSED=$(( $(date +%s) - START ))
echo "startupSeconds=$ELAPSED" | tee -a "$OUT/result.txt"
if [ "$ELAPSED" -gt 90 ]; then
  fail "startup took ${ELAPSED}s"
fi
probe "$OUT/socks-a.log"

echo "toggle" | tee -a "$OUT/result.txt"
n=0
while [ "$n" -lt 3 ]; do
  adb shell run-as com.privacyshield.proxy rm files/smoke_result.txt >/dev/null 2>&1 || true
  smoke stop 18080
  wait_file com.privacyshield.proxy smoke_result.txt || fail "stop produced no result"
  wait_vpn_down || fail "VPN stayed up after stop"
  adb shell run-as com.privacyshield.proxy rm files/smoke_result.txt >/dev/null 2>&1 || true
  smoke start 18080
  wait_file com.privacyshield.proxy smoke_result.txt || fail "restart produced no result"
  wait_vpn 18080 || fail "VPN did not return after toggle"
  n=$((n + 1))
done
probe "$OUT/socks-a.log"

echo "rotate" | tee -a "$OUT/result.txt"
BEFORE_B=$(count_log "$OUT/socks-b.log")
adb shell run-as com.privacyshield.proxy rm files/smoke_result.txt >/dev/null 2>&1 || true
smoke start 18081
wait_file com.privacyshield.proxy smoke_result.txt || fail "rotate produced no result"
wait_vpn 18081 || fail "VPN did not return after rotate"
probe "$OUT/socks-b.log"
AFTER_B=$(count_log "$OUT/socks-b.log")
if [ "$AFTER_B" -le "$BEFORE_B" ]; then
  fail "rotated route did not reach SOCKS proxy B"
fi

echo "scan" | tee -a "$OUT/result.txt"
adb shell run-as com.privacyshield.proxy rm files/smoke_result.txt >/dev/null 2>&1 || true
smoke scan 18081
wait_file com.privacyshield.proxy smoke_result.txt || fail "scan produced no result"
sleep 8

echo "background" | tee -a "$OUT/result.txt"
adb shell input keyevent 3
sleep 120
vpn_up || fail "VPN dropped while backgrounded and the kill switch was not what stopped it"
probe "$OUT/socks-b.log"

MEM=$(adb shell dumpsys meminfo com.privacyshield.proxy | awk '/TOTAL PSS:/ {print $3; exit}' | tr -d '\r')
echo "totalPssKb=${MEM:-unknown}" | tee -a "$OUT/result.txt"
if [ -n "${MEM:-}" ] && [ "$MEM" -gt 900000 ]; then
  fail "PSS ${MEM}KB is excessive"
fi

adb logcat -d -v threadtime > "$OUT/logcat.txt" || true
if grep -E "FATAL EXCEPTION|ANR in com.privacyshield|Fatal signal .*privacyshield" "$OUT/logcat.txt"; then
  fail "logcat contains a fatal exception, native crash, or ANR in ShieldProxy"
fi
if adb shell ls /data/tombstones 2>/dev/null | grep -q .; then
  mkdir -p "$OUT/tombstones"
  adb pull /data/tombstones "$OUT/tombstones" || true
  if grep -R -l -i privacyshield "$OUT/tombstones" >/dev/null 2>&1; then
    fail "tombstone names ShieldProxy"
  fi
fi
echo "PASS api=$API startupSeconds=$ELAPSED totalPssKb=${MEM:-unknown}" | tee -a "$OUT/result.txt"
