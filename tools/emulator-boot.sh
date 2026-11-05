#!/bin/bash
# Boot one google_apis x86_64 AVD and run the smoke script.
# android-emulator-runner's post-boot `input keyevent 82` fails the job on
# API 29/30 (input service not published) and hung API 28 until the timeout.
set -eu
API=${1:?api level}
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
SDK=${ANDROID_SDK_ROOT:-${ANDROID_HOME:?}}
export PATH="$SDK/emulator:$SDK/platform-tools:$SDK/cmdline-tools/latest/bin:$PATH"
if ! command -v sdkmanager >/dev/null; then
  BIN=$(find "$SDK/cmdline-tools" -type f -name sdkmanager | head -1)
  PATH="$(dirname "$BIN"):$PATH"
fi
AVD=shield_api_$API
LOG=$ROOT/emulator-boot.log

yes | sdkmanager --sdk_root="$SDK" --install \
  "emulator" \
  "platforms;android-$API" \
  "system-images;android-$API;google_apis;x86_64" >/tmp/sdkmanager.log || true
if [ ! -d "$SDK/system-images/android-$API/google_apis/x86_64" ]; then
  echo "system image for API $API was not installed" >&2
  tail -20 /tmp/sdkmanager.log >&2 || true
  exit 1
fi

if [ ! -d "$HOME/.android/avd/${AVD}.avd" ]; then
  echo no | avdmanager create avd -n "$AVD" \
    -k "system-images;android-$API;google_apis;x86_64" -d pixel --force
  CFG=$HOME/.android/avd/${AVD}.avd/config.ini
  printf '\nhw.ramSize=2048\nhw.cpu.ncore=4\n' >> "$CFG"
fi

emulator -avd "$AVD" -port 5554 -no-window -gpu swiftshader_indirect \
  -noaudio -no-boot-anim -camera-back none -no-snapshot-save \
  -accel on -cores 4 -memory 2048 > "$LOG" 2>&1 &
EMU=$!
trap 'adb -s emulator-5554 emu kill >/dev/null 2>&1 || kill "$EMU" >/dev/null 2>&1 || true' EXIT

adb start-server >/dev/null
i=0
booted=0
while [ "$i" -lt 180 ]; do
  b=$(adb -s emulator-5554 shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || true)
  if [ "$b" = "1" ]; then
    booted=1
    break
  fi
  i=$((i + 1))
  sleep 2
done
if [ "$booted" != "1" ]; then
  echo "emulator did not boot" >&2
  exit 1
fi
# Best-effort unlock. A missing or stuck input service must not fail the job.
timeout 15 adb -s emulator-5554 shell input keyevent 82 >/dev/null 2>&1 || true
if grep -q "hardware acceleration is not available" "$LOG"; then
  echo "KVM is not available" >&2
  exit 1
fi
grep -E "Boot completed|hardware acceleration" "$LOG" || true
"$ROOT/tools/emulator-api-smoke.sh"
