#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p reports

if [[ -z "${NFC_TEST_DESTINATION:-}" ]]; then
  DEVICE_ID="$(xcrun simctl list devices available --json | python3 -c '
import json, sys
for runtime, devices in json.load(sys.stdin)["devices"].items():
    if ".iOS-" not in runtime:
        continue
    for device in devices:
        if device.get("isAvailable"):
            print(device["udid"])
            sys.exit(0)
sys.exit("No available iOS simulator; install an iOS runtime in Xcode.")
')"
  NFC_TEST_DESTINATION="platform=iOS Simulator,id=$DEVICE_ID"
fi

xcodebuild test \
  -scheme AMANFCPassportReader \
  -destination "$NFC_TEST_DESTINATION" \
  -derivedDataPath "${NFC_DERIVED_DATA:-build/DerivedData}" \
  -resultBundlePath "${NFC_TEST_RESULTS:-reports/NFCPassportReader.xcresult}" \
  -parallel-testing-enabled NO \
  CODE_SIGNING_ALLOWED=NO 2>&1 | tee reports/xcodebuild.log
