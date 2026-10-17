#!/bin/sh
# Creates a private release signing key and prints what you need for GitHub. Run it on YOUR computer.
# Keep securekeyboard-release.jks and its passwords OFFLINE and backed up: lose them and you can never update the app.
set -e
OUT=securekeyboard-release.jks
ALIAS=securekeyboard
keytool -genkeypair -v -keystore "$OUT" -alias "$ALIAS" -keyalg RSA -keysize 4096 -validity 10000
echo
echo "=== Certificate SHA-256 (use it as secureKeyboardExpectedCertSha256) ==="
keytool -list -v -keystore "$OUT" -alias "$ALIAS" | grep "SHA256:"
echo
echo "=== Base64 of the keystore (GitHub secret RELEASE_KEYSTORE_B64) ==="
base64 < "$OUT" | tr -d '\n'
echo
echo
echo "GitHub -> Settings -> Secrets and variables -> Actions: add RELEASE_KEYSTORE_B64, RELEASE_STORE_PASSWORD,"
echo "RELEASE_KEY_ALIAS ($ALIAS), RELEASE_KEY_PASSWORD. The workflow must write the keystore file and export RELEASE_STORE_FILE."
