# Two hardening steps only you can do (they need GitHub / your own key)

## 1. Dependency verification (supply chain)
Today gradle/verification-metadata.xml and the lockfiles do not exist, so Gradle does not check the checksums of
libraries it downloads.
1. GitHub -> Actions -> "Dependency Verification Bootstrap (review before merge)" -> Run workflow.
2. Download the artifact `gradle-verification-metadata-<sha>`.
3. REVIEW it (every library should be a known one: androidx, material, bouncycastle, zxing, robolectric/test libs).
   Do not merge something you do not recognise.
4. Put `gradle/verification-metadata.xml` and the `*.lockfile` files in the repository, commit, and run the normal
   build. From now on a tampered or changed library makes the build fail.

## 2. Private signing key + certificate pinning
1. On your computer run `sh tools/make_release_keystore.sh` (needs Java's keytool). Store the .jks and passwords offline.
2. Add the four GitHub secrets it prints (RELEASE_KEYSTORE_B64, RELEASE_STORE_PASSWORD, RELEASE_KEY_ALIAS,
   RELEASE_KEY_PASSWORD) and make the build workflow decode the keystore and export RELEASE_STORE_FILE.
3. Give me the printed SHA-256 (or set `secureKeyboardExpectedCertSha256=<hash>` in gradle.properties). The app then
   refuses to run if it was re-signed by someone else (SecurityRuntime already supports this).
