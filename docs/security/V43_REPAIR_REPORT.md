# SecureKeyboard V43 — Repair notes

This archive contains source-level repairs applied during static review. It is not a certified security audit.

## Changes applied
- Removed `-Dorg.gradle.dependency.verification=off` from the pre-audit workflow's unit-test, debug-build, and release-build commands. CI no longer explicitly disables strict checksum verification.
- Added an explicit CI preflight check for the required reviewed dependency verification metadata and app dependency lockfile. CI now reports the missing prerequisite clearly instead of silently bypassing verification.
- Updated the manually triggered bootstrap workflow to generate both app and buildscript dependency lockfiles before generating checksum metadata. The bootstrap-only workflow temporarily disables checksum verification while creating the initial trusted records; its generated output must be reviewed before merging.
- Aligned Android `versionCode` / `versionName` with the V43 / 4.3 archive label.
- Updated the supply-chain guide to describe the current fail-fast behavior.
- Regenerated the SHA-256 integrity manifest for the files included in the project.

## Remaining release blockers
- `gradle/verification-metadata.xml` and dependency lockfiles are absent from the supplied archive. They must be generated on a trusted, network-enabled machine/CI runner, reviewed by a human, and committed. The bootstrap workflow generates verification metadata only; dependency lockfiles also need to be generated as documented in `docs/security/SUPPLY_CHAIN.md`.
- `gradle/wrapper/gradle-wrapper.jar` is absent. The workflow currently installs Gradle 8.4 directly, so CI does not require the wrapper JAR; local `./gradlew` execution may not work until a trusted Gradle wrapper is generated.
- No APK/AAB is included. Build, unit tests, Android instrumentation tests, signing, and device behavior were not verified in this environment.
- The integrity manifest is a file-integrity list, not proof of authorship or security.

## Suggested next steps
1. On a trusted network-enabled runner, generate dependency lockfiles and verification metadata using the pinned Gradle/Java toolchain.
2. Review every new checksum and dependency coordinate before committing the generated files.
3. Run the pre-audit workflow; run Android instrumentation tests on an emulator/device.
4. Perform a manual review of accessibility-service behavior, keyboard input handling, key lifecycle, and release signing before public distribution.
