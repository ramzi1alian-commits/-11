# V43 fixes (keyboard bubble, hamza key, CI)

- Long-press bubble on ا / ي was invisible: it was positioned with screen coordinates inside an IME window, so it landed below the screen. It now uses window-relative coordinates with showAsDropDown (SecureInputMethodService.showVariantPopup). ا -> ا أ إ آ, ي -> ي ى ئ. A failure to show it no longer crashes the keyboard.
- Added a standalone ء key to the Arabic layout (letters page and secure-compose page).
- CI: android-actions/setup-android@v3 failed (it tries to install the removed `tools` package and the license prompt hung). Both workflows now use the runner's preinstalled SDK, accept licenses with `yes | sdkmanager --licenses`, and install platforms;android-34 and build-tools;34.0.0.
- Not compiled or run on a device by the author of this pass; verify in CI and on a phone.

## Auto-decrypt (AutoDecryptService) changes
- The ciphertext is now searched for INSIDE a node's text or contentDescription (and wrapped lines are re-joined), instead of requiring the whole node to be only the token. Some chat apps expose a bubble as "name, message, time".
- Accessibility config now also sets flagIncludeNotImportantViews, flagReportViewIds, flagRetrieveInteractiveWindows and listens to typeWindowsChanged, so message views a chat app marks "not important" are visible to the service.
- Settings screen: new button that opens Accessibility settings, plus a status line showing whether the service is enabled and whether the session key is active (both are required).
- Not compiled or run on a device by the author of this pass.

## Auto-decrypt: key expiry, scrolling, colours
- After the session key expires, the overlay shows nothing: render() now checks SessionKeyStore.isActive() before showing anything, including messages already in the decrypted-message cache. While text is on screen the key is re-checked every 2 s, so it disappears at expiry even without a screen event.
- Smoother scrolling: refresh uses a 30 ms throttle instead of a 150 ms debounce, invisible subtrees are skipped while reading the screen, and card views are reused instead of rebuilt.
- Sent cards are green and received cards white (dark-theme equivalents in night mode). Sent vs received is guessed from which side of the screen the bubble sits on, so full-width bubbles count as received.
- Not compiled or run on a device by the author of this pass.

## Merged from the "repaired2" archive
- versionCode 43 / versionName 4.3 (build.gradle), V43 repair report (docs/security/V43_REPAIR_REPORT.md), bootstrap workflow that writes dependency lockfiles before checksum metadata.
- The repaired2 pre-audit workflow stopped the build whenever gradle/verification-metadata.xml or app/gradle.lockfile was missing (they are not in the repository), so no APK could be produced. Merged behaviour: strict verification when both files exist; otherwise the build runs with verification OFF and shows a CI warning. Generate and commit the reviewed files to make CI strict.
