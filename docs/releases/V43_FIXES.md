# V43 fixes (keyboard bubble, hamza key, CI)

- Long-press bubble on ا / ي was invisible: it was positioned with screen coordinates inside an IME window, so it landed below the screen. It now uses window-relative coordinates with showAsDropDown (SecureInputMethodService.showVariantPopup). ا -> ا أ إ آ, ي -> ي ى ئ. A failure to show it no longer crashes the keyboard.
- Added a standalone ء key to the Arabic layout (letters page and secure-compose page).
- CI: android-actions/setup-android@v3 failed (it tries to install the removed `tools` package and the license prompt hung). Both workflows now use the runner's preinstalled SDK, accept licenses with `yes | sdkmanager --licenses`, and install platforms;android-34 and build-tools;34.0.0.
- Not compiled or run on a device by the author of this pass; verify in CI and on a phone.
