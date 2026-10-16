# V56 changes
- Keyboard did not come back after picking a file (screen recording: chat field focused, cursor blinking,
  no keyboard for 5+ s although the file had been prepared). The re-show attempts were skipped by an
  `isInputViewShown` guard that can be stale after the system file picker. Guard removed; extra fallback
  showWindow(true) when an input connection exists; retries extended to 8 s.
- The prepared file is stored first, so tapping the chat field also brings the keyboard back with the file chip.
Not compiled here: build in CI and test on a device.
