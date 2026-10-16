# V59 changes
- Secure-compose page: the whole keyboard moved up/down a little when 🔐 was pressed. Cause: the status/notice
  strip switched between GONE and VISIBLE (adds/removes ~40dp), so the keyboard window changed height.
- Fix: the notice is now drawn over the contact line inside ONE fixed-height (38dp) slot; the contact line is
  hidden while a notice shows and restored after. Total height never changes. Notices are limited to 2 lines.
Not compiled here: build in CI and test on a device.
