# AcroBounced

Portable Windows tray app that blocks configured executables by exact path.

## Use

1. Keep `AcroBounced.exe` in a writable folder.
2. Start it. The supplied icon appears in the notification area.
3. Edit `AcroBounced.json`, then choose **Reload rules and sweep now** from the tray menu.

At every launch and reload, AcroBounced terminates already-running matches. While it remains open, WMI process-start events are used to terminate new matches. If Windows denies WMI event subscriptions, AcroBounced falls back to a one-second process snapshot and inspects only newly seen PIDs. Events are written to `AcroBounced.log`; the log rotates at 1 MiB.

The first run creates rules for the usual 64-bit and 32-bit Adobe Acrobat paths. Rules are case-insensitive after environment expansion and Windows path normalization.

Run AcroBounced as administrator when it must terminate an elevated process. Closing the tray app stops enforcement.

## Build

```powershell
cargo test
cargo build --release
```

The portable executable is `target\release\acrobounced.exe`.
