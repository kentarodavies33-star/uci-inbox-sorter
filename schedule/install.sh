#!/bin/bash
# Run the sorter every day at a set time using macOS launchd.
# Usage:  bash schedule/install.sh          (8:00 AM)
#         bash schedule/install.sh 21 30    (9:30 PM)
set -euo pipefail

HOUR="${1:-8}"
MINUTE="${2:-0}"
LABEL="local.uci-inbox-sorter"
PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"

mkdir -p "$PROJECT/logs" "$HOME/Library/LaunchAgents"

cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PROJECT/.venv/bin/python</string>
    <string>$PROJECT/sorter.py</string>
    <string>--scheduled</string>
  </array>
  <key>WorkingDirectory</key><string>$PROJECT</string>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key><integer>$HOUR</integer>
    <key>Minute</key><integer>$MINUTE</integer>
  </dict>
  <key>StandardOutPath</key><string>$PROJECT/logs/sorter.log</string>
  <key>StandardErrorPath</key><string>$PROJECT/logs/sorter.log</string>
</dict>
</plist>
PLIST

launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
printf "Scheduled: the sorter will run every day at %02d:%02d.\n" "$HOUR" "$MINUTE"
echo "Log file:  $PROJECT/logs/sorter.log"
echo "Run it now to test:  launchctl kickstart gui/$(id -u)/$LABEL"
