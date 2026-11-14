#!/bin/bash
# Stop the daily schedule.
LABEL="local.uci-inbox-sorter"
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
rm -f "$HOME/Library/LaunchAgents/$LABEL.plist"
echo "Daily schedule removed."
