#!/usr/bin/env bash
# Build + install to ~/.local/lib/argv-guard/ and print the arming line.
# System-wide (profile.d) and rc edits are the user's step — not done here.
set -euo pipefail
cd "$(dirname "$0")"

cargo build --release

dest="$HOME/.local/lib/argv-guard"
mkdir -p "$dest"
cp -f target/release/libargvguard.so "$dest/libargvguard.so"
echo "installed: $dest/libargvguard.so"
echo
echo "arm (add to ~/.bashrc and/or ~/.zshrc, then restart shells / relaunch opencode):"
echo "  export LD_PRELOAD=\"$dest/libargvguard.so\${LD_PRELOAD:+:\$LD_PRELOAD}\""
echo
echo "bypass: ARVGUARD_OFF=1 <command>   |   hits log: ~/.local/share/argv-guard/hits.log"
