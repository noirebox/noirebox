#!/bin/sh
# Publishes the extension to the two marketplaces. Distribution credentials
# belong to the maintainer — the repo never holds them.
#   1. marketplace.visualstudio.com → create publisher "noirebox" (or yours)
#      → Personal Access Tokens (Azure DevOps, org: all, scope: Marketplace/Manage) → VSCE_PAT
#   2. open-vsx.org → create account + access token → OVSX_PAT (optional)
# Then:  VSCE_PAT=... ./publish.sh
set -e
cd "$(dirname "$0")"
[ -n "$VSCE_PAT" ] || { echo "VSCE_PAT is empty — create the token first (see header)"; exit 1; }
npx --yes @vscode/vsce package --no-dependencies
npx --yes @vscode/vsce publish -p "$VSCE_PAT"
echo "[✓] published to the Visual Studio Marketplace"
if [ -n "$OVSX_PAT" ]; then
  npx --yes ovsx publish -p "$OVSX_PAT"
  echo "[✓] published to Open VSX"
fi
