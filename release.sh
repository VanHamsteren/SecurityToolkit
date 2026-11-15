#!/usr/bin/env bash
# Build a release package: ./release.sh 1.7.9
# Bumps the version in manifest.json and options.html, replaces the old
# security_toolkit-*.xpi in the repo root with the new one, and prints what is left to do.
set -euo pipefail
cd "$(dirname "$0")"

VERSION="${1:-}"
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Usage: $0 <major.minor.patch>   e.g. $0 1.7.9" >&2
    exit 1
fi

CURRENT=$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' manifest.json | head -1)
if [[ "$CURRENT" == "$VERSION" ]]; then
    echo "manifest.json is already at $VERSION" >&2
    exit 1
fi

if ! grep -q "Version $VERSION" README.md; then
    echo "README.md has no 'Version $VERSION' changelog heading yet. Add it first." >&2
    exit 1
fi

sed -i.bak "s/\"version\": *\"$CURRENT\"/\"version\": \"$VERSION\"/" manifest.json
sed -i.bak "s/Version $CURRENT\. All API/Version $VERSION. All API/" options.html
rm -f manifest.json.bak options.html.bak

for f in background.js busy.js checks.js options.js popup.js quickscan.js report.js; do
    node --check "$f"
done

rm -f security_toolkit-*.xpi
zip -q -X -D -r "security_toolkit-$VERSION.xpi" \
    manifest.json background.js busy.js checks.js options.js popup.js quickscan.js report.js \
    options.html popup.html report.html brand.css options.css popup.css report.css \
    icons img fonts

echo "Built security_toolkit-$VERSION.xpi (was $CURRENT)"
echo "Next: commit, merge, then upload the .xpi at https://addons.mozilla.org/developers/addons"
