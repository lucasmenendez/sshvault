#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${SSHVAULT_BIN:-$ROOT/sshvault}"
APP="${SSHVAULT_APP:-$ROOT/build/SSHVault.app}"
ICON="${SSHVAULT_ICON:-$ROOT/packaging/macos/AppIcon.icns}"
SIGN_IDENTITY="${SSHVAULT_SIGN_IDENTITY:--}"

if [[ ! -x "$BIN" ]]; then
  echo "missing executable binary: $BIN" >&2
  echo "run 'make build' first, or set SSHVAULT_BIN" >&2
  exit 1
fi
if [[ ! -f "$ICON" ]]; then
  echo "missing app icon: $ICON" >&2
  exit 1
fi

VERSION="${SSHVAULT_VERSION:-$("$BIN" --version 2>/dev/null | awk '{print $2}')}"
VERSION="${VERSION#v}"
VERSION="${VERSION%%-*}"
if [[ ! "$VERSION" =~ ^[0-9]+(\.[0-9]+){1,2}$ ]]; then
  VERSION="0.0.0"
fi

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
install -m 0755 "$BIN" "$APP/Contents/MacOS/SSHVault"
cp "$ICON" "$APP/Contents/Resources/AppIcon.icns"
cp "$ROOT/LICENSE" "$APP/Contents/Resources/LICENSE"
printf 'APPL????' > "$APP/Contents/PkgInfo"

cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleDisplayName</key>
  <string>SSHVault</string>
  <key>CFBundleExecutable</key>
  <string>SSHVault</string>
  <key>CFBundleIconFile</key>
  <string>AppIcon</string>
  <key>CFBundleIconName</key>
  <string>AppIcon</string>
  <key>CFBundleIdentifier</key>
  <string>me.lucasmenendez.sshvault</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>SSHVault</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>${VERSION}</string>
  <key>CFBundleVersion</key>
  <string>${VERSION}</string>
  <key>LSApplicationCategoryType</key>
  <string>public.app-category.developer-tools</string>
  <key>LSEnvironment</key>
  <dict>
    <key>SSHVAULT_APP_MODE</key>
    <string>1</string>
  </dict>
  <key>LSMinimumSystemVersion</key>
  <string>12.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSHumanReadableCopyright</key>
  <string>GNU Affero General Public License v3.0 only</string>
</dict>
</plist>
EOF

plutil -lint "$APP/Contents/Info.plist" >/dev/null

if [[ "$SIGN_IDENTITY" == "-" ]]; then
  codesign --force --sign - "$APP/Contents/MacOS/SSHVault"
  codesign --force --sign - "$APP"
else
  codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" "$APP/Contents/MacOS/SSHVault"
  codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" "$APP"
fi

codesign --verify --strict "$APP" >/dev/null

echo "Created $APP (version $VERSION, identity $SIGN_IDENTITY)"
