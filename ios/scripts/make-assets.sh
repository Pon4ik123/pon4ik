#!/usr/bin/env bash
# Рисует иконку, аватар и персонажа из SVG в Assets.xcassets (нужен rsvg-convert: brew install librsvg)
set -euo pipefail
cd "$(dirname "$0")/.."
A=App/Assets.xcassets
rm -rf "$A" && mkdir -p "$A/AppIcon.appiconset" "$A/Avatar.imageset" "$A/Mascot.imageset"
echo '{"info":{"version":1,"author":"xcode"}}' > "$A/Contents.json"

# Иконка: пончик на розовом фоне, без прозрачности (требование iOS)
rsvg-convert -w 1024 -h 1024 -b "#FFE8F1" art/pon4ik-icon.svg -o "$A/AppIcon.appiconset/icon-1024.png"
cat > "$A/AppIcon.appiconset/Contents.json" <<'J'
{"images":[{"filename":"icon-1024.png","idiom":"universal","platform":"ios","size":"1024x1024"}],"info":{"version":1,"author":"xcode"}}
J

rsvg-convert -w 512 -h 512 -b "#FFE8F1" art/pon4ik-icon.svg -o "$A/Avatar.imageset/avatar.png"
cat > "$A/Avatar.imageset/Contents.json" <<'J'
{"images":[{"filename":"avatar.png","idiom":"universal"}],"info":{"version":1,"author":"xcode"}}
J

rsvg-convert -w 600 -h 600 art/pon4ik.svg -o "$A/Mascot.imageset/mascot.png"
cat > "$A/Mascot.imageset/Contents.json" <<'J'
{"images":[{"filename":"mascot.png","idiom":"universal"}],"info":{"version":1,"author":"xcode"}}
J
echo "assets ok"
