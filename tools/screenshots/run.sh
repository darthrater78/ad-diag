#!/usr/bin/env bash
# Regenerates the README screenshots from mock data: builds the harness (the app's own
# MainForm plus Shots.cs), runs it under Wine on a virtual display, and writes the PNGs to
# docs/screenshots/. Linux only. See README.md in this folder.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../.." && pwd)
work=${SHOTS_WORK:-${XDG_CACHE_HOME:-$HOME/.cache}/winforms-screenshots}
out="$repo/docs/screenshots"
dejavu=${DEJAVU_DIR:-/usr/share/fonts/truetype/dejavu}

# Pinned downloads: the fonts the app uses (Cascadia Code) or stands in for (Selawik ≈ Segoe UI)
cascadia_url=https://github.com/microsoft/cascadia-code/releases/download/v2407.24/CascadiaCode-2407.24.zip
cascadia_sha=e67a68ee3386db63f48b9054bd196ea752bc6a4ebb4df35adce6733da50c8474
selawik_url=https://github.com/microsoft/Selawik/releases/download/1.01/Selawik_Release.zip
selawik_sha=3f62c51e05e3b5a1e6241cf92a371f0be2ea1183aa87b30718bbd40832a8d423

for tool in dotnet wine wineboot wineserver xvfb-run python3 curl unzip sha256sum; do
    command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 1; }
done
if [ -f "$here/fake-tools.txt" ]; then
    command -v x86_64-w64-mingw32-gcc >/dev/null || { echo "missing: x86_64-w64-mingw32-gcc (install gcc-mingw-w64-x86-64)" >&2; exit 1; }
fi
[ -f "$dejavu/DejaVuSans.ttf" ] || { echo "DejaVu Sans not found in $dejavu (install fonts-dejavu-core or set DEJAVU_DIR)" >&2; exit 1; }

mkdir -p "$work/downloads" "$work/fonts" "$work/out"

fetch() { # url sha256 dest
    if ! echo "$2  $3" | sha256sum -c --quiet >/dev/null 2>&1; then
        curl -fsSL -o "$3.tmp" "$1"
        echo "$2  $3.tmp" | sha256sum -c --quiet
        mv "$3.tmp" "$3"
    fi
}
fetch "$cascadia_url" "$cascadia_sha" "$work/downloads/cascadia.zip"
fetch "$selawik_url" "$selawik_sha" "$work/downloads/selawik.zip"
unzip -oq "$work/downloads/cascadia.zip" -d "$work/downloads/cascadia"
unzip -oq "$work/downloads/selawik.zip" -d "$work/downloads/selawik"

if [ ! -x "$work/venv/bin/python" ]; then
    python3 -m venv "$work/venv"
    "$work/venv/bin/pip" install -q fonttools==4.66.0 pillow==12.3.0
fi
"$work/venv/bin/python" "$here/prep.py" fonts "$work/downloads" "$work/fonts" "$dejavu"

# Isolated Wine prefix; fonts go in its Fonts folder and are exposed to fontconfig too
export WINEPREFIX="$work/prefix" WINEDEBUG=-all
cat > "$work/fonts.conf" <<CONF
<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "fonts.dtd">
<fontconfig>
  <include ignore_missing="yes">/etc/fonts/fonts.conf</include>
  <dir>$work/fonts</dir>
  <cachedir>$work/fccache</cachedir>
</fontconfig>
CONF
export FONTCONFIG_FILE="$work/fonts.conf"
[ -d "$WINEPREFIX/drive_c" ] || xvfb-run -a wineboot -i >/dev/null 2>&1
cp "$work/fonts/"*.ttf "$WINEPREFIX/drive_c/windows/Fonts/"
cat > "$work/fonts.reg" <<'REG'
REGEDIT4

[HKEY_CURRENT_USER\Software\Wine\Fonts\Replacements]
"Segoe UI"="Selawik"

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Fonts]
"Selawik (TrueType)"="selawk.ttf"
"Selawik Bold (TrueType)"="selawkb.ttf"
"Cascadia Code Regular (TrueType)"="CascadiaCode-Regular.ttf"
"Cascadia Code Bold (TrueType)"="CascadiaCode-Bold.ttf"

[HKEY_CURRENT_USER\Control Panel\Desktop]
"FontSmoothing"="2"
"FontSmoothingType"=dword:00000002
REG
xvfb-run -a wine regedit "$work/fonts.reg"
wineserver -w

# Optional stand-ins for Windows tools the app runs (listed in fake-tools.txt): each prints
# the mock output Shots.cs writes to $SHOTS_FAKE_DIR, so the app's own parsing runs on it
mkdir -p "$work/fake"
if [ -f "$here/fake-tools.txt" ]; then
    overrides=""
    while read -r tool; do
        [ -n "$tool" ] || continue
        x86_64-w64-mingw32-gcc -O2 -s -o "$WINEPREFIX/drive_c/windows/system32/$tool.exe" "$here/faketool.c"
        overrides+="$tool.exe=n;"
    done < "$here/fake-tools.txt"
    export WINEDLLOVERRIDES="$overrides"
fi
export SHOTS_FAKE_DIR="Z:${work//\//\\}\\fake"

version=$(sed -n 's:.*<Version>\(.*\)</Version>.*:\1:p' "$repo"/*.csproj | head -1)
dotnet build "$here/Shots.csproj" -c Release -nologo -v q -p:Version="$version" -o "$work/build"
exe=$(find "$work/build" -maxdepth 1 -name '*.exe' ! -name createdump.exe | head -1)

rm -f "$work/out/"*.png
xvfb-run -a -s "-screen 0 1280x1800x24" wine "$exe" "Z:${work//\//\\}\\out"
"$work/venv/bin/python" "$here/prep.py" crop "$work/out/"*.png

mkdir -p "$out"
cp "$work/out/"*.png "$out/"
echo "Screenshots written to $out:"
ls -1 "$out"
