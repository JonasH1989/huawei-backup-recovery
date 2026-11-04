#!/usr/bin/env bash
# Build-Skript fuer das Huawei-Backup-Recovery-Tool.
#
# Aufruf:
#   ./build.sh              -> kompilieren + Roundtrip-Test laufen lassen
#   ./build.sh test         -> nur den Roundtrip-Test
#   ./build.sh package      -> startbares Programm bauen (Linux/Windows)
#   ./build.sh package linux
#   ./build.sh package windows
#
# Benötigt ein JDK 21 (javac, jar, jpackage). Pfad über JAVA_HOME setzbar.
set -euo pipefail

cd "$(dirname "$0")"

JAVA_HOME="${JAVA_HOME:-$HOME/opt/jdk-21.0.13+9}"
JAVAC="$JAVA_HOME/bin/javac"
JAVA="$JAVA_HOME/bin/java"
JAR="$JAVA_HOME/bin/jar"
JPACKAGE="$JAVA_HOME/bin/jpackage"

if [[ ! -x "$JAVAC" ]]; then
  echo "FEHLER: javac nicht gefunden unter $JAVAC"
  echo "JAVA_HOME setzen oder JDK 21 installieren."
  exit 1
fi

APP_NAME="Huawei-Backup-Recovery"
MAIN_CLASS="de.jonas.huaweibackup.ui.RecoveryWindow"
VERSION="1.3.0"
OUT="out"

build() {
  echo "=== Kompilieren ==="
  rm -rf "$OUT"
  mkdir -p "$OUT"
  "$JAVAC" -d "$OUT" $(find src/main/java -name "*.java")
  "$JAVAC" -cp "$OUT" -d "$OUT" $(find src/test/java -name "*.java")
  echo "OK"

  echo
  echo "=== Manifest ==="
  mkdir -p "$OUT/../manifest"
  cat > "$OUT/../manifest/MANIFEST.MF" <<EOF
Manifest-Version: 1.0
Main-Class: $MAIN_CLASS
Implementation-Title: $APP_NAME
Implementation-Version: $VERSION
EOF
}

test_roundtrip() {
  echo
  echo "=== Roundtrip-Test (bytegenauer Vergleich) ==="
  "$JAVA" -cp "$OUT" de.jonas.huaweibackup.RoundtripTest /tmp/hw_java_test
}

# Staging-Verzeichnis: jpackage braucht die Haupt-JAR relativ zum
# Eingabeverzeichnis und dort vorhanden. Ohne dieses Staging schlaegt
# jpackage mit "Die Haupt-JAR-Datei ist im Eingabeverzeichnis nicht
# vorhanden" fehl.
stage() {
  rm -rf staging
  mkdir -p staging
  cp -r "$OUT"/* staging/
  "$JAR" --create --file "staging/$APP_NAME.jar" \
    --main-class "$MAIN_CLASS" -C "$OUT" .
}

package_linux() {
  echo
  echo "=== Paketieren fuer Linux (app-image) ==="
  rm -rf "dist/$APP_NAME"
  stage
  "$JPACKAGE" \
    --name "$APP_NAME" \
    --app-version "$VERSION" \
    --vendor "Jonas Hillmann" \
    --description "Recovery fuer abgebrochene Huawei/Honor KoBackup-Backups" \
    --input staging \
    --main-jar "$APP_NAME.jar" \
    --main-class "$MAIN_CLASS" \
    --type app-image \
    --dest dist
  echo "Startbar: dist/$APP_NAME/bin/$APP_NAME"
}

# Windows laeuft nicht ueber jpackage unter Linux (kein Cross-Toolchain).
# Stattdessen: portable Temurin-JRE + JAR + start.bat. Die JRE bringt das
# Programm ohne Java-Installation auf den Windows-Rechner.
package_windows() {
  echo
  echo "=== Paketieren fuer Windows (portable JRE) ==="
  local url="https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jre/hotspot/normal/eclipse?project=jdk"
  local tmp
  tmp="$(mktemp -d)"
  echo "JRE herunterladen (~49 MB) ..."
  curl -sL -o "$tmp/jre.zip" "$url"
  unzip -q -o "$tmp/jre.zip" -d "$tmp/jre"
  local jre_dir
  jre_dir="$(find "$tmp/jre" -maxdepth 1 -type d -name 'jdk-*' | head -1)"

  rm -rf "dist-windows/$APP_NAME"
  mkdir -p "dist-windows/$APP_NAME"
  stage
  cp "staging/$APP_NAME.jar" "dist-windows/$APP_NAME/"
  cp -r "$jre_dir" "dist-windows/$APP_NAME/runtime"

  cat > "dist-windows/$APP_NAME/start.bat" <<'EOF'
@echo off
REM Huawei Backup Recovery - Starter
REM Enthaelt eine eigene Java-Laufzeit, Java muss nicht installiert sein.
cd /d "%~dp0"
set "JRE=%~dp0runtime"
if exist "%JRE%\bin\javaw.exe" (
    start "" "%JRE%\bin\javaw.exe" -jar "%~dp0Huawei-Backup-Recovery.jar"
) else (
    echo Java-Laufzeit nicht gefunden: %JRE%
    pause
)
EOF

  cat > "dist-windows/$APP_NAME/LIESMICH.txt" <<'EOF'
Huawei Backup Recovery - Recovery abgebrochener Huawei/Honor KoBackup-Backups

STARTEN:
  start.bat doppelklicken (bzw. "Starten" im Explorer)

Die eigene Java-Laufzeit liegt im Ordner "runtime" - es muss KEIN Java
installiert sein. Der Ordner "runtime" darf nicht verschoben oder
geloescht werden.

Ablauf im Programm:
  1. Pfad zum Backup eintragen (Ordner mit den verschluesselten Daten)
  2. Passwort eingeben
  3. "Start" druecken
  4. Protokoll und Ergebnisliste im Fenster beobachten
  5. Gerettete Dateien landen im Ausgabeordner

WICHTIG: Das Original-Backup wird nur gelesen, nie veraendert.
Das Ergebnis wird immer in einen separaten Ausgabeordner geschrieben.
EOF

  (cd dist-windows && zip -qr "../dist/$APP_NAME-windows-x64.zip" "$APP_NAME")
  rm -rf "$tmp"
  echo "Startbar: dist/$APP_NAME-windows-x64.zip"
}

case "${1:-all}" in
  build)   build ;;
  test)    build && test_roundtrip ;;
  package)
    build && test_roundtrip
    case "${2:-linux}" in
      linux)   package_linux ;;
      windows) package_windows ;;
      *)       echo "Unbekanntes Ziel: $2 (linux|windows)"; exit 1 ;;
    esac
    ;;
  all)     build && test_roundtrip ;;
  *)       echo "Unbekannter Aufruf: $1"; exit 1 ;;
esac

echo
echo "FERTIG."
