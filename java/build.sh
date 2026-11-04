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
VERSION="1.0.0"
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

package_app() {
  local target="${1:-linux}"
  echo
  echo "=== Paketieren fuer $target ==="
  if [[ "$target" == "linux" ]]; then
    "$JPACKAGE" \
      --name "$APP_NAME" \
      --app-version "$VERSION" \
      --vendor "Jonas Hillmann" \
      --description "Recovery fuer abgebrochene Huawei/Honor KoBackup-Backups" \
      --input "$OUT" \
      --main-jar "$APP_NAME.jar" \
      --main-class "$MAIN_CLASS" \
      --linux-app-name huawei-backup-recovery \
      --linux-package-name huawei-backup-recovery \
      --linux-deb-maintainer "jonas@example.com" \
      --dest dist
  elif [[ "$target" == "windows" ]]; then
    # jpackage fuer Windows laeuft unter Linux nur mit cross-Toolchain.
    # Empfehlung: auf einem Windows-Rechner ausfuehren.
    "$JPACKAGE" \
      --name "$APP_NAME" \
      --app-version "$VERSION" \
      --vendor "Jonas Hillmann" \
      --description "Recovery fuer abgebrochene Huawei/Honor KoBackup-Backups" \
      --input "$OUT" \
      --main-jar "$APP_NAME.jar" \
      --main-class "$MAIN_CLASS" \
      --win-console \
      --dest dist
  fi
  echo "Artefakte in dist/"
}

case "${1:-all}" in
  build)   build ;;
  test)    build && test_roundtrip ;;
  package) build && test_roundtrip && package_app "${2:-linux}" ;;
  all)     build && test_roundtrip ;;
  *)       echo "Unbekannter Aufruf: $1"; exit 1 ;;
esac

echo
echo "FERTIG."
