# Huawei/Honor KoBackup – Recovery für abgebrochene Backups

Werkzeug, um Bilder/Videos aus einem **unvollständigen** Huawei-Backup
zurückzugewinnen, bei dem die Index-Datei (`info.xml`) durch einen Abbruch
mitten im Backup beschädigt ist.

Zwei Auslieferungsformen, beide aus derselben fachlichen Basis:

| | Java-Desktop-App | Python-CLI |
|---|---|---|
| **Ziel** | Lokal auf Jonas' Rechner starten | Server / Skript / Automatisierung |
| **Oberfläche** | Swing-GUI mit Pfad, Passwort, Fortschritt | Kommandozeile |
| **Plattformen** | Windows + Linux (via `jpackage`) | überall mit Python 3 + pycryptodome |
| **Start** | `build.sh package` → startbares Programm | `python3 huawei_backup_recover.py …` |

Die rechenintensive Arbeit läuft in **beiden** Fällen lokal auf dem
Rechner, der das Backup liest. Kein Netzlaufwerk, kein WebDAV, kein
Nextcloud – siehe [Warum nicht Nextcloud](#warum-nicht-nextcloud).

---

## Das Problem

Beim Backup auf dem Gerät (HiSuite / „Sichern auf USB-Stick") bricht der
Vorgang ab. Danach gilt:

- Bilder/Videos liegen verschlüsselt auf dem Stick, sind aber **nicht
  mehr über den normalen Weg lesbar**
- Die Index-Datei (`info.xml` / `cinfoset.dat`) ist **beschädigt und
  unvollständig**
- Das Passwort ist bekannt
- Die betroffenen Dateien selbst sind **intakt** – nur die Verwaltung
  fehlt

## Die Antwort: ja, das ist möglich

Die Verschlüsselung ist dateiweise, nicht containerweise. Jede Datei
bekommt ihren Schlüssel aus einem Salz, das pro Modul in der Index-Datei
stand. Für die eigentliche Rettung braucht man:

| Schema | Benötigt | Woher |
|---|---|---|
| **A** – KoBackup v10…v12 (AES-256-CTR) | `e_perbackupkey` + `pwkey_salt` + `encMsgV3` | Index-Datei |
| **B** – KoBackup v13 / HiSuite 11+ (AES-256-GCM) | nur `encMsgV3` (Salz + Nonce) | Index-Datei |

**Schema B braucht kein `e_perbackupkey`** – der Schlüssel folgt direkt aus
Passwort und Salz. Das ist die wichtigste Rettungschance: Selbst wenn die
Index-Datei nur teilweise beschädigt ist, genügt das Salz eines einzelnen
Moduls.

### Die drei Rettungswege

1. **Strukturierte Auswertung** – `info.xml`, `cinfoset.dat`,
   `backupinfo.ini` werden geparst (UTF-8 *und* UTF-16).
2. **Rohtext-Rettung** – alle Hex-Blöcke werden zusätzlich über den
   **gesamten** Backup-Bestand gesucht, nicht nur in den Index-Dateien.
   Ein Backup bricht an genau einer Stelle ab; die Kopie des Index an
   anderer Stelle kann intakt sein. Abgeschnittene Hex-Werte werden
   rekonstruiert.
3. **Signatur-Verifikation** – jede Datei wird mit jedem plausiblen
   Schlüssel entschlüsselt und anhand der Dateisignatur (JPEG/PNG/MP4/
   SQLite/…) geprüft.

Punkt 3 ist der Kern: **Ordnerstruktur und Index-Vollständigkeit sind
nicht nötig.** Was die Signaturprüfung besteht, ist gültiger Klartext.

---

## Die grafische Oberfläche (Java)

![Fenster](docs/screenshot-beschreibung.md)

Bedienung:

1. **Backup-Pfad** eintragen oder über „Backup wählen" auswählen
2. **Passwort** eintragen (maskiert)
3. **Ausgabe-Pfad** eintragen oder auswählen
4. **Start** drücken

Danach zeigt das Fenster:

- ein **Protokoll** mit dem kompletten Lauf (Index-Auswertung, Kandidaten,
  Einzelmeldungen)
- eine **Ergebnisliste** mit `OK` / `FEHL` je Datei, erkanntem Dateityp und
  dem Marker `[authentifiziert]` bzw. `[unvollständig]`
- eine **Fortschrittsanzeige** (`n / gesamt`)
- **Fehlermeldungen** als Dialog, wenn nichts entschlüsselt werden konnte

Der Lauf läuft im Hintergrund, das Fenster bleibt bedienbar. Das Passwort
wird nach dem Start aus dem Feld entfernt.

### Installation (fertige Pakete)

Die Pakete liegen als GitHub-Release bereit – **kein Java nötig**, die
Java-Laufzeit ist jeweils enthalten:

**Windows (x64)**

1. [Huawei-Backup-Recovery-windows-x64.zip](https://github.com/JonasH1989/huawei-backup-recovery/releases/download/v1.0.0/Huawei-Backup-Recovery-windows-x64.zip) herunterladen
2. Entpacken (z. B. nach `C:\Huawei-Backup-Recovery`)
3. **`start.bat` doppelklicken**

Der Ordner `runtime` enthält die eigene Java-Laufzeit und darf **nicht**
verschoben oder gelöscht werden.

**Linux (x64)**

1. [Huawei-Backup-Recovery-linux-x64.tar.gz](https://github.com/JonasH1989/huawei-backup-recovery/releases/download/v1.0.0/Huawei-Backup-Recovery-linux-x64.tar.gz) herunterladen und entpacken
2. Starten mit `./Huawei-Backup-Recovery/bin/Huawei-Backup-Recovery`

**Universelles JAR** (für alle, die Java 21+ schon haben)

[Huawei-Backup-Recovery.jar](https://github.com/JonasH1989/huawei-backup-recovery/releases/download/v1.0.0/Huawei-Backup-Recovery.jar)

```bash
java -jar Huawei-Backup-Recovery.jar
```

### Bedienung im Programm

1. **Pfad zum Backup** eintragen – der Ordner mit den verschlüsselten Daten
2. **Passwort** eingeben
3. **„Start"** drücken
4. Protokoll und Ergebnisliste (`OK` / `FEHL` je Datei, erkannter Dateityp)
   im Fenster beobachten
5. Gerettete Dateien landen im **Ausgabeordner**

Das Original-Backup wird nur **gelesen**, nie verändert. Das Ergebnis landet
immer in einem separaten Ausgabeordner.

### Bauen (für Nachbauten)

```bash
# JDK 21 bereitstellen (falls nicht vorhanden)
export JAVA_HOME=~/opt/jdk-21.0.13+9

cd java
./build.sh test               # kompilieren + Roundtrip-Test
./build.sh package linux      # startbares Linux-Programm in dist/
./build.sh package windows    # portables Windows-Paket (JRE + ZIP)
```

`./build.sh package windows` legt eine portable Temurin-JRE 21 daneben – damit
läuft das Programm auf Windows ohne Java-Installation. Ein echtes
`jpackage --type exe` für Windows braucht einen Windows-Rechner.

### Ausführen ohne Paketierung

```bash
./build.sh build
java -cp out de.jonas.huaweibackup.ui.RecoveryWindow
```

---

## Die Kommandozeilen-Variante (Python)

```bash
pip install pycryptodome

# 1) Bestandsaufnahme – read-only, verändert nichts
python3 huawei_backup_recover.py --inspect /pfad/zum/backup

# 2) Entschüsselung
export HUAWEI_BACKUP_PASSWORD='…'
python3 huawei_backup_recover.py --recover /pfad/zum/backup --out /pfad/zum/ausgabe
```

Ohne `HUAWEI_BACKUP_PASSWORD` wird das Passwort interaktiv abgefragt
(dann landet es nicht in der Shell-History).

Ausgabe:

```
  [1/5] IMG_0002.jpg   -> .jpg (B) [authentifiziert]
  [2/5] IMG_0001.jpg   -> .jpg (B) [authentifiziert]
  [3/5] VID_0001.mp4   -> .mp4 (B) [authentifiziert]

  entschluesselt: 5 | nicht entschluesselbar: 0
```

---

## Warum nicht Nextcloud

Nutzdaten über Nextcloud oder WebDAV zu transportieren ist für große
Dateimengen ausgeschlossen: viele kleine Dateien erzeugen beim Schreiben
sofort einen Upload, das Bandbreitenlimit reißt, und ein WebDAV-Mount ist
keine native Dateisystemebene – das System wird instabil.

Ein WebDAV-Mount ist damit **kein** Ersatz für ein Netzlaufwerk. Wenn der
Server die Daten später braucht, ist ein **Netzlaufwerk** (SMB/NFS) der
richtige Weg.

Konsequenz für die Architektur: Der rechenintensive Teil (Entschlüsseln)
läuft **auf Jonas' Rechner**, nicht auf dem Server. Der Server liefert
höchstens den Code.

---

## Grenzen (ehrlich benannt)

- **Ohne Salz ist nichts zu holen.** Ist der Index so zerstört, dass weder
  `encMsgV3` noch `e_perbackupkey`/`pwkey_salt` zu bergen sind, lässt sich
  der Schlüssel nicht ableiten – Verschlüsselung ist nicht umkehrbar. Das
  Tool sagt das explizit, statt still zu scheitern.
- **Ein falsches Passwort** scheitert an der GCM-Authentifizierung
  (Schema B) bzw. am bkey-Tag (Schema A) – nicht an einem späteren
  Dateiformat-Fehler.
- **Fremde Verschlüsselungsverfahren** (andere HiSuite-Version) werden
  nicht erkannt. In dem Fall: Header-Dateien hexdumpen und mit dem
  Algorithmus aus `irsl/Huawei-Hisuite-KobackupCipherTool` abgleichen.

---

## Getestet

Der Roundtrip-Test erzeugt synthetische Backups beider Schemata, je mit
intaktem und mit **mitten im Attribut abgeschnittenem** Index, stellt sie
wieder her und vergleicht **bytegenau** mit dem Original. Ein Test, der nur
prüft „die Datei öffnet sich", ist kein Test.

```
schema_a             5 identisch, 0 abweichend
schema_a_corrupt     5 identisch, 0 abweichend
schema_b             5 identisch, 0 abweichend
schema_b_corrupt     5 identisch, 0 abweichend
```

Der Test läuft in **beiden** Sprachen – Python (`make_test_backup.py` +
`huawei_backup_recover.py`) und Java (`RoundtripTest`).

```bash
# Java
cd java && ./build.sh test

# Python
python3 make_test_backup.py /tmp/hw_test
python3 huawei_backup_recover.py --recover /tmp/hw_test/schema_b --out /tmp/hw_out
```

---

## Projektstruktur

```
huawei-backup-recovery/
├── README.md                       ← dieses Dokument
├── huawei_backup_recover.py        ← Python-CLI
├── make_test_backup.py             ← synthetische Backups (Python)
├── docs/
│   ├── ALGORITHMUS.md              ← die(reverse-engineerten) Verfahren
│   └── GCM-IN-JAVA.md              ← gemessenes Provider-Verhalten
└── java/
    ├── build.sh                    ← Build + Test + jpackage
    └── src/
        ├── main/java/de/jonas/huaweibackup/
        │   ├── core/
        │   │   ├── Crypto.java           ← PBKDF2, AES-CTR, AES-GCM
        │   │   ├── IndexScanner.java     ← Index-Auswertung + Rohtext-Rettung
        │   │   ├── CandidateBuilder.java ← Schlüssel-Kandidaten
        │   │   ├── KeyCandidate.java
        │   │   ├── Signatures.java       ← Dateisignatur-Erkennung
        │   │   ├── BadPasswordException.java
        │   │   └── RecoveryEngine.java   ← der Lauf
        │   └── ui/
        │       └── RecoveryWindow.java   ← die grafische Oberfläche
        └── test/java/de/jonas/huaweibackup/
            ├── TestBackupBuilder.java
            └── RoundtripTest.java
```

## Quellen der reverse-engineerten Algorithmen

- `uncognic/kobackup-decrypt` – Schema A, PBKDF2-SHA256, bkey als Hex-String
- `r33ya/Huawei-KoBackup-Decrypt` – Schema A/B, GCM-Variante, Plaintext-Orakel
- `kellynull2026/huawei-backup-decrypt` – Schema B (KoBackup v13), AES-256-GCM
- `RealityNet/kobackupdec` – AES-256-CTR, `checkMsgV3`-HMAC-Prüfung
- `irsl/Huawei-Hisuite-KobackupCipherTool` – Java-Referenzimplementierung

## Version 1.1.0 - am echten Backup verifiziert

Die Version 1.0.0 blieb bei einem 20-GB-Backup bei 0 % stehen. Ursache
waren vier Engpaesse, die jetzt behoben sind:

1. **Kein Streaming.** Jede Datei wurde vollstaendig in den Speicher
   gelesen (`Files.readAllBytes`). Bei 20 GB bedeutet das ein Vielfaches
   des Speichers. Jetzt wird blockweise (4 MB) gelesen und geschrieben.
   Nachgewiesen: 300 MB Datei mit nur 128 MB Heap entschluesselt, das
   Ergebnis ist bytegenau identisch.

2. **Rohtext-Suche las das ganze Backup.** Der Index-Scanner las jede
   Datei komplett ein. Jetzt wird nur ein Fenster am Dateianfang
   gelesen (2 MB) - der Index liegt am Anfang.

3. **Jede Datei wurde mit jedem Kandidaten entschluesselt.** Bei 30
   Kandidaten und 5.000 Dateien sind das 150.000 volle
   Entschluesselungen. Jetzt traegt jeder Kandidat sein Modul
   (`calllog`, `sms`, ...); das passende Modul wird zuerst probiert.

4. **Kein Fortschritt in der Index-Phase.** Die Anzeige blieb bei 0 %.
   Jetzt wird auch die Index-Phase gemeldet.

### Der entscheidende Bugfix: die GCM-Nonce ist 16 Byte lang

Der bkey-Schritt benutzt als GCM-Nonce `pwkey_salt[16:32]` - **nicht**
`pwkey_salt[16:28]` (12 Byte). Mit 12 Byte schlug der GCM-Tag fehl und
das Passwort wurde faelschlich als falsch gemeldet. Am echten Backup
verifiziert: mit 16 Byte wird der bkey korrekt abgeleitet, mit 12 Byte
nicht.

### Recovery eines abgeschnittenen Index

Faellt die `info.xml` mitten in einem Attribut aus, wird der Wert am
Praefix wiedererkannt. Der vollstaendige Wert wird an anderer Stelle im
Backup gesucht (Rohtext-Rettung). Zusaetzlich werden abgeschnittene
Hex-Werte mit Nullen aufgefuellt - ob der Kandidat taugt, entscheidet
anschliessend die Signaturpruefung.

### Was am echten Backup nachgewiesen wurde

Das Huawei P30 (EML-L29, HiSuite 10) mit Schema A wurde mit dem
Original-Passwort und der beschädigten `info.xml` erfolgreich
entschluesselt:

- `calllog.db` (606.208 Byte) -> gueltige SQLite-Datenbank mit 1.968
  Anrufen - exakt die in der `info.xml` angegebene `recordTotal`.
- Der bkey wird aus `e_perbackupkey` und `pwkey_salt` abgeleitet und
  der GCM-Tag bestaetigt das Passwort.

### Nicht gelöst: Dateien mit `isCopyFileEncrypt=true`

Die Audioaufnahme aus dem Ordner `soundrecorder` ist mit einem eigenen
Verfahren verschluesselt, das weder Schema A noch Schema B entspricht.
Sie bleibt vorerst unentschluesselt. Die uebrigen Module (`sms`,
`calllog`, `Memo`) werden korrekt entschluesselt.

## Version 1.2.0 - Tiefensuche und MP3-Erkennung

### Warum die WhatsApp-Sprachnachricht nicht verschluesselt wurde

Der Dateiname `AUD-20261026-WA0001---a65c1068-....mp3` stammt aus dem
Chatverlauf (WA = WhatsApp). Die Datei liess sich mit **401.506
Kombinationen** aus Schluessel x IV x Offset x Verfahren nicht
entschluesseln.

Der Grund ist nicht das Verfahren, sondern der **Index**: die
`info.xml` ist bei 8192 Byte abgeschnitten, und die Indexzeile des
Moduls fehlt. Ohne `encMsgV3` gibt es keinen Schluessel - unabhaengig
vom Passwort.

**Belegt** ueber das `checkMsgV3`-Orakel (HMAC-SHA256 ueber die
verschluesselte Datei, Key = `PBKDF2(bkey, checkMsgV3[32:64], 5000)`):
`calllog.db` matcht exakt, die MP3 matcht **kein** Modul.

### Die Tiefensuche (Neu)

Der Wert fehlt nicht im Backup - er steht nur nicht an der Stelle, an
der er in der `info.xml` stehen wuerde. Deshalb sucht das Tool jetzt
das **gesamte Backup** nach Index-Bloecken:

- blockweises Lesen (1 MB), Speicherbedarf bleibt konstant
- ueberlappende Fenster (4 KB), damit kein Wert zerschnitten wird
- gesucht werden nur Hex-Runs ab 96 Zeichen (48 Byte) - das sind
  genau die Kandidaten fuer `encMsgV3` und `checkMsgV3`
- grosse Archivteile werden am Anfang **und** am Ende gelesen

Die Suche laeuft **vor** der Kandidatenbildung, damit die gefundenen
Werte als Salts verwendet werden.

### MP3-Erkennung repariert

Bisher erkannte das Tool nur MP3 mit ID3-Tag. Huawei-Sprachnachrichten
haben oft **kein** ID3 - sie beginnen direkt mit dem MPEG-Frame-Sync.

Die Erkennung prueft jetzt eine **Kette von mindestens drei
aufeinanderfolgenden Frames** an den berechneten Positionen. Das ist
notig, weil `0xFFEx` in Zufallsdaten alle ~5.600 Byte auftritt - ein
einzelner Sync waere in einer 4-KB-Probe ein haeufiger Fehlalarm.
Nach der Umstellung: **0 Falsch-Positive** in 260 KB Zufallsdaten.

### Media-Weg (fuer Backup-Varianten mit Multimedia-XML)

Mediendateien werden in manchen Backup-Versionen nicht ueber
`encMsgV3` abgeleitet, sondern ueber eine **eigene IV pro Datei** aus
einer `<Multimedia>`-XML:

```xml
<Multimedia><File><Path>/Sounds/AUD-....mp3</Path><Iv>HEX</Iv></File></Multimedia>
```

- Key: `SHA256(bkey)[0:16]` (AES-128)
- Modus: AES-256-CTR, IV = der `<Iv>`-Wert

Das Tool sucht diese XML jetzt selbst. Liegt sie nicht vor, bleibt die
Datei unentschluesselbar - die IV laesst sich nicht aus der Datei
ableiten.
