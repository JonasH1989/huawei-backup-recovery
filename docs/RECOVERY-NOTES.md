# Recovery-Notizen

## 2026-11-04, 23:21 — calllog.db: Entschlüsselung verifiziert (Weg rekonstruiert)

**Wichtig:** Die Aussage "1968 Anrufe, gueltige SQLite-DB" stammt aus einer frueheren
Session. Die entschluesselte Datei lag danach NICHT mehr auf der Platte - unter
`/tmp/hw_real/calllog.db` lag die **verschluesselte** Eingabe (Header `b152249d...`,
kein SQLite-Magic). Die Entschluesselung wurde am 2026-11-04 23:21 neu durchgefuehrt
und verifiziert.

**Der Weg (Schema A, am echten Backup verifiziert):**

```
pwkey_salt  -> key_salt = pwkey_salt[:16]
             -> nonce    = pwkey_salt[16:32]      <-- 16 Byte, nicht 12!
K        = PBKDF2-HMAC-SHA256(passwort, key_salt, 10000, 32)
bkey     = AES-256-GCM.decrypt(K, nonce, e_perbackupkey[:32])  # Tag = e_perbackupkey[32:48]
file_key = PBKDF2-HMAC-SHA256(bkey.encode(utf-8), encMsgV3[:32], 5000, 32)
iv       = encMsgV3[32:48]
Klartext = AES-256-CTR(file_key, iv, chiffrat)
```

**Nachweis:**
- GCM-Tag der bkey-Ableitung gueltig -> Passwort stimmt
- Klartext-Header exakt `53514c69746520666f726d6174203300` = "SQLite format 3"
- `PRAGMA integrity_check` -> **ok**
- Tabelle `calls_tb`: **1968 Zeilen** = exakt `recordTotal` aus der `info.xml`
- 30 Spalten (number, date, duration, countryiso, geocoded_location, transcription, ...)
- Datensaetze plausibel (z.B. `+49 160 92535537`, `DE`, `Deutschland`)

**Die `info.xml` reichte dafuer - die Tiefensuche war NICHT noetig.** Der Modulblock
`calllog` liegt innerhalb der ersten 8192 Byte. Abgeschnitten ist der Block fuer
`soundrecorder`/WhatsApp - deshalb bleibt `audio.mp3` weiterhin unentschluesselt.

**Gefundener Bug in der Python-Variante** (`huawei_backup_recover.py`, `derive_bkey`):
sie nutzt eine **12-Byte**-GCM-Nonce (`pwkey_salt[16:28]`), die Java-Variante nutzt
**16 Byte** (`pwkey_salt[16:32]`). Mit der 12-Byte-Nonce schlaegt der GCM-Tag fehl ->
`ValueError: MAC check failed` -> das Passwort wird faelschlich als falsch gemeldet.
Die Java-Variante ist korrekt, die Python-Variante nicht.

**checkMsgV3-Orakel:** in dieser Reproduktion kein Treffer weder mit
`HMAC(file_key, chiffrat)` noch mit `HMAC(file_key, klartext)`. Die fruehere Session
berichtete einen Treffer fuer calllog.db - die genaue Formel ist damit **nicht
belegt**. Der Erfolg des calllog-Wegs haengt am gueltigen GCM-Tag der bkey-Ableitung
und am SQLite-Header, nicht am checkMsgV3.

**Gesicherte Kopie:** `~/.openclaw/secure/huawei_recovered/calllog.db` (chmod 600)
SHA-256 `2e858d06bc582f8d12bd774f57a1701a3bd0637c0da1d938fcf9cce84e2ca1a2`

## 2026-11-05, 00:05 — Warum der Recovery-Lauf 0 Dateien fand (v1.3.0)

**Anlass:** Jonas: "das Recovery Tool lief durch und konnte nichts entschluesseln."

Das war kein Krypto-Problem, sondern drei Fehler in der Erkennung. Der
calllog-Weg funktioniert nachweislich - das Tool kam nur nicht daran, ihn
zu finden.

### Ursache 1 - Index nur nach Dateiname erkannt (Hauptursache)

Die Datei aus dem Chat-Transfer hies `input-info---<uuid>.xml` statt
`info.xml`. Der Index wurde deshalb nicht als Index erkannt:

    Index-Datei: input-info---9571937b-....xml
    Module strukturiert: 0 | e_perbackupkey: NEIN | pwkey_salt: NEIN
    entschluesselt: 0

Ohne `e_perbackupkey` und `pwkey_salt` ist gar kein Schluessel ableitbar.

**Fix:** Index-Dateien werden zusaetzlich am INHALT erkannt (`e_perbackupkey`,
`pwkey_salt`, `BackupFilesTypeInfo`, `BackupFileModuleInfo`), nicht nur am
Dateinamen. `IndexScanner.looksLikeIndexContent()`.

### Ursache 2 - GCM-Nonce des bkey-Schritts

Die Python-Variante nutzte 12 Byte (`pwkey_salt[16:28]`), die Java-Variante
korrekt 16 Byte (`pwkey_salt[16:32]`). Mit 12 Byte schlaegt der GCM-Tag fehl
und das Passwort wird faelschlich als falsch gemeldet.

**Fix:** `BKEY_NONCE_LEN = 16` in `huawei_backup_recover.py`.

### Ursache 3 - strenger XML-Parser in der Python-Variante

Bei abgeschnittenem XML lieferte `ET.fromstring` nichts mehr, obwohl die
vollen Zeilen davor lesbar sind.

**Fix:** lockeres Zeilen-Parsing wie in Java - pro `<row table="...">...</row>`
ein Block, unabhaengig von der Gesamtdokumentstruktur.

### Zusaetzlich: OGG/Opus-Erkennung

`OggS` (0x4f 0x67 0x67 0x53) wird jetzt als `.ogg` erkannt. WhatsApp-
Sprachnachrichten speichert das Geraet als `.ogg`; ohne diese Signatur waere
die entschluesselte Datei als unbekannter Typ verworfen worden.

### Nachweis am echten Backup (Original-Dateinamen)

    Index-Datei: input-info---9571937b-....xml (8192 Byte)
    Module strukturiert: 4 | Hex-Bloecke gerettet: 14
      Modul sms             Salt: c682b2df5fadc1d9dca5...
      Modul calllog         Salt: 2d0cb5b7f5d36478fbc0...
      Modul Memo            Salt: 5c85603e2e89eca915cb...
      Modul soundrecorder   Salt: 21f2258045b00f24f055...
    e_perbackupkey: ja | pwkey_salt: ja
    bkey erfolgreich abgeleitet (GCM-Tag gueltig)
    GERETTET: input-calllog---....db -> .db (Schema A)

    PRAGMA integrity_check = ok
    calls_tb: 1968 Zeilen  (= recordTotal aus der info.xml)
    SHA-256 2e858d06bc582f8d12bd774f57a1701a3bd0637c0da1d938fcf9cce84e2ca1a2

Regression: Roundtrip 4 Szenarien x 6 Dateien, 0 Abweichungen.

### Was weiterhin nicht entschluesselt wird

`input-AUD-20261026-WA0001---<uuid>.mp3` bleibt unentschluesselt. Der Modulblock
`soundrecorder` ist zwar VOLLSTAENDIG in der `info.xml` (inkl. `encMsgV3`,
`copyFilePath=/Sounds`, `isCopyFileEncrypt=true`), aber keine gepruefte
Schluessel-/IV-Kombination liefert eine erkennbare Dateisignatur.

`isCopyFileEncrypt=true` heisst: das ist ein **Copy-File**, kein normales
Datenbankmodul. Copy-Dateien bekommen ihre IV nicht aus `encMsgV3`, sondern
aus einer eigenen Multimedia-XML mit einem `<Iv>`-Eintrag pro Datei. Eine
solche XML liegt in den drei Dateien nicht vor - fuer `soundrecorder` ist sie
im Backup nicht vorhanden.

Naechster Schritt: das vollstaendige 20-GB-Backup, damit die Tiefensuche die
fehlende Multimedia-XML bzw. den Copy-File-IV findet.
