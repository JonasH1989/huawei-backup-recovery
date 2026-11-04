# Huawei/Honor KoBackup – Recovery für abgebrochene Backups

Werkzeug, um Bilder/Videos aus einem **unvollständigen** Huawei-Backup
zurückzugewinnen, bei dem die Index-Datei (`info.xml`) durch einen Abbruch
mitten im Backup beschädigt ist.

## Das Problem

Beim Backup auf dem Gerät (HiSuite / „Sichern auf USB-Stick“) bricht der
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

### Die drei Rettungswege des Tools

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

## Benutzung

```bash
pip install pycryptodome

# 1) Bestandsaufnahme – read-only, verändert nichts
python3 huawei_backup_recover.py --inspect /pfad/zum/backup

# 2) Entschüsselung
export HUAWEI_BACKUP_PASSWORD='dein-passwort'
python3 huawei_backup_recover.py --recover /pfad/zum/backup --out /pfad/zum/ausgabe
```

Ohne `HUAWEI_BACKUP_PASSWORD` wird das Passwort interaktiv abgefragt
(dann landet es nicht in der Shell-History).

### Ausgabe

```
  [1/5] IMG_0002.jpg   -> .jpg (B) [authentifiziert]
  [2/5] IMG_0001.jpg   -> .jpg (B) [authentifiziert]
  [3/5] VID_0001.mp4   -> .mp4 (B) [authentifiziert]

  entschluesselt: 5 | nicht entschluesselbar: 0
```

Dateien landen unter `--out` mit erkanntem Dateityp. Bei Schema B wird
zusätzlich der GCM-Tag geprüft:

- `[authentifiziert]` – Schlüssel und Datei sind nachweislich korrekt
- `[Tag passt nicht …]` – der Klartext ist gültig, aber die Datei wurde
  vermutlich durch den Abbruch verkürzt. **Die Datei wird trotzdem
  gerettet**, weil der Klartext bis zum Abbruchpunkt korrekt ist.

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

## Getestet

`make_test_backup.py` erzeugt synthetische Backups beider Schemata, je mit
intaktem und mit **mitten im Attribut abgeschnittenem** Index. Der
Roundtrip-Vergleich ist bytegenau:

```
schema_a             5 identisch, 0 abweichend
schema_a_corrupt     5 identisch, 0 abweichend
schema_b             5 identisch, 0 abweichend
schema_b_corrupt     5 identisch, 0 abweichend
```

## Quellen der reverse-engineerten Algorithmen

- `uncognic/kobackup-decrypt` – Schema A, PBKDF2-SHA256, bkey als Hex-String
- `r33ya/Huawei-KoBackup-Decrypt` – Schema A/B, GCM-Variante, Plaintext-Orakel
- `kellynull2026/huawei-backup-decrypt` – Schema B (KoBackup v13), AES-256-GCM
- `RealityNet/kobackupdec` – AES-256-CTR, `checkMsgV3`-HMAC-Prüfung
- `irsl/Huawei-Hisuite-KobackupCipherTool` – Java-Referenzimplementierung
