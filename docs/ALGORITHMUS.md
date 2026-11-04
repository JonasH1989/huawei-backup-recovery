# Die reverse-engineerten Verfahren

Diese Datei hält die fachlichen Erkenntnisse fest, damit sie nach einem
Kontext-Reset nicht verloren gehen. Sie ist die Referenz für beide
Implementierungen (Python und Java).

## Übersicht

Huawei/Honor KoBackup verschlüsselt **dateiweise**, nicht containerweise.
Jede Datei bekommt einen eigenen Schlüssel, abgeleitet aus einem
modul-spezifischen Salz (`encMsgV3`).

Es gibt zwei relevante Schemata:

| | Schema A | Schema B |
|---|---|---|
| **Version** | KoBackup v10…v12 | KoBackup v13 / HiSuite 11+ |
| **Verfahren** | AES-256-CTR | AES-256-GCM |
| **Braucht `e_perbackupkey`** | ja | **nein** |
| **Braucht `pwkey_salt`** | ja | nein |
| **Braucht `encMsgV3`** | ja | ja |

**Schema B ist die beste Hoffnung bei beschädigtem Index**, weil der
Schlüssel direkt aus Passwort und Salz folgt. Genügt ein einziger
geborgener Salz-Block eines Moduls, ist das Backup zu entschlüsseln.

---

## Schema A – KoBackup v10…v12 (AES-256-CTR)

```
1.  K        = PBKDF2-HMAC-SHA256(password, pwkey_salt[:16], 10000, 32)
2.  bkey     = AES-256-GCM(K, nonce=pwkey_salt[16:28]).decrypt(e_perbackupkey[:32])
               e_perbackupkey[32:48] ist der GCM-Tag → dient als Passwort-Prüfung
3.  je Modul:  seed     = encMsgV3[:32]
                iv       = encMsgV3[32:48]
                file_key = PBKDF2-HMAC-SHA256(bkey.encode('utf-8'), seed, 5000, 32)
4.  Datei    = AES-256-CTR(file_key, iv, big-endian counter)
```

Der `bkey` ist ein **32-stelliger Hex-String als UTF-8-Bytes** – nicht
beliebige Bytes. Das ist der subtile Punkt, an dem eine naive
Implementierung scheitert.

**Wichtig:** Jede Datei wird **unabhängig** verschlüsselt, der Counter
startet pro Datei neu. Ein durchlaufender Counter wäre kein realistisches
HiSuite-Backup.

## Schema B – KoBackup v13 / HiSuite 11+ (AES-256-GCM)

```
1.  aes_key = PBKDF2-HMAC-SHA256(password, encMsgV3[:32], 5000, 32)
2.  nonce   = encMsgV3[32:48]
3.  Datei   = AES-256-GCM(aes_key, nonce)  →  ciphertext || 16-Byte-Tag
```

### Der GCM-Tag gehört nicht zum Klartext

Der 16-Byte-Tag am Dateiende ist **kein Chiffrat**. Wird er
mitentschlüsselt, ist die Ausgabe 16 Byte zu lang – ein JPEG bekäme 16
Byte Müll angehängt und wäre **kaputt**.

Deshalb:

- Der Tag wird vor dem Entschlüsseln **abgetrennt**.
- Die Signaturprüfung liest nur den Dateianfang (dort ist kein Tag).
- Der Tag wird **separiat geprüft**:
  - passt → Datei ist authentifiziert
  - passt nicht → die Datei wurde vermutlich durch den Backup-Abbruch
    verkürzt. **Der Klartext ist trotzdem gültig und wird gerettet.**

Diese Trennung ist der Grund, warum durch den Abbruch verkürzte Dateien
überhaupt rettbar sind.

---

## Die drei Rettungswege

### 1. Strukturierte XML-Auswertung

`info.xml`, `cinfoset.dat`, `backupinfo.ini` werden geparst. Index-Dateien
dürfen **UTF-8 oder UTF-16** (mit BOM) sein – beides wird versucht.

Gesucht werden:

- Tabelle `BackupFilesTypeInfo` → `e_perbackupkey`, `pwkey_salt`
- Tabellen `BackupFileModuleInfo`, `BackupFileModuleInfo_Media`,
  `BackupFileModuleInfo_SystemData` → `name`, `encMsgV3`

Das XML darf dabei **kaputt** sein. Beide Implementierungen nutzen
deshalb einen lockeren Parser, der die einzelnen `<row table="…">`-Blöcke
auch aus zerstörtem XML isoliert.

### 2. Rohtext-Rettung

Alle Hex-Blöcke werden zusätzlich über den **gesamten** Backup-Bestand
gesucht, nicht nur in den Index-Dateien.

Begründung: Ein Backup bricht an **genau einer** Stelle ab. Die Kopie des
Index an anderer Stelle kann intakt sein – z.B. `check/info.xml` ist
abgeschnitten, aber `cinfoset.dat` enthält denselben Index vollständig.

Zusätzlich werden **abgeschnittene** Hex-Werte rekonstruiert: Der
fehlende Teil wird mit Nullen aufgefüllt, die GCM-Prüfung entscheidet
später, ob der Kandidat taugt.

**UTF-16-Falle:** Bei UTF-16-kodierten Index-Dateien sind die Hex-Zeichen
von Nullbytes durchsetzt. Ein Regex auf den Rohbytes greift nicht. Die
Implementierungen dekodieren deshalb zusätzlich nach UTF-16LE/BE und
filtern Nicht-ASCII-Zeichen heraus.

### 3. Signatur-Verifikation

Jede Datei wird mit **jedem** plausiblen Schlüssel entschlüsselt und an
hand der Dateisignatur geprüft:

| Signatur | Typ |
|---|---|
| `FF D8 FF` | `.jpg` |
| `89 50 4E 47 0D 0A 1A 0A` | `.png` |
| `SQLite format 3\0` | `.db` |
| `RIFF` | `.riff` |
| `1A 45 DF A3` | `.mkv` |
| `fLaC` | `.flac` |
| `ID3` | `.mp3` |
| `<?xml` | `.xml` |
| `PK 03 04` | `.zip` |
| `ftyp` bei Byte 4 + Brand | `.mp4` |

**Das ist der entscheidende Punkt:** Ordnerstruktur und
Index-Vollständigkeit sind nicht nötig. Was die Signaturprüfung besteht,
ist gültiger Klartext. Ein falscher Schlüssel erzeugt keine plausible
Signatur – Zufallstreffer sind bei 8 Byte Magic praktisch ausgeschlossen.

---

## Kandidatenbildung

```
1. Schema B direkt aus dem Passwort
   → braucht nur einen 48-Byte-Salt (encMsgV3)
   → 32 Byte Salt + 16 Byte Nonce

2. Schema A über den bkey
   → braucht e_perbackupkey + pwkey_salt (beide aus dem Index)
   → bkey-Ableitung prüft den GCM-Tag: passt er nicht, ist das
     Passwort falsch
```

Die Salts stammen aus den strukturiert gelesenen Modulen **und** aus dem
Blob-Pool der Rohtext-Rettung. Kürzere Hex-Werte werden auf 96 Zeichen
aufgefüllt (wie in der Python-Vorlage).

---

## Grenzen

Ohne geborgenen Salt ist nichts zu holen – Verschlüsselung ist nicht
umkehrbar. Das Tool sagt das explizit, statt still zu scheitern.

Ein falsches Passwort scheitert an der GCM-Authentifizierung (Schema B)
bzw. am bkey-Tag (Schema A) – **nicht** erst an einem Dateiformat-Fehler
später. Das ist der Unterschied zwischen „falsches Passwort" und
„falsches Dateiformat" und macht die Fehlermeldung belastbar.

## Quellen

- `uncognic/kobackup-decrypt` – Schema A, PBKDF2-SHA256, bkey als Hex-String
- `r33ya/Huawei-KoBackup-Decrypt` – Schema A/B, GCM-Variante, Plaintext-Orakel
- `kellynull2026/huawei-backup-decrypt` – Schema B (KoBackup v13), AES-256-GCM
- `RealityNet/kobackupdec` – AES-256-CTR, `checkMsgV3`-HMAC-Prüfung
- `irsl/Huawei-Hisuite-KobackupCipherTool` – Java-Referenzimplementierung
