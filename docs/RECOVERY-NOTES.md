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
