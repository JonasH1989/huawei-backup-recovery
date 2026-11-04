# GCM in Java – gemessenes Provider-Verhalten

Ergebnis einer Probe gegen den Java-21-Standard-Provider (`AES/GCM/NoPadding`).
Vor dem Portieren der Salvage-Logik von Python nach Java **immer** gegen
den konkret eingesetzten Provider messen, statt das Verhalten anzunehmen.

## Die Messung

```java
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key,"AES"),
       new GCMParameterSpec(128, iv16));
byte[] ct = c.doFinal(pt);   // ct = plaintext + 16 Byte Tag

Cipher d = Cipher.getInstance("AES/GCM/NoPadding");
d.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key,"AES"),
       new GCMParameterSpec(128, iv16));
byte[] out = d.doFinal(ct);          // enthält Tag -> ergibt Klartext
```

Gemessene Ergebnisse:

| Aufruf | Ergebnis |
|---|---|
| `doFinal(ct)` mit Tag | Klartext, **gleich** dem Original |
| `update(ct)` | liefert **0 Byte** – die Ausgabe kommt erst bei `doFinal()` |
| `update(ct)` mit falschem Schlüssel | **kein** Fehler, nur unbrauchbare Bytes |

## Konsequenz für die Rettung

In Python (PyCryptodome) lässt sich der Klartext auch **ohne** Tag-Verifikation
entschlüsseln – genau das wird für die Rettung gebraucht, weil eine durch den
Backup-Abbruch verkürzte Datei einen kaputten Tag hat, ihr Klartext aber bis zum
Abbruchpunkt korrekt ist.

In Java gilt das so nicht:

- `update()` liefert bei GCM nichts – als „Entschlüsselung ohne Tag" unbrauchbar.
- `doFinal()` **ohne** den Tag wirft `AEADBadTagException`; der Klartext geht dabei
  verloren, auch wenn er bis zum Abbruchpunkt gültig ist.
- Ein falscher Schlüssel erzeugt keinen Fehler, sondern plausibel aussehende
  Müllbytes – die Signaturprüfung bleibt also das eigentliche Auswahlkriterium.

## Die Sackgasse: GCM selbst nachbauen

Der naheliegende Weg ist, GCM als CTR + GHASH nachzubauen, weil dann der
Klartext auch ohne Tag gewinnbar ist. **Das wurde versucht und ist
gescheitert** – die Implementierung muss hier nicht weiterverfolgt werden.

### Warum es nicht funktioniert

GCM ist AES-CTR mit einem J0-Konstrukt (NIST SP 800-38D, Gleichung 7):

```
J0 = GHASH_H(IV || 0^(s+64) || [len(IV)]_64)
```

mit `s = 128*ceil(len(IV)/128) - len(IV)` – die Längenangaben in **Bit**.

Beide naheliegenden Varianten führen zum selben falschen J0:

| Variante | J0 (gemessen) |
|---|---|
| `s` in Bit berechnet | `7bfce05f4ab5a083ec1c8dc4b7cbdbc3` |
| `s` als Byte-Padding | `7bfce05f4ab5a083ec1c8dc4b7cbdbc3` |

Beide erzeugen einen **falschen Keystream** – der CTR-Vergleich mit dem
Original schlägt fehl. Der Grund: der Byte-Nullblock-Anhang muss
`s/8 + 8` Byte groß sein, und die GHASH-Multiplikation in GF(2^128) muss
exakt dem Standard entsprechen. Das sind zwei Fehlerquellen in
Handarbeit – ein Grund, den Provider zu nutzen.

## Die Lösung: Keystream über den Provider

Der Provider kann den Keystream **selbst** liefern, ohne dass das J0
nachgebaut werden muss:

```java
// Provider verschlüsselt einen Nullblock:
// XOR mit Null ist die Identität -> das Ergebnis IST der Keystream.
Cipher stream = Cipher.getInstance("AES/GCM/NoPadding");
stream.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
            new GCMParameterSpec(128, iv));
byte[] keystream = stream.doFinal(new byte[ct.length]);

byte[] plaintext = new byte[ct.length];
for (int i = 0; i < ct.length; i++) {
    plaintext[i] = (byte) (ct[i] ^ keystream[i]);
}
```

Gemessen verifiziert für **beide** IV-Längen:

```
ivLen=12  keystream-Trick korrekt: true
ivLen=16  keystream-Trick korrekt: true
```

Damit gilt in Java dasselbe wie in Python:

- Der Klartext ist **ohne** Tag-Verifikation gewinnbar → verkürzte Dateien
  bleiben rettbar.
- Der Tag wird **separiat** geprüft (`cipher.doFinal(data)` mit Tag):
  - passt → `[authentifiziert]`
  - passt nicht → `[unvollständig]`, Klartext wird trotzdem geschrieben.

Diese Implementierung steckt in `core/Crypto.java`, Methode
`decryptGcmPlaintext`.

## Empfohlene Reihenfolge beim Portieren

1. Provider-Verhalten messen (`update()` vs. `doFinal()`, Tag-Behandlung).
2. Den kleinstmöglichen Roundtrip schreiben: **ein** Block, ein Schlüssel,
   ein IV – Ergebnis byteweise vergleichen.
3. Erst dann die Salvage-Logik portieren.
4. Den vollständigen Roundtrip portieren, nicht ersetzen – der Test muss
   bytegenau bleiben.

## Weitere Fallstricke beim Portieren

| Thema | Python | Java | Fußnote |
|---|---|---|---|
| PBKDF2 | `hashlib.pbkdf2_hmac` | `SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")` | Java nimmt `char[]`; ein Password mit Nicht-ASCII wird als UTF-8 dekodiert – entspricht der Python-Vorlage |
| CTR-Counter | `Crypto.Util.Counter` | `AES/CTR/NoPadding` + `IvParameterSpec` | Big-Endian-Zähler in beiden |
| bkey | Hex-String als UTF-8 | dito | **nicht** beliebige Bytes – sonst wird der abgeleitete Dateischlüssel falsch |
| Salt-Auffüllung | `h[:96].ljust(96, "0")` | dito | kürzere Hex-Werte müssen auf 96 Zeichen aufgefüllt werden |
| Dateiendung | `rel.stem + ext` | dito | **nicht** `rel.name + ext` – sonst entsteht `IMG_0001.jpg.jpg` |

## Ergebnis der Portierung

```
schema_a             5 identisch, 0 abweichend
schema_a_corrupt     5 identisch, 0 abweichend
schema_b             5 identisch, 0 abweichend
schema_b_corrupt     5 identisch, 0 abweichend
```

Bytegenau in **beiden** Sprachen. Der Test steht in
`src/test/java/de/jonas/huaweibackup/RoundtripTest.java`.
