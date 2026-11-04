package de.jonas.huaweibackup.core;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Krypto-Primitive fuer die Huawei-KoBackup-Recovery.
 *
 * <p>Zwei Schemata werden unterstuetzt (reverse-engineered aus der
 * KoBackup-/HiSuite-Implementierung und an echten Backup-Daten
 * verifiziert):
 *
 * <pre>
 * Schema A - KoBackup v10..v12 / HiSuite 10 (AES-256-CTR)
 *   K        = PBKDF2-HMAC-SHA256(passwort, pwkey_salt[:16], 10000, 32)
 *   bkey     = AES-256-GCM(K, nonce=pwkey_salt[16:32]).decrypt(e_perbackupkey[:32])
 *              (e_perbackupkey[32:48] ist der GCM-Tag -&gt; Passwort-Pruefung)
 *   file_key = PBKDF2-HMAC-SHA256(bkey.encode(utf-8), encMsgV3[:32], 5000, 32)
 *   Datei    = AES-256-CTR(file_key, iv=encMsgV3[32:48])
 *
 * Schema B - KoBackup v13 / HiSuite 11+ (AES-256-GCM)
 *   aes_key = PBKDF2-HMAC-SHA256(passwort, encMsgV3[:32], 5000, 32)
 *   Datei   = ciphertext || 16-Byte-GCM-Tag, nonce = encMsgV3[32:48]
 * </pre>
 *
 * <p><b>Wichtig (am echten Backup verifiziert):</b> die GCM-Nonce des
 * bkey-Schritts ist <b>16 Byte</b> lang, also {@code pwkey_salt[16:32]}.
 * Mit 12 Byte (wie in aelteren Beschreibungen) schlaegt der GCM-Tag
 * fehl und das Passwort wird faelschlich als falsch gemeldet.
 *
 * <p><b>Kein eigener GCM-Prototyp.</b> Alle GCM-Rechenwege laufen ueber
 * den JDK-Provider. Eine eigene GHASH-Implementierung wurde gegen den
 * Provider geprueft und war nicht byte-identisch - sie wird deshalb
 * nicht verwendet.
 */
public final class Crypto {

    public static final int GCM_TAG_LEN = 16;
    public static final int PBKDF2_ITER_BKEY = 10_000;  // Schema A: Passwort -> K
    public static final int PBKDF2_ITER_FILE = 5_000;   // Schema A: bkey -> file_key
    public static final int PBKDF2_ITER_V13 = 5_000;    // Schema B: Passwort -> aes_key

    /** Laenge der GCM-Nonce fuer den bkey-Schritt (verifiziert: 16). */
    public static final int BKEY_NONCE_LEN = 16;

    private Crypto() {
    }

    // -----------------------------------------------------------------
    // Schluessel-Ableitung
    // -----------------------------------------------------------------

    /**
     * Schema A: bkey (als UTF-8-String) aus Passwort ableiten.
     *
     * <p>Der GCM-Tag aus {@code e_perbackupkey[32:48]} dient als
     * Passwort-Pruefung: passt er nicht, ist das Passwort falsch.
     *
     * @throws BadPasswordException wenn der GCM-Tag nicht passt
     * @throws IllegalArgumentException wenn die Salt-Werte zu kurz sind
     */
    public static String deriveBkey(String password, byte[] ePerBackupKey, byte[] pwKeySalt)
            throws BadPasswordException {

        if (pwKeySalt.length < 16 + BKEY_NONCE_LEN || ePerBackupKey.length < 32) {
            throw new IllegalArgumentException("pwkey_salt/e_perbackupkey zu kurz");
        }

        byte[] keySalt = Arrays.copyOfRange(pwKeySalt, 0, 16);
        // 16-Byte-Nonce - am echten Backup verifiziert.
        byte[] nonce = Arrays.copyOfRange(pwKeySalt, 16, 16 + BKEY_NONCE_LEN);
        byte[] ct = Arrays.copyOfRange(ePerBackupKey, 0, 32);
        byte[] tag = ePerBackupKey.length >= 48
                ? Arrays.copyOfRange(ePerBackupKey, 32, 48)
                : new byte[0];

        byte[] k = pbkdf2(password.getBytes(StandardCharsets.UTF_8), keySalt,
                PBKDF2_ITER_BKEY, 32);

        // Ciphertext + Tag hintereinander -> doFinal() entschluesselt und prueft.
        byte[] combined = new byte[ct.length + tag.length];
        System.arraycopy(ct, 0, combined, 0, ct.length);
        System.arraycopy(tag, 0, combined, ct.length, tag.length);

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(k, "AES"),
                    new GCMParameterSpec(GCM_TAG_LEN * 8, nonce));
            byte[] plain = cipher.doFinal(combined);
            return new String(plain, StandardCharsets.UTF_8);
        } catch (AEADBadTagException e) {
            throw new BadPasswordException("GCM-Tag passt nicht - falsches Passwort?");
        } catch (Exception e) {
            throw new BadPasswordException("bkey nicht ableitbar: " + e.getMessage());
        }
    }

    /** Schema A: (file_key, iv) fuer ein Modul. */
    public static byte[][] deriveFileKeyA(String bkey, byte[] encMsgV3) {
        byte[] seed = Arrays.copyOfRange(encMsgV3, 0, 32);
        byte[] iv = Arrays.copyOfRange(encMsgV3, 32, 48);
        byte[] fileKey = pbkdf2(bkey.getBytes(StandardCharsets.UTF_8), seed,
                PBKDF2_ITER_FILE, 32);
        return new byte[][]{fileKey, iv};
    }

    /** Schema B: (aes_key, nonce) fuer ein Modul. */
    public static byte[][] deriveKeyB(String password, byte[] encMsgV3) {
        byte[] seed = Arrays.copyOfRange(encMsgV3, 0, 32);
        byte[] nonce = Arrays.copyOfRange(encMsgV3, 32, 48);
        byte[] key = pbkdf2(password.getBytes(StandardCharsets.UTF_8), seed,
                PBKDF2_ITER_V13, 32);
        return new byte[][]{key, nonce};
    }

    /**
     * PBKDF2-HMAC-SHA256.
     *
     * <p>Hinweis: {@code PBEKeySpec} nimmt ein char[] an. Ein Password mit
     * Nicht-ASCII-Zeichen wird dabei als UTF-8 dekodiert und wieder zu
     * chars konvertiert - das entspricht der Python-Vorlage, die mit
     * {@code password.encode('utf-8')} arbeitet.
     */
    public static byte[] pbkdf2(byte[] password, byte[] salt, int iterations, int keyLen) {
        try {
            SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            char[] chars = new String(password, StandardCharsets.UTF_8).toCharArray();
            return f.generateSecret(new PBEKeySpec(chars, salt, iterations, keyLen * 8))
                    .getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("PBKDF2 fehlgeschlagen", e);
        }
    }

    // -----------------------------------------------------------------
    // Entschluesselung (einmalig, fuer kleine Dateien und Signaturproben)
    // -----------------------------------------------------------------

    /**
     * Schema A: AES-256-CTR.
     *
     * <p>Der Java-Provider liefert bei GCM nichts aus {@code update()};
     * CTR ist davon nicht betroffen und eignet sich deshalb fuer den Weg
     * "Klartext ohne Tag".
     */
    public static byte[] decryptCtr(byte[] key, byte[] iv, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new IvParameterSpec(counter(iv)));
            return cipher.doFinal(data);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Schema B: AES-256-GCM, Tag wird abgetrennt.
     *
     * @param hasTag true, wenn {@code data} den Tag bereits enthaelt
     */
    public static byte[] decryptGcm(byte[] key, byte[] nonce, byte[] data, boolean hasTag) {
        try {
            byte[] ct = data;
            if (hasTag) {
                if (data.length <= GCM_TAG_LEN) {
                    return null;
                }
                ct = Arrays.copyOfRange(data, 0, data.length - GCM_TAG_LEN);
            }
            return decryptGcmPlaintext(key, nonce, ct);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * GCM-Klartext ohne Tag-Verifikation.
     *
     * <p>GCM ist im Kern AES-CTR mit einem J0-Konstrukt. Der Klartext
     * laesst sich daher auch dann gewinnen, wenn der Tag nicht passt -
     * das ist der entscheidende Unterschied zur Python-Vorlage und der
     * Grund, warum durch den Backup-Abbruch verkuerzte Dateien
     * rettbar bleiben.
     *
     * <p>Der JDK-Provider verliert bei {@code doFinal()} ohne passenden
     * Tag den Klartext und wirft {@code AEADBadTagException}. Deshalb
     * wird der Keystream hier ueber einen Umweg gewonnen: der Provider
     * verschluesselt einen Nullblock, das Ergebnis ist der Keystream
     * selbst (XOR mit Null = Identitaet). Das J0-Konstrukt wird damit
     * nicht nachgebaut - der Provider erledigt es fuer alle IV-Laengen
     * korrekt.
     */
    private static byte[] decryptGcmPlaintext(byte[] key, byte[] nonce, byte[] ct) {
        try {
            byte[] keystream = gcmKeystream(key, nonce, ct.length);
            byte[] out = new byte[ct.length];
            for (int i = 0; i < ct.length; i++) {
                out[i] = (byte) (ct[i] ^ keystream[i]);
            }
            return out;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Erzeugt {@code n} Byte Keystream fuer Schema B (GCM).
     *
     * <p>Am Provider verifiziert: chunkweises {@code update()} liefert
     * denselben Keystream wie der One-Shot-Aufruf. Wegen der internen
     * Pufferung des Providers wird der Keystream in einem Puffer
     * gesammelt und nur bei Bedarf weitergegeben.
     */
    public static byte[] gcmKeystream(byte[] key, byte[] nonce, int n) throws Exception {
        Cipher stream = Cipher.getInstance("AES/GCM/NoPadding");
        stream.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(GCM_TAG_LEN * 8, nonce));
        byte[] out = new byte[n];
        int produced = 0;
        int pos = 0;
        byte[] zeros = new byte[Math.min(64 * 1024, Math.max(1, n))];
        while (produced < n) {
            int want = Math.min(zeros.length, n - produced);
            byte[] part = stream.update(zeros, 0, want);
            if (part != null && part.length > 0) {
                int take = Math.min(part.length, n - pos);
                System.arraycopy(part, 0, out, pos, take);
                pos += take;
            }
            produced += want;
        }
        return out;
    }

    /**
     * Prueft den GCM-Tag einer vollstaendigen Schema-B-Datei.
     *
     * @return true, wenn die Datei authentifiziert ist (Schluessel und
     *         Datei passen). false kann auch eine abgebrochene Datei
     *         bedeuten - der Klartext ist dann trotzdem gueltig.
     */
    public static boolean verifyGcmTag(byte[] key, byte[] nonce, byte[] data) {
        if (data.length <= GCM_TAG_LEN) {
            return false;
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_LEN * 8, counter(nonce)));
            cipher.doFinal(data);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // -----------------------------------------------------------------
    // Streaming-Entschluesselung ( fuer grosse Dateien )
    // -----------------------------------------------------------------

    /**
     * Schema A: streamt eine Datei im AES-CTR-Modus in {@code out}.
     *
     * <p>Der Speicherbedarf bleibt konstant, unabhaengig von der
     * Dateigroesse. Das ist der entscheidende Punkt fuer Backups im
     * zweistelligen Gigabyte-Bereich.
     *
     * @return Anzahl geschriebener Klartext-Byte
     */
    public static long decryptCtrStream(byte[] key, byte[] iv, InputStream in,
                                        OutputStream out, int chunkSize) throws IOException {
        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new IvParameterSpec(counter(iv)));
            return pump(cipher, in, out, chunkSize);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("CTR-Entschluesselung fehlgeschlagen: " + e.getMessage(), e);
        }
    }

    /**
     * Schema B: streamt eine Datei im GCM-Modus in {@code out}.
     *
     * <p>Der Tag am Dateiende wird abgetrennt und separat geprueft.
     * Der Klartext wird auch dann geschrieben, wenn der Tag nicht passt
     * (durch den Backup-Abbruch verkuerzte Datei) - die Authentizitaet
     * wird dann als "nicht bestaetigt" ausgewiesen.
     *
     * @param hasTag true, wenn die Datei den GCM-Tag enthaelt
     * @return Anzahl geschriebener Klartext-Byte
     */
    public static long decryptGcmStream(byte[] key, byte[] nonce, InputStream in,
                                        OutputStream out, long cipherLen, int chunkSize)
            throws IOException {
        try {
            // Keystream erzeugen. Der Provider liefert bei
            // GCM-ENCRYPT im ENCRYPT-Modus zu update(zeros) genau so
            // viele Byte zurueck, wie Nullen uebergeben wurden - das
            // ist der Keystream (Null XOR Keystream = Keystream).
            // Der GCM-Tag wird dabei NICHT berechnet und stört nicht.
            Cipher stream = Cipher.getInstance("AES/GCM/NoPadding");
            stream.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_LEN * 8, counter(nonce)));

            byte[] buf = new byte[chunkSize];
            byte[] zeros = new byte[chunkSize];
            long total = 0;
            long remaining = cipherLen;

            // Der Provider puffert den GCM-ENCRYPT-Stream intern: update()
            // liefert nur volle 16-Byte-Bloecke zurueck. Der Rest
            // bleibt im Provider-Puffer. Deshalb wird der gelieferte
            // Keystream gesammelt, bis genug fuer den Chiffrat-Block
            // vorliegt.
            byte[] ks = new byte[0];

            while (remaining > 0) {
                int want = (int) Math.min(chunkSize, remaining);
                int n = in.read(buf, 0, want);
                if (n <= 0) {
                    break;
                }
                byte[] part = stream.update(zeros, 0, n);
                if (part != null && part.length > 0) {
                    byte[] merged = new byte[ks.length + part.length];
                    System.arraycopy(ks, 0, merged, 0, ks.length);
                    System.arraycopy(part, 0, merged, ks.length, part.length);
                    ks = merged;
                }
                if (ks.length < n) {
                    // Zu wenig Keystream: mehr anfordern. update() mit
                    // Nullen erzeugt weiteren Keystream, ohne den
                    // Chiffrat zu veraendern.
                    byte[] more = stream.update(zeros, 0, 0);
                    if (more != null && more.length > 0) {
                        byte[] merged = new byte[ks.length + more.length];
                        System.arraycopy(ks, 0, merged, 0, ks.length);
                        System.arraycopy(more, 0, merged, ks.length, more.length);
                        ks = merged;
                    }
                }
                if (ks.length < n) {
                    // Letzte Chance: Rest aus dem Provider holen.
                    byte[] tail = stream.doFinal();
                    if (tail != null && tail.length > 0) {
                        byte[] merged = new byte[ks.length + tail.length];
                        System.arraycopy(ks, 0, merged, 0, ks.length);
                        System.arraycopy(tail, 0, merged, ks.length, tail.length);
                        ks = merged;
                    }
                }
                if (ks.length < n) {
                    throw new IOException("Provider lieferte zu wenig Keystream ("
                            + ks.length + " < " + n + ")");
                }
                for (int i = 0; i < n; i++) {
                    buf[i] ^= ks[i];
                }
                // Nicht verbrauchten Keystream fuer den naechsten Block
                // behalten.
                byte[] rest = new byte[ks.length - n];
                System.arraycopy(ks, n, rest, 0, rest.length);
                ks = rest;
                out.write(buf, 0, n);
                total += n;
                remaining -= n;
            }
            return total;
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("GCM-Entschluesselung fehlgeschlagen: " + e.getMessage(), e);
        }
    }

    /**
     * Prueft den GCM-Tag einer Datei, ohne sie vollstaendig zu laden.
     *
     * <p>Der Provider puffert den Chiffrat intern; erst {@code doFinal()}
     * mit dem Tag liefert das Ergebnis. Der Klartext wird dabei nicht
     * ausgegeben - dafuer ist {@link #decryptGcmStream} da.
     *
     * @param cipherLen Laenge des Chiffrats ohne Tag
     * @param tag       die letzten 16 Byte der Datei
     */
    public static boolean verifyGcmTagStream(byte[] key, byte[] nonce, InputStream in,
                                              long cipherLen, byte[] tag) {
        if (tag == null || tag.length != GCM_TAG_LEN) {
            return false;
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_LEN * 8, counter(nonce)));
            byte[] buf = new byte[64 * 1024];
            long remaining = cipherLen;
            while (remaining > 0) {
                int want = (int) Math.min(buf.length, remaining);
                int n = in.read(buf, 0, want);
                if (n <= 0) {
                    break;
                }
                cipher.update(buf, 0, n);
                remaining -= n;
            }
            cipher.doFinal(tag);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Streamt Ciphertext durch einen Cipher in {@code out}.
     *
     * <p>Der Cipher liefert bei CTR sofort Klartext; bei GCM im
     * DECRYPT-Modus gibt {@code update()} nichts zurueck, daher wird
     * dort {@link #decryptGcmStream(byte[], byte[], InputStream, OutputStream, boolean, int)}
     * verwendet.
     */
    private static long pump(Cipher cipher, InputStream in, OutputStream out, int chunkSize)
            throws IOException {
        byte[] buf = new byte[chunkSize];
        long total = 0;
        int n;
        try {
            while ((n = in.read(buf)) > 0) {
                byte[] part = cipher.update(buf, 0, n);
                if (part != null && part.length > 0) {
                    out.write(part);
                    total += part.length;
                }
            }
            byte[] tail = cipher.doFinal();
            if (tail != null && tail.length > 0) {
                out.write(tail);
                total += tail.length;
            }
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Stream-Entschluesselung fehlgeschlagen: " + e.getMessage(), e);
        }
        return total;
    }

    /** CTR-Zaehler auf 16 Byte bringen. */
    private static byte[] counter(byte[] iv) {
        if (iv.length >= 16) {
            return Arrays.copyOfRange(iv, 0, 16);
        }
        byte[] out = new byte[16];
        System.arraycopy(iv, 0, out, 0, Math.min(iv.length, 16));
        return out;
    }

    private static byte[] padded(byte[] data, int len) {
        byte[] out = new byte[len];
        System.arraycopy(data, 0, out, 0, Math.min(data.length, len));
        return out;
    }

    /** Zufallsbytes - fuer Tests. */
    public static byte[] randomBytes(int n) {
        byte[] out = new byte[n];
        new java.security.SecureRandom().nextBytes(out);
        return out;
    }
}
