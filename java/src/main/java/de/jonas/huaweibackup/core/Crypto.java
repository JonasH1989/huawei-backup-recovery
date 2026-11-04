package de.jonas.huaweibackup.core;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import javax.crypto.AEADBadTagException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Krypto-Primitive fuer die Huawei-KoBackup-Recovery.
 *
 * <p>Zwei Schemata werden unterstuetzt (reverse-engineered aus der
 * KoBackup-/HiSuite-Implementierung):
 *
 * <pre>
 * Schema A - KoBackup v10..v12 (AES-256-CTR)
 *   K        = PBKDF2-HMAC-SHA256(passwort, pwkey_salt[:16], 10000, 32)
 *   bkey     = AES-256-GCM(K, nonce=pwkey_salt[16:28]).decrypt(e_perbackupkey[:32])
 *              (e_perbackupkey[32:48] ist der GCM-Tag -&gt; Passwort-Pruefung)
 *   file_key = PBKDF2-HMAC-SHA256(bkey.encode(utf-8), encMsgV3[:32], 5000, 32)
 *   Datei    = AES-256-CTR(file_key, iv=encMsgV3[32:48])
 *
 * Schema B - KoBackup v13 / HiSuite 11+ (AES-256-GCM)
 *   aes_key = PBKDF2-HMAC-SHA256(passwort, encMsgV3[:32], 5000, 32)
 *   Datei   = ciphertext || 16-Byte-GCM-Tag, nonce = encMsgV3[32:48]
 * </pre>
 *
 * <p><b>Wichtig fuer die Rettung:</b> Schema B braucht kein
 * {@code e_perbackupkey} - der Schluessel folgt direkt aus Passwort und
 * Salt. Damit reicht es, die {@code encMsgV3}-Bloecke zu bergen.
 */
public final class Crypto {

    public static final int GCM_TAG_LEN = 16;
    public static final int PBKDF2_ITER_BKEY = 10_000;  // Schema A: Passwort -> K
    public static final int PBKDF2_ITER_FILE = 5_000;   // Schema A: bkey -> file_key
    public static final int PBKDF2_ITER_V13 = 5_000;    // Schema B: Passwort -> aes_key

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

        if (pwKeySalt.length < 16 || ePerBackupKey.length < 32) {
            throw new IllegalArgumentException("pwkey_salt/e_perbackupkey zu kurz");
        }

        byte[] keySalt = Arrays.copyOfRange(pwKeySalt, 0, 16);
        byte[] nonce = pwKeySalt.length >= 28
                ? Arrays.copyOfRange(pwKeySalt, 16, 28)
                : Arrays.copyOfRange(pwKeySalt, 16, pwKeySalt.length);
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
            javax.crypto.SecretKeyFactory f =
                    javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            char[] chars = new String(password, StandardCharsets.UTF_8).toCharArray();
            return f.generateSecret(new javax.crypto.spec.PBEKeySpec(
                    chars, salt, iterations, keyLen * 8)).getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("PBKDF2 fehlgeschlagen", e);
        }
    }

    // -----------------------------------------------------------------
    // Entschluesselung
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
            byte[] counter = iv.length >= 16
                    ? Arrays.copyOfRange(iv, 0, 16)
                    : padded(iv, 16);
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new javax.crypto.spec.IvParameterSpec(counter));
            return cipher.doFinal(data);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Schema B: AES-256-GCM, Tag wird abgetrennt.
     *
     * <p>Der 16-Byte-Tag am Dateiende ist KEIN Chiffrat. Wird er
     * mitentschluesselt, ist die Ausgabe 16 Byte zu lang und die Datei
     * kaputt.
     *
     * @param hasTag true, wenn {@code data} den Tag bereits enthaelt
     */
    public static byte[] decryptGcm(byte[] key, byte[] nonce, byte[] data, boolean hasTag) {
        try {
            byte[] iv = nonce.length >= 16
                    ? Arrays.copyOfRange(nonce, 0, 16)
                    : padded(nonce, 16);
            byte[] ct = data;
            if (hasTag) {
                if (data.length <= GCM_TAG_LEN) {
                    return null;
                }
                ct = Arrays.copyOfRange(data, 0, data.length - GCM_TAG_LEN);
            }
            return decryptGcmPlaintext(key, iv, ct);
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
     * selbst (XOR mit Null = Identitaet).
     *
     * <p>Damit muss das J0-Konstrukt nicht nachgebaut werden - der
     * Provider erledigt es fuer alle IV-Laengen korrekt. Ein selbst
     * gebautes GHASH waere hier fehleranfaellig; die Referenz-Datei
     * {@code references/java-portierung-gcm.md} dokumentiert die
     * Messung und die Sackgassen.
     */
    private static byte[] decryptGcmPlaintext(byte[] key, byte[] iv, byte[] ct) {
        try {
            // Keystream: Provider verschluesselt Nullen -> Ergebnis ist
            // der Keystream (die ersten n Byte vor dem Tag).
            Cipher stream = Cipher.getInstance("AES/GCM/NoPadding");
            stream.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_LEN * 8, iv));
            byte[] keystream = stream.doFinal(new byte[ct.length]);

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
     * J0-Konstrukt nach NIST SP 800-38D, Gleichung 7.
     *
     * <pre>
     * J0 = GHASH_H(IV || 0^(s+64) || [len(IV)]_64)
     * </pre>
     *
     * <p>Die Laengenangaben in der Norm sind in <b>Bit</b>:
     * {@code s = 128*ceil(len(IV)/128) - len(IV)}. Damit ist der
     * Nullblock-Anhang {@code s/8 + 8} Byte (8 Byte Nullen plus der
     * 64-Bit-Laengenwert), und die Gesamtlänge ist ein Vielfaches von
     * 16 Byte.
     *
     * <p>Fuer ein 96-Bit-IV gilt die Vereinfachung
     * {@code J0 = IV || 0^31 || 1}. KoBackup nutzt jedoch 16-Byte-Nonces -
     * damit greift der GHASH-Fall.
     */
    private static byte[] gcmJ0(byte[] h, byte[] iv) {
        if (iv.length == 12) {
            byte[] j0 = new byte[16];
            System.arraycopy(iv, 0, j0, 0, 12);
            j0[15] = 1;
            return j0;
        }
        // s (in Bit) = 128*ceil(len*8/128) - len*8
        long lenBits = (long) iv.length * 8L;
        long sBits = 128L * ((lenBits + 127L) / 128L) - lenBits;
        int sBytes = (int) (sBits / 8L);

        // x = IV || 0^(s/8 + 8) || [len(IV)]_64
        byte[] x = new byte[iv.length + sBytes + 8 + 8];
        System.arraycopy(iv, 0, x, 0, iv.length);
        // [len(IV)]_64 in Bit, big-endian
        for (int i = 0; i < 8; i++) {
            x[x.length - 1 - i] = (byte) (lenBits >>> (8 * i));
        }
        return ghash(h, x);
    }

    /** GHASH: Multiplikation in GF(2^128) mit R = 0xe1 || 0^120. */
    private static byte[] ghash(byte[] h, byte[] x) {
        byte[] y = new byte[16];
        for (int off = 0; off + 16 <= x.length; off += 16) {
            for (int i = 0; i < 16; i++) {
                y[i] ^= x[off + i];
            }
            y = gfMul(y, h);
        }
        return y;
    }

    /** Multiplikation in GF(2^128), Bit-fuer-Bit, MSB zuerst. */
    private static byte[] gfMul(byte[] a, byte[] b) {
        byte[] z = new byte[16];
        byte[] v = b.clone();
        for (int i = 0; i < 128; i++) {
            int bit = (a[i / 8] >>> (7 - (i % 8))) & 1;
            if (bit != 0) {
                for (int k = 0; k < 16; k++) {
                    z[k] ^= v[k];
                }
            }
            boolean lsb = (v[15] & 1) != 0;
            // v >>= 1
            for (int k = 15; k > 0; k--) {
                v[k] = (byte) ((v[k] >>> 1) | ((v[k - 1] & 1) << 7));
            }
            v[0] = (byte) (v[0] >>> 1);
            if (lsb) {
                v[0] ^= (byte) 0xe1;
            }
        }
        return z;
    }

    /** AES-ECB-Blockverschluesselung (ein Block). */
    private static byte[] aesEncryptBlock(byte[] key, byte[] block) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        return cipher.doFinal(block);
    }

    /** 128-Bit-Big-Endian-Zaehler um 1 erhoehen. */
    private static byte[] incrementCounter(byte[] counter) {
        byte[] out = counter.clone();
        for (int i = out.length - 1; i >= 0; i--) {
            if (++out[i] != 0) {
                break;
            }
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
            byte[] iv = nonce.length >= 16
                    ? Arrays.copyOfRange(nonce, 0, 16)
                    : padded(nonce, 16);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_LEN * 8, iv));
            cipher.doFinal(data);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] padded(byte[] data, int len) {
        byte[] out = new byte[len];
        System.arraycopy(data, 0, out, 0, Math.min(data.length, len));
        return out;
    }

    /** Zufallsbytes - fuer Tests. */
    public static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        new java.security.SecureRandom().nextBytes(b);
        return b;
    }
}
