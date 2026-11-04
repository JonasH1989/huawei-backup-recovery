package de.jonas.huaweibackup.core;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Erzeugt alle plausiblen Schluessel-Kandidaten aus Passwort und Index.
 *
 * <p>Zwei Wege:
 *
 * <ol>
 *   <li><b>Schema B direkt aus dem Passwort</b> - braucht nur den Salt
 *       aus {@code encMsgV3}. Das ist der wichtigste Weg, weil Schema B
 *       kein {@code e_perbackupkey} braucht: reicht ein einziger
 *       geborgener Salt-Block, ist das Backup zu entschluesseln.</li>
 *   <li><b>Schema A ueber den bkey</b> - braucht {@code e_perbackupkey}
 *       und {@code pwkey_salt} im geretteten XML-Fragment.</li>
 * </ol>
 */
public final class CandidateBuilder {

    private final List<String> log = new ArrayList<>();

    public List<String> log() {
        return log;
    }

    /**
     * Baut alle Kandidaten.
     *
     * @param password    das Backup-Passwort
     * @param scan        Ergebnis der Index-Auswertung
     * @param passwordOk  wird false, wenn das Passwort am GCM-Tag scheitert
     */
    public List<KeyCandidate> build(String password, IndexScanner.Result scan,
                                    boolean[] passwordOk) {
        List<KeyCandidate> candidates = new ArrayList<>();
        Set<KeyCandidate> seen = new LinkedHashSet<>();

        // --- 1) Schema B: direkt aus dem Passwort ------------------------
        List<byte[]> salts = collectSalts(scan);

        for (byte[] enc : salts) {
            try {
                byte[][] keyAndNonce = Crypto.deriveKeyB(password, enc);
                seen.add(new KeyCandidate("B(passwort)", keyAndNonce[0], keyAndNonce[1]));
            } catch (Exception e) {
                // Kandidat faellt einfach weg
            }
        }

        // --- 2) Schema A: ueber den bkey --------------------------------
        boolean bkeyOk = false;
        if (scan.ePerBackupKey != null && scan.pwKeySalt != null) {
            try {
                byte[] epbk = hexToBytes(scan.ePerBackupKey);
                byte[] pwSalt = hexToBytes(scan.pwKeySalt);
                String bkey = Crypto.deriveBkey(password, epbk, pwSalt);
                bkeyOk = true;
                log.add("  bkey erfolgreich abgeleitet (GCM-Tag gueltig)");

                for (byte[] enc : salts) {
                    byte[][] keyAndIv = Crypto.deriveFileKeyA(bkey, enc);
                    seen.add(new KeyCandidate("A(bkey)", keyAndIv[0], keyAndIv[1]));
                }
            } catch (BadPasswordException e) {
                log.add("  bkey nicht ableitbar (" + e.getMessage() + ")");
                if (passwordOk != null && passwordOk.length > 0) {
                    passwordOk[0] = false;
                }
            } catch (Exception e) {
                log.add("  bkey nicht ableitbar (" + e.getMessage() + ")");
            }
        }

        if (passwordOk != null && passwordOk.length > 0) {
            passwordOk[0] = bkeyOk || !candidates.isEmpty() || !salts.isEmpty();
        }
        candidates.addAll(seen);
        return candidates;
    }

    /**
     * Sammelt alle 48-Byte-Salts aus den Modulen und dem Blob-Pool.
     */
    private List<byte[]> collectSalts(IndexScanner.Result scan) {
        List<byte[]> salts = new ArrayList<>();

        for (String encHex : scan.modules.values()) {
            addSalt(salts, encHex);
        }
        for (String blob : scan.blobPool) {
            addSalt(salts, blob);
        }
        return salts;
    }

    private static void addSalt(List<byte[]> salts, String hex) {
        if (hex == null) {
            return;
        }
        String h = hex.trim();
        if (h.length() < 64) {
            return;
        }
        try {
            // 96 Hex-Zeichen = 48 Byte: Salt (32) + Nonce (16).
            // Kuerzere Werte werden aufgefuellt - genau wie in der
            // Python-Vorlage (h[:96].ljust(96, "0")).
            String padded = h.length() >= 96
                    ? h.substring(0, 96)
                    : h + "0".repeat(96 - h.length());
            byte[] b = hexToBytes(padded);
            if (b.length == 48) {
                salts.add(b);
            }
        } catch (IllegalArgumentException e) {
            // Kein gueltiges Hex - ueberspringen
        }
    }

    /** Hex-String -> Bytes. */
    public static byte[] hexToBytes(String hex) {
        String h = hex.trim();
        if ((h.length() % 2) != 0) {
            h = h.substring(0, h.length() - 1);
        }
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    /** Bytes -> Hex-String (klein). */
    public static String bytesToHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString().toLowerCase(Locale.ROOT);
    }
}
