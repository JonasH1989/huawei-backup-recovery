package de.jonas.huaweibackup.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
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
 *
 * <p><b>Modulbindung:</b> jeder Kandidat traegt das Modul, aus dem sein
 * Salt stammt ({@code calllog}, {@code sms}, ...). Damit wird nicht mehr
 * jeder Schluessel an jeder Datei durchprobiert, sondern zuerst das
 * passende Modul. Das ist bei einem 20-GB-Backup der Unterschied
 * zwischen Minuten und Stunden.
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
        for (Map.Entry<String, byte[]> e : collectSalts(scan).entrySet()) {
            try {
                byte[][] keyAndNonce = Crypto.deriveKeyB(password, e.getValue());
                KeyCandidate c = new KeyCandidate("B(passwort)", keyAndNonce[0],
                        keyAndNonce[1], e.getKey());
                if (seen.add(c)) {
                    candidates.add(c);
                }
            } catch (Exception ex) {
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

                for (Map.Entry<String, byte[]> e : collectSalts(scan).entrySet()) {
                    byte[][] keyAndIv = Crypto.deriveFileKeyA(bkey, e.getValue());
                    KeyCandidate c = new KeyCandidate("A(bkey)", keyAndIv[0],
                            keyAndIv[1], e.getKey());
                    if (seen.add(c)) {
                        candidates.add(c);
                    }
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
            passwordOk[0] = bkeyOk || !candidates.isEmpty();
        }
        candidates.addAll(seen);
        return candidates;
    }

    /**
     * Sammelt alle 48-Byte-Salts aus den Modulen und dem Blob-Pool.
     *
     * <p>Der Schluessel des Map-Eintrags ist der Modulname. Fuer
     * Bloecke ohne Modulbezug (aus dem Rohtext-Pool) wird der Name
     * {@code (allgemein)} verwendet - solche Kandidaten werden
     * moduluebergreifend probiert.
     */
    private Map<String, byte[]> collectSalts(IndexScanner.Result scan) {
        Map<String, byte[]> salts = new LinkedHashMap<>();

        // Bekannte Nicht-Salt-Bloecke ausschliessen.
        java.util.Set<String> nonSalt = new java.util.HashSet<>();
        for (String b : scan.nonSaltBlobs) {
            if (b != null) {
                nonSalt.add(b.toLowerCase(Locale.ROOT));
            }
        }

        // 1) Module mit vollstaendigem Salt
        for (Map.Entry<String, String> e : scan.modules.entrySet()) {
            byte[] s = toSalt(e.getValue());
            if (s != null) {
                salts.put(e.getKey(), s);
            }
        }

        // 2) Module mit ABGESCHNITTENEM Salt: der vollstaendige Wert
        //    liegt an anderer Stelle im Backup. Gesucht wird ueber das
        //    Praefix - der abgeschnittene Wert ist die ersten Zeichen
        //    des vollstaendigen.
        for (Map.Entry<String, String> e : scan.modules.entrySet()) {
            if (salts.containsKey(e.getKey())) {
                continue;
            }
            String prefix = e.getValue() == null ? "" : e.getValue().trim().toLowerCase(Locale.ROOT);
            if (prefix.length() < 16) {
                continue;
            }
            for (String blob : scan.blobPool) {
                String b = blob.toLowerCase(Locale.ROOT);
                if (b.length() >= 96 && b.startsWith(prefix)) {
                    byte[] s = toSalt(blob);
                    if (s != null) {
                        salts.put(e.getKey(), s);
                        break;
                    }
                }
            }
        }

        // 3) Uebrige Bloecke als moduluebergreifende Kandidaten
        for (String blob : scan.blobPool) {
            if (nonSalt.contains(blob.toLowerCase(Locale.ROOT))) {
                continue;
            }
            byte[] s = toSalt(blob);
            if (s != null) {
                boolean known = false;
                for (byte[] existing : salts.values()) {
                    if (java.util.Arrays.equals(existing, s)) {
                        known = true;
                        break;
                    }
                }
                if (!known) {
                    salts.put("(allgemein)", s);
                }
            }
        }
        return salts;
    }

    /**
     * Hex -> 48-Byte-Salt (Salt 32 + Nonce 16).
     *
     * <p>Kuerzere Werte werden aufgefuellt - genau wie in der
     * Python-Vorlage ({@code h[:96].ljust(96, "0")}).
     */
    private static byte[] toSalt(String hex) {
        if (hex == null) {
            return null;
        }
        String h = hex.trim();
        if (h.length() < 64) {
            return null;
        }
        try {
            String padded = h.length() >= 96
                    ? h.substring(0, 96)
                    : h + "0".repeat(96 - h.length());
            byte[] b = hexToBytes(padded);
            return b.length == 48 ? b : null;
        } catch (IllegalArgumentException e) {
            return null;
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
