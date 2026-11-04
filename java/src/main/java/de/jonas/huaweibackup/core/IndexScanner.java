package de.jonas.huaweibackup.core;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Findet und bewertet die Index-Dateien eines abgebrochenen Backups.
 *
 * <p>Zwei unabhaengige Rettungswege:
 *
 * <ol>
 *   <li><b>Strukturierte XML-Auswertung</b> von {@code info.xml},
 *       {@code cinfoset.dat} und Verwandten. Das XML darf kaputt sein -
 *       dann greift Weg 2.</li>
 *   <li><b>Rohtext-Rettung</b>: alle Hex-Bloecke werden im GEGENWERTIG
 *       ueber <em>alle</em> Dateien des Backups gesucht, nicht nur in den
 *       Index-Dateien. Ein Backup bricht an genau einer Stelle ab; die
 *       Kopie des Index an anderer Stelle kann intakt sein.</li>
 * </ol>
 *
 * <p><b>Streaming:</b> bei einem 20-GB-Backup darf keine Datei
 * vollstaendig in den Speicher. Die Index-Dateien werden begrenzt
 * gelesen (sie sind klein), die Nutzdateien werden nur gestreift und
 * nur bis zu einem begrenzten Fenster durchsucht.
 *
 * <p>Index-Dateien koennen UTF-8 oder UTF-16 kodiert sein. Bei UTF-16
 * sind die Hex-Zeichen von Nullbytes durchsetzt, ein Regex auf den
 * Rohbytes greift nicht - deshalb wird zusaetzlich dekodiert.
 */
public final class IndexScanner {

    private static final Set<String> INDEX_NAMES = new LinkedHashSet<>(List.of(
            "info.xml", "cinfoset.dat", "backupinfo.ini", "index.xml", "backupinfo.xml"));

    /** Dateiendungen, die nie Nutzdaten sind. */
    public static final Set<String> SKIP_NAMES = new LinkedHashSet<>(List.of(
            "info.xml", "cinfoset.dat", "backupinfo.ini", "index.xml",
            "backupinfo.xml", "readme.txt", "readme"));

    private static final Set<String> MODULE_TABLES = new LinkedHashSet<>(List.of(
            "BackupFileModuleInfo",
            "BackupFileModuleInfo_Media",
            "BackupFileModuleInfo_SystemData"));

    /** Hex-Run mit mindestens 64 Zeichen (32 Byte). */
    private static final Pattern HEX_RUN = Pattern.compile("[0-9a-fA-F]{16,}");

    /** Maximale Groesse einer Index-Datei, die vollstaendig gelesen wird. */
    private static final long MAX_INDEX_BYTES = 8L * 1024 * 1024;

    /**
     * Wie viele Byte einer Nicht-Index-Datei fuer die Rohtext-Suche
     * gelesen werden. Bei einem 20-GB-Backup waere ein vollstaendiger
     * Scan unmoeglich; die Hex-Bloecke liegen am Dateianfang oder
     * innerhalb der ersten MB.
     */
    private static final long RAW_SCAN_WINDOW = 2L * 1024 * 1024;

    /** Maximale Dateigroesse, die fuer die Rohtext-Suche beruecksichtigt wird. */
    private static final long MAX_RAW_SCAN_FILE = 64L * 1024 * 1024;

    private final List<String> log = new ArrayList<>();

    public List<String> log() {
        return log;
    }

    /** Ergebnis der Index-Auswertung. */
    public static final class Result {
        /** Modulname -> encMsgV3 (Hex). */
        public final Map<String, String> modules = new LinkedHashMap<>();
        /** Modulname -> Tabellen (z. B. {@code calls}). */
        public final Map<String, String> moduleTables = new LinkedHashMap<>();
        /** e_perbackupkey (Hex) oder null. */
        public String ePerBackupKey;
        /** pwkey_salt (Hex) oder null. */
        public String pwKeySalt;
        /** Alle gefundenen Hex-Bloecke, dedupliziert, Reihenfolge stabil. */
        public final List<String> blobPool = new ArrayList<>();
        /**
         * Hex-Bloecke, die nachweislich KEIN Salt sind (e_perbackupkey,
         * pwkey_salt, checkMsgV3, snHash ...). Sie wuerden als Salt
         * falsche Schluessel ergeben.
         */
        public final List<String> nonSaltBlobs = new ArrayList<>();
        /** Wurde ein wohlgeformtes XML gelesen? */
        public boolean xmlOk;
    }

    /**
     * Scannt das Backup und sammelt alle Index-relevanten Werte.
     *
     * @param root Wurzelverzeichnis des Backups
     */
    public Result scan(Path root) throws IOException {
        Result result = new Result();
        List<Path> indexFiles = findIndexFiles(root);
        Set<String> seenBlobs = new LinkedHashSet<>();

        for (Path p : indexFiles) {
            long size;
            try {
                size = Files.size(p);
            } catch (IOException e) {
                continue;
            }
            log.add(String.format("  Index-Datei: %s (%d Byte)",
                    p.getFileName(), size));

            byte[] raw = readLimited(p, MAX_INDEX_BYTES);
            if (raw == null) {
                continue;
            }

            if (looksLikeXml(p, raw)) {
                parseXml(raw, result);
            }
            // Rohtext-Rettung immer - auch aus einem wohlgeformten XML.
            // Ein abgebrochener Wert ist sonst nicht auffindbar.
            for (String blob : salvageHexBlobs(raw)) {
                if (seenBlobs.add(blob.toLowerCase(Locale.ROOT))) {
                    result.blobPool.add(blob);
                }
            }
            // Abgeschnittene Hex-Werte: der fehlende Teil wird mit
            // Nullen aufgefuellt. Ob der Kandidat taugt, entscheidet
            // anschliessend die Signatur- bzw. GCM-Pruefung.
            for (String blob : salvageTruncated(raw)) {
                if (seenBlobs.add(blob.toLowerCase(Locale.ROOT))) {
                    result.blobPool.add(blob);
                }
            }
        }

        // Rohtext-Suche im GESAMTEN Backup - aber nur gestreift.
        int scanned = 0;
        long bytesRead = 0;
        for (Path p : listFiles(root)) {
            if (indexFiles.contains(p)) {
                continue;
            }
            long size;
            try {
                size = Files.size(p);
            } catch (IOException e) {
                continue;
            }
            if (size < 32 || size > MAX_RAW_SCAN_FILE) {
                continue;
            }
            // Nur ein Fenster am Dateianfang lesen, nicht die ganze Datei.
            long window = Math.min(size, RAW_SCAN_WINDOW);
            byte[] raw = readLimited(p, window);
            if (raw == null || raw.length < 32) {
                continue;
            }
            scanned++;
            bytesRead += raw.length;
            List<String> found = salvageHexBlobs(raw);
            if (!found.isEmpty()) {
                log.add(String.format("  Weitere Hex-Bloecke in: %s (%d Treffer)",
                        root.relativize(p), found.size()));
                for (String blob : found) {
                    if (seenBlobs.add(blob.toLowerCase(Locale.ROOT))) {
                        result.blobPool.add(blob);
                    }
                }
            }
        }
        if (scanned > 0) {
            log.add(String.format("  Rohtext-Suche ueber %d Dateien (%d MB gelesen)",
                    scanned, bytesRead / (1024 * 1024)));
        }
        return result;
    }

    /**
     * Liest hoechstens {@code max} Byte am Dateianfang.
     *
     * <p>Der Index liegt am Anfang der Datei; ein Abbruch passiert
     * typischerweise erst danach.
     */
    private static byte[] readLimited(Path p, long max) {
        try (InputStream in = Files.newInputStream(p)) {
            byte[] buf = new byte[(int) Math.min(max, Integer.MAX_VALUE)];
            int total = 0;
            int n;
            while (total < buf.length
                    && (n = in.read(buf, total, buf.length - total)) > 0) {
                total += n;
            }
            if (total == buf.length) {
                return buf;
            }
            return Arrays.copyOf(buf, total);
        } catch (IOException e) {
            return null;
        }
    }

    private static boolean looksLikeXml(Path p, byte[] raw) {
        String name = p.getFileName().toString().toLowerCase(Locale.ROOT);
        if (name.endsWith(".xml")) {
            return true;
        }
        // UTF-16LE-BOM
        if (raw.length >= 2 && (raw[0] & 0xff) == 0xff && (raw[1] & 0xff) == 0xfe) {
            return true;
        }
        String head = new String(raw, 0, Math.min(raw.length, 64),
                StandardCharsets.UTF_8).trim();
        return head.startsWith("<?xml") || head.startsWith("<");
    }

    /**
     * Wertet ein (moeglicherweise kaputtes) XML strukturiert aus.
     *
     * <p>Das XML wird mit einem lockeren Parser gelesen: auch wenn die
     * Gesamtstruktur kaputt ist, werden die einzelnen
     * {@code <row table="...">}-Bloecke trotzdem gefunden.
     */
    private void parseXml(byte[] raw, Result result) {
        String text = decodeXml(raw);
        if (text == null) {
            return;
        }
        // Lockere Zeilen-Parsing: pro <row>...</row> ein Block.
        Matcher rowMatcher = Pattern.compile(
                "<row\\s+table=\"([^\"]*)\"[^>]*>(.*?)</row>",
                Pattern.DOTALL).matcher(text);

        boolean anyRow = false;
        while (rowMatcher.find()) {
            anyRow = true;
            String table = rowMatcher.group(1);
            String block = rowMatcher.group(2);
            Map<String, String> cols = parseColumns(block);

            if ("BackupFilesTypeInfo".equals(table)) {
                if (result.ePerBackupKey == null) {
                    result.ePerBackupKey = cols.get("e_perbackupkey");
                }
                if (result.pwKeySalt == null) {
                    result.pwKeySalt = cols.get("pwkey_salt");
                }
                if (result.ePerBackupKey != null) {
                    result.nonSaltBlobs.add(result.ePerBackupKey.trim());
                }
                if (result.pwKeySalt != null) {
                    result.nonSaltBlobs.add(result.pwKeySalt.trim());
                }
            } else if (MODULE_TABLES.contains(table)) {
                String name = cols.get("name");
                if (name != null && !name.isBlank()) {
                    String mod = name.trim();
                    result.modules.putIfAbsent(mod,
                            cols.getOrDefault("encMsgV3", "").trim());
                    String tables = cols.get("tables");
                    if (tables != null && !tables.isBlank()) {
                        result.moduleTables.putIfAbsent(mod, tables.trim());
                    }
                    // checkMsgV3 ist ein Pruefwert, KEIN Salt.
                    String check = cols.get("checkMsgV3");
                    if (check != null && !check.isBlank()) {
                        result.nonSaltBlobs.add(check.trim());
                    }
                }
            }
        }
        if (anyRow) {
            result.xmlOk = true;
        }
    }

    /** Liest alle {@code <column name="X"><value String="Y"/>} aus einem Block. */
    private static Map<String, String> parseColumns(String block) {
        Map<String, String> cols = new LinkedHashMap<>();
        Matcher m = Pattern.compile(
                "<column\\s+name=\"([^\"]*)\"[^>]*>(.*?)</column>",
                Pattern.DOTALL).matcher(block);
        while (m.find()) {
            String colName = m.group(1);
            String body = m.group(2);
            Matcher v = Pattern.compile(
                    "<value\\s+([^>]*)/?>").matcher(body);
            if (v.find()) {
                String attrs = v.group(1);
                Matcher a = Pattern.compile("(String|Integer|Long|Boolean)=\"([^\"]*)\"")
                        .matcher(attrs);
                if (a.find()) {
                    cols.put(colName, a.group(2));
                }
            }
        }
        return cols;
    }

    /** Dekodiert UTF-8 oder UTF-16 (mit BOM). */
    private static String decodeXml(byte[] raw) {
        if (raw.length >= 2) {
            int b0 = raw[0] & 0xff;
            int b1 = raw[1] & 0xff;
            if (b0 == 0xff && b1 == 0xfe) {
                return new String(raw, 2, raw.length - 2, StandardCharsets.UTF_16LE);
            }
            if (b0 == 0xfe && b1 == 0xff) {
                return new String(raw, 2, raw.length - 2, StandardCharsets.UTF_16BE);
            }
        }
        try {
            return new String(raw, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Zieht alle Hex-Bloecke aus Rohdaten.
     *
     * <p>Ein mitten im Attribut abgeschnittener Wert hat eine unvollstaendige
     * Hex-Laenge und wird hier <em>nicht</em> gefunden. Dafuer gibt es
     * {@link #salvageTruncated(byte[])}.
     */
    public static List<String> salvageHexBlobs(byte[] raw) {
        List<String> out = new ArrayList<>();
        for (byte[] variant : decodedVariants(raw)) {
            String s = new String(variant, StandardCharsets.US_ASCII);
            Matcher m = HEX_RUN.matcher(s);
            while (m.find()) {
                String h = m.group();
                if (h.length() >= 64) {
                    out.add(h);
                }
            }
        }
        return out;
    }

    /**
     * Rekonstruiert Hex-Bloecke, die am Dateiende abgeschnitten wurden.
     *
     * <p>Ein Backup-Abbruch mitten in der Datei hinterlaesst oft einen
     * angefangenen Hex-Wert. Der fehlende Teil wird mit Nullen aufgefuellt -
     * die GCM-Pruefung entscheidet, ob der Kandidat taugt.
     */
    public static List<String> salvageTruncated(byte[] raw) {
        List<String> out = new ArrayList<>();
        for (byte[] variant : decodedVariants(raw)) {
            String s = new String(variant, StandardCharsets.US_ASCII);
            Matcher m = HEX_RUN.matcher(s);
            while (m.find()) {
                String h = m.group();
                if (h.length() >= 96) {
                    continue;
                }
                if ((h.length() % 2) != 0) {
                    h = h.substring(0, h.length() - 1);
                }
                out.add(h + "0".repeat(96 - h.length()));
            }
        }
        return out;
    }

    /**
     * Rohtext plus UTF-16-Dekodierungen.
     *
     * <p>Index-Dateien koennen UTF-16LE/BE-kodiert sein. Dann sind die
     * Hex-Zeichen von Nullbytes durchsetzt und ein Regex auf den Rohbytes
     * greift nicht.
     */
    private static List<byte[]> decodedVariants(byte[] raw) {
        List<byte[]> variants = new ArrayList<>();
        variants.add(raw);
        byte[] head = new byte[Math.min(raw.length, 400)];
        System.arraycopy(raw, 0, head, 0, head.length);
        boolean hasNull = false;
        for (byte b : head) {
            if (b == 0) {
                hasNull = true;
                break;
            }
        }
        if (hasNull) {
            variants.add(decodeUtf16(raw, StandardCharsets.UTF_16LE));
            variants.add(decodeUtf16(raw, StandardCharsets.UTF_16BE));
        }
        return variants;
    }

    /**
     * Dekodiert UTF-16 und filtert Nicht-ASCII-Zeichen heraus.
     */
    private static byte[] decodeUtf16(byte[] raw, java.nio.charset.Charset cs) {
        String s = new String(raw, cs);
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 128) {
                sb.append(c);
            }
        }
        return sb.toString().getBytes(StandardCharsets.US_ASCII);
    }

    /** Findet alle Index-Dateien im Backup. */
    public static List<Path> findIndexFiles(Path root) throws IOException {
        List<Path> out = new ArrayList<>();
        for (Path p : listFiles(root)) {
            String name = p.getFileName().toString().toLowerCase(Locale.ROOT);
            if (INDEX_NAMES.contains(name)) {
                out.add(p);
            }
        }
        return out;
    }

    /** Listet alle Dateien unterhalb von {@code root}. */
    public static List<Path> listFiles(Path root) throws IOException {
        List<Path> out = new ArrayList<>();
        try (var stream = Files.walk(root)) {
            stream.filter(Files::isRegularFile).forEach(out::add);
        }
        return out;
    }

    /**
     * Listet die Dateien, die Inhalt sein koennten (keine Index-Dateien).
     */
    public static List<Path> collectPayloadFiles(Path root) throws IOException {
        List<Path> out = new ArrayList<>();
        for (Path p : listFiles(root)) {
            String name = p.getFileName().toString().toLowerCase(Locale.ROOT);
            if (SKIP_NAMES.contains(name)) {
                continue;
            }
            try {
                if (Files.size(p) < 32) {
                    continue;
                }
            } catch (IOException e) {
                continue;
            }
            out.add(p);
        }
        return out;
    }
}
