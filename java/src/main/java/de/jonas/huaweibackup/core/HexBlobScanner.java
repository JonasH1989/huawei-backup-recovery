package de.jonas.huaweibackup.core;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Sucht verschluesselungsrelevante Hex-Bloecke in beliebigen Dateien.
 *
 * <p><b>Warum das noetig ist:</b> bei einem abgebrochenen Backup ist die
 * {@code info.xml} unvollstaendig. Die Indexzeile eines Moduls fehlt
 * dann - und damit dessen {@code encMsgV3}. Ohne diesen Wert ist die
 * Datei des Moduls nicht entschluesselbar, egal wie gut das Passwort
 * ist.
 *
 * <p>Der Wert kann aber im Backup an anderer Stelle liegen: in einer
 * zweiten Indexdatei, in einer Pruefdatei ({@code check.dat}) oder in
 * einem der Archivteile. Diese Suche findet ihn.
 *
 * <p><b>Warum das nicht trivial ist:</b> das Backup ist 20 GB gross.
 * Ein vollstaendiger Durchlauf mit {@code readAllBytes} ist unmoeglich
 * (Speicher), ein einfaches {@code grep} ueber Hex-Muster ist
 * langsam. Deshalb:
 *
 * <ul>
 *   <li>Die Datei wird <b>blockweise</b> gelesen (1 MB), nicht am Stueck.
 *       Der Speicherbedarf ist konstant.</li>
 *   <li>Die Bloecke werden <b>ueberlappend</b> gelesen, damit ein
 *       Hex-Wert nicht ueber die Blockgrenze zerschnitten wird. Der
 *       Ueberhang betraegt 4 KB - ein 96-Byte-Wert passt immer hinein.</li>
 *   <li>Gesucht wird nur nach Hex-Runs ab 96 Zeichen (48 Byte). Das
 *       sind genau die Kandidaten fuer {@code encMsgV3} und
 *       {@code checkMsgV3}. Kuerzere Runs wuerden nur Unrat liefern
 *       (Zeitstempel, Dateinamen-Hashes) und die Laufzeit sprengen.</li>
 * </ul>
 */
public final class HexBlobScanner {

    /** Blockgroesse fuer das Lesen. */
    private static final int CHUNK = 1024 * 1024;

    /**
     * Ueberhang zwischen zwei Fenstern.
     *
     * <p>Ein {@code encMsgV3} ist 96 Hex-Zeichen lang. Damit ein
     * solcher Wert nicht zerschnitten wird, muss der Ueberhang groesser
     * sein als die maximale Run-Laenge. 4 KB ist gross genug fuer
     * {@code checkMsgV3} (128 Zeichen) und klein genug, um nicht
     * unnoetig zu arbeiten.
     */
    private static final int OVERLAP = 4096;

    /** Mindestlaenge eines Hex-Runs (96 Zeichen = 48 Byte). */
    private static final int MIN_RUN = 96;

    /** Maximale Groesse einer Datei, die durchsucht wird. */
    public static final long MAX_FILE_BYTES = 2L * 1024 * 1024 * 1024;

    /** Muster fuer einen Hex-Run. */
    private static final Pattern HEX_RUN = Pattern.compile("[0-9a-fA-F]{" + MIN_RUN + ",}");

    /** Zaehler fuer die Protokoll-Ausgabe. */
    private int filesScanned;
    private long bytesScanned;
    private int blobsFound;

    /** Ergebnis eines Durchlaufs. */
    public static final class Result {
        /** Alle gefundenen Hex-Bloecke, dedupliziert, Reihenfolge stabil. */
        public final List<String> blobs = new ArrayList<>();
        /** Wie viele Dateien wurden durchsucht. */
        public int filesScanned;
        /** Wie viele Byte wurden gelesen. */
        public long bytesScanned;
    }

    /**
     * Durchsucht alle Dateien unterhalb von {@code root}.
     *
     * @param root       Wurzelverzeichnis
     * @param known      bereits bekannte Bloecke (werden nicht doppelt gemeldet)
     * @param progress   Fortschrittsrueckmeldung (Dateiname), darf null sein
     */
    public Result scan(Path root, Set<String> known, java.util.function.Consumer<String> progress)
            throws IOException {
        Result result = new Result();
        Set<String> seen = new LinkedHashSet<>(known);

        for (Path p : IndexScanner.listFiles(root)) {
            long size;
            try {
                size = Files.size(p);
            } catch (IOException e) {
                continue;
            }
            // Zu kleine Dateien enthalten keine Bloecke, zu grosse
            // sind im 20-GB-Backup die Archivteile - die werden nur
            // gestreift (siehe unten).
            if (size < MIN_RUN / 2) {
                continue;
            }
            if (progress != null) {
                progress.accept(p.getFileName().toString());
            }

            for (String blob : scanFile(p, size)) {
                if (seen.add(blob.toLowerCase(Locale.ROOT))) {
                    result.blobs.add(blob);
                }
            }
            result.filesScanned++;
        }
        result.bytesScanned = bytesScanned;
        return result;
    }

    /**
     * Durchsucht eine einzelne Datei blockweise.
     *
     * @param p    die Datei
     * @param size ihre Groesse
     * @return gefundene Hex-Bloecke
     */
    public List<String> scanFile(Path p, long size) {
        List<String> found = new ArrayList<>();
        Set<String> localSeen = new LinkedHashSet<>();

        // Sehr grosse Dateien (Archivteile) werden nur am Anfang und
        // am Ende gelesen. Ein Index steht praktisch immer am Anfang;
        // das Ende ist eine zweite Chance fuer abgeschnittene Werte.
        boolean fullScan = size <= 64L * 1024 * 1024;

        try (InputStream in = Files.newInputStream(p)) {
            byte[] buf = new byte[CHUNK];
            byte[] tail = new byte[0];
            long consumed = 0;

            while (consumed < size) {
                int n = in.read(buf);
                if (n <= 0) {
                    break;
                }
                consumed += n;
                bytesScanned += n;

                // Fenster aus Ueberhang + aktuellem Block bilden.
                byte[] window = new byte[tail.length + n];
                System.arraycopy(tail, 0, window, 0, tail.length);
                System.arraycopy(buf, 0, window, tail.length, n);

                collect(window, found, localSeen);

                // Ueberhang fuer den naechsten Block sichern.
                int keep = Math.min(OVERLAP, window.length);
                tail = new byte[keep];
                System.arraycopy(window, window.length - keep, tail, 0, keep);

                if (!fullScan && consumed >= 8L * 1024 * 1024) {
                    // Nur der Anfang wurde gelesen - jetzt noch das Ende.
                    readTail(p, size, found, localSeen);
                    break;
                }
            }
        } catch (IOException e) {
            // Teilweise gelesen - die bisher gefundenen Werte bleiben.
        }
        blobsFound += found.size();
        return found;
    }

    /** Liest die letzten 2 MB einer Datei. */
    private void readTail(Path p, long size, List<String> found, Set<String> localSeen) {
        long want = Math.min(size, 2L * 1024 * 1024);
        try (InputStream in = Files.newInputStream(p)) {
            long skip = size - want;
            while (skip > 0) {
                long r = in.skip(skip);
                if (r <= 0) {
                    break;
                }
                skip -= r;
            }
            byte[] tail = in.readAllBytes();
            bytesScanned += tail.length;
            collect(tail, found, localSeen);
        } catch (IOException e) {
            // ignorieren
        }
    }

    /** Sammelt alle Hex-Runs aus einem Fenster. */
    private static void collect(byte[] window, List<String> found, Set<String> localSeen) {
        Matcher m = HEX_RUN.matcher(new String(window, StandardCharsets.US_ASCII));
        while (m.find()) {
            String blob = m.group().toLowerCase(Locale.ROOT);
            if (localSeen.add(blob)) {
                found.add(blob);
            }
        }
    }

    /** Zaehler fuer die Protokoll-Ausgabe. */
    public int filesScanned() {
        return filesScanned;
    }

    public long bytesScanned() {
        return bytesScanned;
    }

    public int blobsFound() {
        return blobsFound;
    }
}
