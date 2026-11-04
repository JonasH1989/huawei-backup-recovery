package de.jonas.huaweibackup.core;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Die Recovery-Engine: entschluesselt ein abgebrochenes Backup.
 *
 * <p>Der entscheidende Punkt ist die <b>Signatur-Verifikation</b>: jede
 * Datei wird mit jedem plausiblen Schluessel entschluesselt und anhand
 * der Dateisignatur (JPEG/PNG/MP4/SQLite/...) geprueft. Damit braucht
 * der Vorgang weder eine vollstaendige Ordnerstruktur noch einen
 * intakten Index.
 *
 * <p><b>Streaming:</b> Dateien werden blockweise gelesen und
 * geschrieben. Nur die ersten 4 KB werden zur Signaturpruefung
 * entschluesselt; der Rest wird gestreamt, sobald der Schluessel
 * feststeht. Der Speicherbedarf ist dadurch konstant und unabhaengig
 * von der Backup-Groesse.
 *
 * <p><b>Modulbindung:</b> Kandidaten tragen ihr Modul. Beim Versuch
 * wird zuerst das passende Modul probiert und erst danach der Rest -
 * das haelt die Laufzeit auch bei 20 GB vertretbar.
 */
public final class RecoveryEngine {

    /** Blockgroesse fuer das Streaming. */
    private static final int CHUNK = 4 * 1024 * 1024;

    /** Wie viele Byte fuer die Signaturpruefung entschluesselt werden. */
    private static final int SIGNATURE_PROBE = 4096;

    /** Rueckmeldung an die Oberflaeche. */
    public interface Listener {
        /** Fortschritt: {@code done} von {@code total} Dateien bearbeitet. */
        void onProgress(int done, int total);

        /** Fortschritt in der Index-Phase. */
        void onIndexProgress(int done, int total, String phase);

        /** Eine Datei wurde entschluesselt und geschrieben. */
        void onRecovered(String sourcePath, String targetPath, String extension,
                         String schema, boolean authenticated);

        /** Eine Datei liess sich nicht entschluesseln. */
        void onFailed(String sourcePath, String reason);

        /** Eine Meldung fuer das Protokollfenster. */
        void onMessage(String message);
    }

    /** Ergebnis eines Laufs. */
    public static final class Summary {
        public int recovered;
        public int failed;
        public int total;
        public final Map<String, Integer> byExtension = new LinkedHashMap<>();
        public final List<String> failures = new ArrayList<>();
    }

    private final Path backupRoot;
    private final Path outputRoot;
    private final String password;
    private final Listener listener;

    /** Media-Index mit den pro Datei hinterlegten IVs. */
    private MediaIndex mediaIndex = new MediaIndex();

    /**
     * Soll das gesamte Backup nach Index-Bloecken durchsucht werden?
     *
     * <p>Bei einem abgebrochenen {@code info.xml} fehlt die Indexzeile
     * des betroffenen Moduls. Nur eine Suche durch das ganze Backup
     * kann den fehlenden {@code encMsgV3} noch finden.
     */
    private boolean deepSearch = true;

    public RecoveryEngine(Path backupRoot, Path outputRoot, String password,
                          Listener listener) {
        this.backupRoot = backupRoot;
        this.outputRoot = outputRoot;
        this.password = password;
        this.listener = listener;
    }

    /**
     * Fuehrt die Recovery aus.
     *
     * @throws IOException bei Zugriffsproblemen
     */
    public Summary run() throws IOException {
        Summary summary = new Summary();

        // --- Index auswerten -------------------------------------------
        message("=== Index-Auswertung ===");
        IndexScanner scanner = new IndexScanner();
        IndexScanner.Result scan = scanner.scan(backupRoot);
        scanner.log().forEach(this::message);

        message(String.format("  Module strukturiert: %d | Hex-Bloecke gerettet: %d",
                scan.modules.size(), scan.blobPool.size()));
        for (Map.Entry<String, String> e : scan.modules.entrySet()) {
            message(String.format("    Modul %-18s Salt: %s",
                    e.getKey(), shortHex(e.getValue())));
        }
        message("  e_perbackupkey: " + (scan.ePerBackupKey != null ? "ja" : "NEIN")
                + " | pwkey_salt: " + (scan.pwKeySalt != null ? "ja" : "NEIN"));

        // --- Media-Index (eigene IV pro Mediendatei) --------------------
        message("=== Media-Index ===");
        try {
            mediaIndex = MediaIndex.scan(backupRoot);
            message("  Multimedia-XML gefunden: " + mediaIndex.sourceFiles().size()
                    + " | IVs: " + mediaIndex.size());
            for (String src : mediaIndex.sourceFiles()) {
                message("    " + src);
            }
        } catch (IOException e) {
            message("  Media-Index nicht lesbar: " + e.getMessage());
        }

        // --- Tiefensuche nach fehlenden Index-Bloecken -------------------
        // Die info.xml kann abgeschnitten sein. Dann fehlt die
        // Indexzeile eines Moduls - und damit sein encMsgV3. Der Wert
        // kann aber an anderer Stelle im Backup liegen. Deshalb wird
        // das ganze Backup blockweise nach Hex-Bloecken durchsucht.
        if (deepSearch) {
            message("=== Tiefensuche nach Index-Bloecken ===");
            HexBlobScanner deep = new HexBlobScanner();
            try {
                HexBlobScanner.Result deepResult = deep.scan(backupRoot,
                        new java.util.LinkedHashSet<>(), null);
                int added = 0;
                for (String blob : deepResult.blobs) {
                    if (scan.blobPool.stream().noneMatch(b -> b.equalsIgnoreCase(blob))) {
                        scan.blobPool.add(blob);
                        added++;
                    }
                }
                message(String.format("  %d Dateien durchsucht, %.1f MB gelesen, "
                                + "%d Bloecke, davon %d neu",
                        deepResult.filesScanned,
                        deepResult.bytesScanned / (1024.0 * 1024.0),
                        deepResult.blobs.size(), added));
            } catch (IOException e) {
                message("  Tiefensuche fehlgeschlagen: " + e.getMessage());
            }
        }

        // --- Schluessel-Kandidaten --------------------------------------
        // WICHTIG: das kommt NACH der Tiefensuche. Die dort gefundenen
        // Bloecke koennen die fehlenden encMsgV3-Werte der abgeschnittenen
        // info.xml sein - ohne sie ist das betroffene Modul nicht
        // entschluesselbar.
        CandidateBuilder builder = new CandidateBuilder();
        boolean[] passwordOk = {true};
        List<KeyCandidate> candidates = builder.build(password, scan, passwordOk);
        builder.log().forEach(this::message);
        message("  Schluessel-Kandidaten: " + candidates.size());

        if (candidates.isEmpty()) {
            message("ERROR: kein Schluessel ableitbar");
            message("  Es fehlt entweder das Passwort oder e_perbackupkey/pwkey_salt");
            message("  UND alle Salt-Bloecke.");
            return summary;
        }
        if (!passwordOk[0]) {
            message("WARNUNG: der GCM-Tag des bkey passt nicht.");
            message("  Das Passwort ist vermutlich falsch ODER das Backup nutzt");
            message("  ein anderes Schema. Es werden trotzdem alle Kandidaten");
            message("  durchprobiert - der Klartext kann auch ohne passendes");
            message("  Tag stimmen.");
        }

        // Der bkey wird auch fuer den Media-Key gebraucht
        // (SHA256(bkey)[0:16]).
        if (scan.ePerBackupKey != null && scan.pwKeySalt != null) {
            try {
                setBkey(Crypto.deriveBkey(password,
                        CandidateBuilder.hexToBytes(scan.ePerBackupKey),
                        CandidateBuilder.hexToBytes(scan.pwKeySalt)));
            } catch (Exception e) {
                message("  bkey fuer Media-Key nicht ableitbar: " + e.getMessage());
            }
        }

        // --- Nutzdaten sammeln ------------------------------------------
        List<Path> payloads = IndexScanner.collectPayloadFiles(backupRoot);
        summary.total = payloads.size();
        message("=== Entschluesselung (" + payloads.size() + " Dateien) ===");

        Files.createDirectories(outputRoot);

        // --- Datei fuer Datei -------------------------------------------
        int index = 0;
        for (Path p : payloads) {
            index++;
            if (index % 25 == 0 || index == payloads.size()) {
                listener.onProgress(index, payloads.size());
            }

            try {
                recoverOne(p, candidates, summary);
            } catch (IOException e) {
                summary.failed++;
                summary.failures.add(p + " - " + e.getMessage());
                listener.onFailed(p.toString(), e.getMessage());
            }
        }

        listener.onProgress(summary.total, summary.total);
        return summary;
    }

    /**
     * Versucht, eine einzelne Datei zu entschluesseln.
     *
     * <p>Ablauf je Kandidat:
     * <ol>
     *   <li>Die ersten 4 KB entschluesseln und die Dateisignatur pruefen.</li>
     *   <li>Bei Treffer die Datei gestreamt in die Zieldatei schreiben.</li>
     *   <li>Bei Schema B den GCM-Tag separat verifizieren.</li>
     * </ol>
     */
    private void recoverOne(Path p, List<KeyCandidate> candidates, Summary summary)
            throws IOException {

        // Kandidaten mit passendem Modul zuerst, danach der Rest.
        List<KeyCandidate> ordered = orderCandidates(p, candidates);

        // Media-Kandidat: eigene IV aus der Multimedia-XML, Key =
        // SHA256(bkey)[0:16]. Der muss VOR den Modul-Kandidaten
        // probiert werden, weil eine Mediendatei zu keinem Modul
        // gehoert und sonst nie getroffen wuerde.
        KeyCandidate mediaCandidate = buildMediaCandidate(p);
        if (mediaCandidate != null) {
            ordered.add(0, mediaCandidate);
        }

        for (KeyCandidate candidate : ordered) {
            boolean isB = "B".equals(candidate.schema());
            boolean hasTag = isB;

            // 1) Signaturprobe
            byte[] probe;
            try (InputStream in = Files.newInputStream(p)) {
                byte[] head = new byte[SIGNATURE_PROBE];
                int total = 0;
                int n;
                while (total < head.length && (n = in.read(head, total, head.length - total)) > 0) {
                    total += n;
                }
                if (total == 0) {
                    continue;
                }
                byte[] raw = java.util.Arrays.copyOf(head, total);
                probe = isB
                        ? Crypto.decryptGcm(candidate.key(), candidate.iv(), raw, false)
                        : Crypto.decryptCtr(candidate.key(), candidate.iv(), raw);
            } catch (IOException e) {
                throw e;
            }
            if (probe == null) {
                continue;
            }
            String extension = Signatures.detect(probe);
            if (extension == null) {
                continue;
            }

            // 2) Zielpfad bestimmen
            Path target = targetFor(p, extension);

            // 3) Datei gestreamt entschluesseln
            long fileSize = Files.size(p);
            // Bei Schema B steht der GCM-Tag (16 Byte) am Dateiende und
            // gehoert NICHT zum Chiffrat.
            long cipherLen = isB ? Math.max(0, fileSize - Crypto.GCM_TAG_LEN) : fileSize;

            boolean authenticated = false;
            try (InputStream in = Files.newInputStream(p);
                 OutputStream out = Files.newOutputStream(target)) {
                if (isB) {
                    Crypto.decryptGcmStream(candidate.key(), candidate.iv(),
                            in, out, cipherLen, CHUNK);
                } else {
                    Crypto.decryptCtrStream(candidate.key(), candidate.iv(),
                            in, out, CHUNK);
                }
            } catch (IOException e) {
                Files.deleteIfExists(target);
                throw e;
            }

            // 4) Authentizitaet separat pruefen (Schema B)
            if (isB) {
                authenticated = verifyTagStreaming(p, candidate, cipherLen);
            }

            summary.recovered++;
            summary.byExtension.merge(extension, 1, Integer::sum);
            listener.onRecovered(p.toString(), target.toString(), extension,
                    candidate.schema(), authenticated);
            return;
        }

        summary.failed++;
        summary.failures.add(p + " - nicht entschluesselbar");
        listener.onFailed(p.toString(), "nicht entschluesselbar");
    }

    /**
     * Prueft den GCM-Tag einer Datei, ohne sie vollstaendig zu laden.
     *
     * <p>Bei einer durch den Backup-Abbruch verkuerzten Datei passt der
     * Tag nicht - der Klartext ist aber trotzdem gueltig und wurde
     * bereits gerettet. In dem Fall wird "nicht authentifiziert"
     * gemeldet.
     */
    private boolean verifyTagStreaming(Path p, KeyCandidate candidate, long cipherLen) {
        try (InputStream in = Files.newInputStream(p)) {
            long skip = cipherLen;
            while (skip > 0) {
                long r = in.skip(skip);
                if (r <= 0) {
                    break;
                }
                skip -= r;
            }
            byte[] tag = in.readAllBytes();
            if (tag.length < Crypto.GCM_TAG_LEN) {
                return false;
            }
            try (InputStream in2 = Files.newInputStream(p)) {
                return Crypto.verifyGcmTagStream(candidate.key(), candidate.iv(),
                        in2, cipherLen, tag);
            }
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Baut den Media-Kandidaten fuer eine Datei.
     *
     * <p>Mediendateien (Audio/Foto/Video) werden nicht ueber
     * {@code encMsgV3} abgeleitet, sondern ueber:
     * <ul>
     *   <li>Key = {@code SHA256(bkey)[0:16]} (AES-128)</li>
     *   <li>IV  = die Datei eigene IV aus der Multimedia-XML</li>
     * </ul>
     *
     * <p>Die IV fehlt, wenn die Multimedia-XML nicht im Backup liegt -
     * dann ist die Datei nicht entschluesselbar.
     *
     * @return der Kandidat oder null, wenn keine IV vorliegt
     */
    private KeyCandidate buildMediaCandidate(Path p) {
        if (mediaIndex == null || mediaIndex.size() == 0) {
            return null;
        }
        String ivHex = mediaIndex.ivFor(p, backupRoot);
        if (ivHex == null) {
            return null;
        }
        try {
            byte[] iv = CandidateBuilder.hexToBytes(ivHex);
            if (iv.length < 16) {
                return null;
            }
            // Der bkey wird aus Passwort + e_perbackupkey/pwkey_salt
            // abgeleitet. Ohne diese Werte gibt es keinen Media-Key.
            String bkey = cachedBkey;
            if (bkey == null) {
                return null;
            }
            byte[] key = Crypto.deriveMediaKey(bkey);
            return new KeyCandidate("M(Media)", key, iv, null);
        } catch (Exception e) {
            return null;
        }
    }

    /** Der aus dem Scan gespeicherte bkey (wird im Lauf gesetzt). */
    private String cachedBkey;

    /** Setzt den bkey nach der Index-Auswertung. */
    private void setBkey(String bkey) {
        this.cachedBkey = bkey;
    }

    /**
     * Sortiert die Kandidaten: passendes Modul zuerst.
     *
     * <p>Der Modulname wird aus dem Dateinamen abgeleitet
     * ({@code calllog.db} -&gt; {@code calllog}).
     */
    private List<KeyCandidate> orderCandidates(Path p, List<KeyCandidate> candidates) {
        String file = p.getFileName().toString().toLowerCase(Locale.ROOT);
        int dot = file.lastIndexOf('.');
        String stem = dot > 0 ? file.substring(0, dot) : file;

        List<KeyCandidate> matching = new ArrayList<>();
        List<KeyCandidate> rest = new ArrayList<>();
        for (KeyCandidate c : candidates) {
            String mod = c.module();
            if (mod == null || "(allgemein)".equals(mod)) {
                rest.add(c);
            } else if (stem.contains(mod.toLowerCase(Locale.ROOT))
                    || mod.toLowerCase(Locale.ROOT).contains(stem)) {
                matching.add(c);
            } else {
                rest.add(c);
            }
        }
        List<KeyCandidate> out = new ArrayList<>(matching);
        out.addAll(rest);
        return out;
    }

    /** Zielpfad fuer eine gerettete Datei. */
    private Path targetFor(Path p, String extension) {
        Path rel = backupRoot.relativize(p);
        String name = rel.getFileName().toString();
        int dot = name.lastIndexOf('.');
        String stem = dot > 0 ? name.substring(0, dot) : name;
        Path target = outputRoot.resolve(rel.getParent() == null
                ? Path.of(stem + extension)
                : rel.getParent().resolve(stem + extension));
        try {
            Files.createDirectories(target.getParent());
        } catch (IOException e) {
            // Wird beim Schreiben erneut gemeldet.
        }
        return target;
    }

    private static String shortHex(String hex) {
        if (hex == null || hex.isBlank()) {
            return "(leer)";
        }
        String h = hex.trim();
        return h.length() <= 20 ? h : h.substring(0, 20) + "...";
    }

    private void message(String m) {
        listener.onMessage(m);
    }
}
