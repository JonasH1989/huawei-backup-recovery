package de.jonas.huaweibackup.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
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
 */
public final class RecoveryEngine {

    /** Rueckmeldung an die Oberflaeche. */
    public interface Listener {
        /** Fortschritt: {@code done} von {@code total} Dateien bearbeitet. */
        void onProgress(int done, int total);

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
        message("  e_perbackupkey: " + (scan.ePerBackupKey != null ? "ja" : "NEIN")
                + " | pwkey_salt: " + (scan.pwKeySalt != null ? "ja" : "NEIN"));

        // --- Schluessel-Kandidaten --------------------------------------
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

        // --- Nutzdaten sammeln ------------------------------------------
        List<Path> payloads = IndexScanner.collectPayloadFiles(backupRoot);
        summary.total = payloads.size();
        message("=== Entschluesselung (" + payloads.size() + " Dateien) ===");

        Files.createDirectories(outputRoot);

        // --- Datei fuer Datei -------------------------------------------
        int index = 0;
        for (Path p : payloads) {
            index++;
            if (index % 50 == 0) {
                listener.onProgress(index, payloads.size());
            }

            byte[] raw;
            try {
                raw = Files.readAllBytes(p);
            } catch (IOException e) {
                summary.failed++;
                summary.failures.add(p + " - " + e.getMessage());
                listener.onFailed(p.toString(), e.getMessage());
                continue;
            }

            byte[] head = new byte[Math.min(4096, raw.length)];
            System.arraycopy(raw, 0, head, 0, head.length);

            boolean done = false;
            for (KeyCandidate candidate : candidates) {
                // Schema B: GCM-Tag steht am Dateiende -> muss abgetrennt
                // werden, sonst haengt 16 Byte Muell an der Datei.
                boolean isB = "B".equals(candidate.schema());
                boolean hasTag = isB;

                // Signaturpruefung am Dateianfang (ohne Tag).
                byte[] probe = isB
                        ? Crypto.decryptGcm(candidate.key(), candidate.iv(), head, false)
                        : Crypto.decryptCtr(candidate.key(), candidate.iv(), head);
                if (probe == null) {
                    continue;
                }
                String extension = Signatures.detect(probe);
                if (extension == null) {
                    continue;
                }

                // Vollstaendig entschluesseln.
                byte[] full = isB
                        ? Crypto.decryptGcm(candidate.key(), candidate.iv(), raw, hasTag)
                        : Crypto.decryptCtr(candidate.key(), candidate.iv(), raw);
                if (full == null) {
                    continue;
                }

                // Integritaet pruefen (Schema B). Bei einer durch den
                // Backup-Abbruch verkuerzten Datei passt der Tag nicht -
                // der Klartext ist aber trotzdem gueltig und wird gerettet.
                Boolean authenticated = null;
                if (isB) {
                    authenticated = Crypto.verifyGcmTag(candidate.key(), candidate.iv(), raw);
                }

                Path rel = backupRoot.relativize(p);
                String name = rel.getFileName().toString();
                int dot = name.lastIndexOf('.');
                String stem = dot > 0 ? name.substring(0, dot) : name;
                Path target = outputRoot.resolve(rel.getParent() == null
                        ? Path.of(stem + extension)
                        : rel.getParent().resolve(stem + extension));

                try {
                    Files.createDirectories(target.getParent());
                    Files.write(target, full);
                } catch (IOException e) {
                    summary.failed++;
                    summary.failures.add(p + " - " + e.getMessage());
                    listener.onFailed(p.toString(), e.getMessage());
                    done = true;
                    break;
                }

                summary.recovered++;
                summary.byExtension.merge(extension, 1, Integer::sum);
                listener.onRecovered(p.toString(), target.toString(), extension,
                        candidate.schema(), Boolean.TRUE.equals(authenticated));
                done = true;
                break;
            }

            if (!done) {
                summary.failed++;
                summary.failures.add(p + " - nicht entschluesselbar");
                listener.onFailed(p.toString(), "nicht entschluesselbar");
            }
        }

        listener.onProgress(summary.total, summary.total);
        return summary;
    }

    private void message(String m) {
        listener.onMessage(m);
    }
}
