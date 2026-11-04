package de.jonas.huaweibackup;

import de.jonas.huaweibackup.core.RecoveryEngine;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Roundtrip-Test: synthetisches Backup erzeugen, wiederherstellen,
 * bytegenau gegen das Original vergleichen.
 *
 * <p>Ein Test, der nur prueft "die Datei laesst sich oeffnen", ist kein
 * Test. Deshalb wird jedes Byte verglichen.
 *
 * <p>Szenarien:
 * <ul>
 *   <li>schema_a          - Schema A, intakter Index</li>
 *   <li>schema_a_corrupt  - Schema A, Index mitten im Attribut abgeschnitten</li>
 *   <li>schema_b          - Schema B, intakter Index</li>
 *   <li>schema_b_corrupt  - Schema B, Index mitten im Attribut abgeschnitten</li>
 * </ul>
 */
public final class RoundtripTest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        Path base = Path.of(args.length > 0 ? args[0] : "/tmp/hw_java_test");
        if (Files.exists(base)) {
            deleteRecursively(base);
        }
        Files.createDirectories(base);

        TestBackupBuilder.checkSignatures();
        System.out.println("Signatur-Erkennung: OK");

        Map<String, byte[]> originals = TestBackupBuilder.payloads();

        runCase(base, "schema_a", false, originals);
        runCase(base, "schema_a_corrupt", true, originals);
        runCase(base, "schema_b", false, originals);
        runCase(base, "schema_b_corrupt", true, originals);

        System.out.println();
        if (failures == 0) {
            System.out.println("ALLE SZENARIEN BYTEGENAU IDENTISCH");
        } else {
            System.out.println("FEHLER: " + failures + " Abweichung(en)");
            System.exit(1);
        }
    }

    private static void runCase(Path base, String name, boolean corrupt,
                                Map<String, byte[]> originals) throws Exception {
        Path backup = base.resolve(name);
        if (name.startsWith("schema_a")) {
            TestBackupBuilder.buildSchemaA(backup, corrupt);
        } else {
            TestBackupBuilder.buildSchemaB(backup, corrupt);
        }

        Path output = base.resolve(name + "_out");
        List<String> messages = new ArrayList<>();

        RecoveryEngine engine = new RecoveryEngine(
                backup, output, TestBackupBuilder.PASSWORD,
                new RecoveryEngine.Listener() {
                    @Override
                    public void onProgress(int done, int total) {
                    }

                    @Override
                    public void onRecovered(String source, String target, String extension,
                                            String schema, boolean authenticated) {
                    }

                    @Override
                    public void onFailed(String source, String reason) {
                    }

                    @Override
                    public void onMessage(String message) {
                        messages.add(message);
                    }
                });

        RecoveryEngine.Summary summary = engine.run();

        // --- Bytegenauer Vergleich ------------------------------------
        int identical = 0;
        int different = 0;
        for (Map.Entry<String, byte[]> e : originals.entrySet()) {
            String expectedExt = e.getKey().substring(e.getKey().lastIndexOf('.'));
            String stem = e.getKey().substring(0, e.getKey().lastIndexOf('.'));

            Path found = null;
            for (String ext : new String[]{".jpg", ".png", ".mp4", ".db", ".xml", ".zip"}) {
                Path candidate = find(output, baseName(stem) + ext);
                if (candidate != null) {
                    found = candidate;
                    break;
                }
            }
            if (found == null) {
                different++;
                System.out.println("  FEHLT: " + e.getKey());
                failures++;
                continue;
            }
            byte[] got = Files.readAllBytes(found);
            if (java.util.Arrays.equals(got, e.getValue())) {
                identical++;
            } else {
                different++;
                failures++;
                System.out.println("  ABWEICHUNG: " + found.getFileName()
                        + " (" + got.length + " vs. " + e.getValue().length + " Byte)");
            }
        }

        System.out.printf("  %-20s %d identisch, %d abweichend "
                        + "(entschlüsselt=%d, fehlgeschlagen=%d)%n",
                name, identical, different, summary.recovered, summary.failed);
    }

    /** Nur der Dateiname ohne Verzeichnis und ohne Endung. */
    private static String baseName(String path) {
        int slash = path.lastIndexOf('/');
        String name = slash >= 0 ? path.substring(slash + 1) : path;
        return name;
    }

    /** Sucht eine Datei im Ausgabeverzeichnis. */
    private static Path find(Path root, String fileName) throws Exception {
        try (var stream = Files.walk(root)) {
            return stream.filter(Files::isRegularFile)
                    .filter(p -> p.getFileName().toString().equals(fileName))
                    .findFirst()
                    .orElse(null);
        }
    }

    private static void deleteRecursively(Path path) throws Exception {
        if (!Files.exists(path)) {
            return;
        }
        try (var stream = Files.walk(path)) {
            stream.sorted((a, b) -> b.getNameCount() - a.getNameCount())
                    .forEach(p -> {
                        try {
                            Files.deleteIfExists(p);
                        } catch (Exception ignored) {
                            // nicht kritisch
                        }
                    });
        }
    }
}
