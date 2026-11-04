package de.jonas.huaweibackup;

import de.jonas.huaweibackup.core.RecoveryEngine;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Headless-Lauf der Recovery-Engine.
 *
 * <p>Damit laesst sich exakt das Verhalten des GUI-Tools beobachten,
 * ohne Swing. Aufruf:
 *
 * <pre>
 *   java -cp out de.jonas.huaweibackup.HeadlessRun &lt;backup&gt; &lt;out&gt; [passwort]
 * </pre>
 */
public final class HeadlessRun {

    public static void main(String[] args) throws Exception {
        Path backup = Path.of(args.length > 0 ? args[0] : "/tmp/hw_real");
        Path out = Path.of(args.length > 1 ? args[1] : "/tmp/hw_headless_out");
        String password = args.length > 2 ? args[2] : "";

        Files.createDirectories(out);

        RecoveryEngine engine = new RecoveryEngine(backup, out, password,
                new RecoveryEngine.Listener() {
                    @Override
                    public void onProgress(int done, int total) {
                        System.out.println("  Fortschritt: " + done + "/" + total);
                    }

                    @Override
                    public void onIndexProgress(int done, int total, String phase) {
                    }

                    @Override
                    public void onRecovered(String src, String dst, String ext,
                                            String schema, boolean auth) {
                        System.out.println("  GERETTET: " + src + " -> " + dst
                                + " (" + ext + ", Schema " + schema
                                + (auth ? ", authentifiziert" : "") + ")");
                    }

                    @Override
                    public void onFailed(String src, String reason) {
                        System.out.println("  FEHLGESCHLAGEN: " + src + " - " + reason);
                    }

                    @Override
                    public void onMessage(String msg) {
                        System.out.println(msg);
                    }
                });

        RecoveryEngine.Summary s = engine.run();

        System.out.println();
        System.out.println("=== ERGEBNIS ===");
        System.out.println("  gesamt:       " + s.total);
        System.out.println("  entschluesselt: " + s.recovered);
        System.out.println("  fehlgeschlagen: " + s.failed);
        System.out.println("  nach Typ: " + s.byExtension);
        for (String f : s.failures) {
            System.out.println("   - " + f);
        }
    }
}
