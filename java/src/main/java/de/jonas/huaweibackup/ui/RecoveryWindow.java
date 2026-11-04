package de.jonas.huaweibackup.ui;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Die grafische Oberflaeche des Recovery-Tools.
 *
 * <p>Aufbau:
 * <ul>
 *   <li>Eingabefeld fuer den <b>Pfad zum Backup</b> (mit Auswahl-Knopf)</li>
 *   <li>maskiertes <b>Passwortfeld</b></li>
 *   <li>Eingabefeld fuer den <b>Ausgabepfad</b> (mit Auswahl-Knopf)</li>
 *   <li><b>Start</b>-Knopf - ein eigener Analyse-Schritt ist nicht
 *       noetig, der Lauf meldet alles mit</li>
 *   <li><b>Fortschrittsanzeige</b> plus Protokollfenster, das zeigt, was
 *       erfolgreich war und was nicht</li>
 * </ul>
 */
public final class RecoveryWindow extends JFrame {

    private final JTextField backupField = new JTextField();
    private final JPasswordField passwordField = new JPasswordField();
    private final JTextField outputField = new JTextField();
    private final JButton startButton = new JButton("Start");
    private final JProgressBar progressBar = new JProgressBar();
    private final JLabel statusLabel = new JLabel("Bereit");
    private final JTextArea logArea = new JTextArea();

    /** Zeilen der Ergebnisliste: Datei, Ergebnis, Typ. */
    private final DefaultListModel<String> resultModel = new DefaultListModel<>();
    private final JList<String> resultList = new JList<>(resultModel);

    public RecoveryWindow() {
        super("Huawei-Backup-Recovery");
        setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        setSize(940, 680);
        setLocationRelativeTo(null);

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                // Der Lauf laeuft im Hintergrund weiter; nur das Fenster
                // wird geschlossen.
            }
        });

        setLayout(new BorderLayout(8, 8));

        // --- Eingabebereich --------------------------------------------
        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 6, 4, 6);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0;
        gbc.gridy = 0;
        form.add(new JLabel("Backup-Pfad:"), gbc);
        gbc.gridx = 1;
        gbc.gridwidth = 2;
        gbc.weightx = 1;
        form.add(backupField, gbc);
        gbc.gridx = 3;
        gbc.gridwidth = 1;
        gbc.weightx = 0;
        form.add(browseButton("Backup wählen", backupField, true), gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        form.add(new JLabel("Passwort:"), gbc);
        gbc.gridx = 1;
        gbc.gridwidth = 2;
        gbc.weightx = 1;
        form.add(passwordField, gbc);

        gbc.gridx = 0;
        gbc.gridy = 2;
        form.add(new JLabel("Ausgabe-Pfad:"), gbc);
        gbc.gridx = 1;
        gbc.gridwidth = 2;
        gbc.weightx = 1;
        form.add(outputField, gbc);
        gbc.gridx = 3;
        gbc.gridwidth = 1;
        gbc.weightx = 0;
        form.add(browseButton("Ausgabe wählen", outputField, false), gbc);

        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 3;
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        actions.add(startButton);
        actions.add(new JLabel("Die Berechnung läuft lokal auf diesem Rechner."));
        form.add(actions, gbc);

        // Standardpfade aus dem letzten Lauf
        String home = System.getProperty("user.home");
        outputField.setText(home + File.separator + "Huawei-Recovery");

        add(form, BorderLayout.NORTH);

        // --- Mitte: Protokoll + Ergebnisse ------------------------------
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(logArea),
                new JScrollPane(resultList));
        split.setResizeWeight(0.55);
        add(split, BorderLayout.CENTER);

        // --- Fortschritt -----------------------------------------------
        JPanel status = new JPanel(new BorderLayout(6, 0));
        status.setBorder(BorderFactory.createEmptyBorder(0, 6, 6, 6));
        progressBar.setStringPainted(true);
        status.add(progressBar, BorderLayout.CENTER);
        status.add(statusLabel, BorderLayout.EAST);
        add(status, BorderLayout.SOUTH);

        startButton.addActionListener(e -> start());

        // Vorgabe: das erste Verzeichnis der letzten verwendet Pfade
        setVisible(true);
    }

    /** Knopf zur Auswahl eines Verzeichnisses. */
    private JButton browseButton(String label, JTextField target, boolean forInput) {
        JButton button = new JButton(label);
        button.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            chooser.setDialogTitle(label);
            if (!target.getText().isBlank()) {
                File current = new File(target.getText());
                if (current.isDirectory()) {
                    chooser.setCurrentDirectory(current);
                }
            }
            if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                target.setText(chooser.getSelectedFile().getAbsolutePath());
            }
        });
        return button;
    }

    /** Startet die Recovery im Hintergrund. */
    private void start() {
        String backup = backupField.getText().trim();
        String output = outputField.getText().trim();
        char[] password = passwordField.getPassword();

        if (backup.isEmpty()) {
            showError("Bitte den Pfad zum Backup angeben.");
            return;
        }
        if (output.isEmpty()) {
            showError("Bitte den Pfad zur Ausgabe angeben.");
            return;
        }
        File backupDir = new File(backup);
        if (!backupDir.isDirectory()) {
            showError("Das Backup-Verzeichnis existiert nicht:\n" + backup);
            return;
        }
        if (password.length == 0) {
            showError("Bitte das Backup-Passwort angeben.");
            return;
        }

        startButton.setEnabled(false);
        statusLabel.setText("läuft …");
        progressBar.setValue(0);
        progressBar.setIndeterminate(false);
        resultModel.clear();

        // Passwort sofort aus dem Feld entfernen
        passwordField.setText("");

        new Thread(() -> {
            String pass = new String(password);
            java.util.Arrays.fill(password, '\0');

            List<String> failures = new ArrayList<>();

            try {
                de.jonas.huaweibackup.core.RecoveryEngine engine =
                        new de.jonas.huaweibackup.core.RecoveryEngine(
                                Path.of(backup), Path.of(output), pass,
                                new de.jonas.huaweibackup.core.RecoveryEngine.Listener() {
                                    @Override
                                    public void onProgress(int done, int total) {
                                        SwingUtilities.invokeLater(() -> {
                                            progressBar.setMaximum(Math.max(total, 1));
                                            progressBar.setValue(done);
                                            progressBar.setString(done + " / " + total);
                                        });
                                    }

                                    @Override
                                    public void onIndexProgress(int done, int total, String phase) {
                                        SwingUtilities.invokeLater(() -> {
                                            progressBar.setMaximum(Math.max(total, 1));
                                            progressBar.setValue(done);
                                            progressBar.setString(phase + " " + done + " / " + total);
                                        });
                                    }

                                    @Override
                                    public void onRecovered(String source, String target,
                                                            String extension, String schema,
                                                            boolean authenticated) {
                                        SwingUtilities.invokeLater(() -> {
                                            resultModel.addElement(String.format("OK   %-42s -> %s%s",
                                                    shorten(source), extension,
                                                    authenticated ? " [authentifiziert]"
                                                            : (schema.equals("B")
                                                                ? " [unvollständig]" : "")));
                                        });
                                    }

                                    @Override
                                    public void onFailed(String source, String reason) {
                                        failures.add(source + " - " + reason);
                                        SwingUtilities.invokeLater(() ->
                                                resultModel.addElement(String.format(
                                                        "FEHL %-42s %s", shorten(source), reason)));
                                    }

                                    @Override
                                    public void onMessage(String message) {
                                        SwingUtilities.invokeLater(() -> {
                                            logArea.append(message + "\n");
                                            logArea.setCaretPosition(logArea.getDocument().getLength());
                                        });
                                    }
                                });

                de.jonas.huaweibackup.core.RecoveryEngine.Summary summary = engine.run();

                StringBuilder sb = new StringBuilder();
                sb.append("\n=== Ergebnis ===\n");
                sb.append("  entschlüsselt: ").append(summary.recovered);
                sb.append(" | nicht entschlüsselbar: ").append(summary.failed).append('\n');
                sb.append("  Ausgabe: ").append(output).append('\n');

                SwingUtilities.invokeLater(() -> {
                    logArea.append(sb.toString());
                    statusLabel.setText(summary.recovered + " gerettet");
                    startButton.setEnabled(true);
                    if (summary.recovered == 0) {
                        showError("Keine Datei ließ sich entschlüsseln.\n\n"
                                + "Mögliche Gründe:\n"
                                + "  - falsches Passwort\n"
                                + "  - beide Schlüssel-Arten fehlen "
                                + "(e_perbackupkey + alle Salts)\n"
                                + "  - anderes Verschlüsselungsverfahren");
                    }
                });
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    logArea.append("\nFEHLER: " + e.getMessage() + "\n");
                    statusLabel.setText("Fehler");
                    startButton.setEnabled(true);
                    showError("Der Lauf ist fehlgeschlagen:\n" + e.getMessage());
                });
            }
        }, "recovery").start();
    }

    private static String shorten(String path) {
        if (path.length() <= 42) {
            return path;
        }
        return "…" + path.substring(path.length() - 41);
    }

    private void showError(String message) {
        JOptionPane.showMessageDialog(this, message, "Recovery",
                JOptionPane.ERROR_MESSAGE);
    }

    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {
            // Der Standard-Look-and-Feel ist auch in Ordnung.
        }
        SwingUtilities.invokeLater(() -> new RecoveryWindow().setVisible(true));
    }
}
