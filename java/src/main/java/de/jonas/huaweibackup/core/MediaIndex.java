package de.jonas.huaweibackup.core;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Liest die Multimedia-Indizes eines Backups.
 *
 * <p>Huawei legt fuer verschluesselte Mediendateien eine eigene
 * XML-Datei an, die je Datei eine <b>eigene IV</b> enthaelt:
 *
 * <pre>
 * &lt;Multimedia&gt;
 *   &lt;File&gt;
 *     &lt;Path&gt;/Sounds/AUD-20261026-WA0001.mp3&lt;/Path&gt;
 *     &lt;Iv&gt;00112233445566778899aabbccddeeff&lt;/Iv&gt;
 *   &lt;/File&gt;
 * &lt;/Multimedia&gt;
 * </pre>
 *
 * <p>Diese Datei liegt im selben Ordner wie die verschluesselten
 * Mediendateien. Der Schluessel fuer diese Dateien ist
 * {@code SHA256(bkey)[0:16]} (AES-128) im CTR-Modus - <b>kein</b>
 * PBKDF2 wie bei den Datenbankmodulen.
 *
 * <p>Ohne diese XML ist die Datei nicht entschluesselbar: die IV
 * laesst sich nicht aus der Datei ableiten. Deshalb wird sie hier
 * gesucht und jedes gefundene IV als Schluessel-Kandidat
 * weitergegeben.
 *
 * <p>Referenz: {@code RealityNet/kobackupdec}, Funktion
 * {@code parse_generic_xml}.
 */
public final class MediaIndex {

    /** XML-Wurzelelement der Multimedia-Indizes. */
    private static final Pattern MULTIMEDIA_ROOT =
            Pattern.compile("<Multimedia\\b", Pattern.CASE_INSENSITIVE);

    /** {@code <Path>…</Path>} innerhalb eines {@code <File>}-Blocks. */
    private static final Pattern PATH_TAG =
            Pattern.compile("<Path>\\s*(.*?)\\s*</Path>", Pattern.DOTALL);

    /** {@code <Iv>…</Iv>} innerhalb eines {@code <File>}-Blocks. */
    private static final Pattern IV_TAG =
            Pattern.compile("<Iv>\\s*([0-9a-fA-F]+)\\s*</Iv>", Pattern.DOTALL);

    /** Maximale Groesse einer Multimedia-XML. */
    private static final long MAX_XML_BYTES = 32L * 1024 * 1024;

    /** Normalisierter Pfad -> IV (Hex). */
    private final Map<String, String> pathToIv = new LinkedHashMap<>();

    /** Liste der gefundenen XML-Dateien (fuer die Protokoll-Ausgabe). */
    private final List<String> sourceFiles = new ArrayList<>();

    /**
     * Durchsucht das Backup nach Multimedia-Indizes.
     *
     * @param root Wurzelverzeichnis des Backups
     * @throws IOException bei Zugriffsproblemen
     */
    public static MediaIndex scan(Path root) throws IOException {
        MediaIndex index = new MediaIndex();
        for (Path p : IndexScanner.listFiles(root)) {
            if (!p.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".xml")) {
                continue;
            }
            try {
                if (Files.size(p) > MAX_XML_BYTES) {
                    continue;
                }
                String xml = readText(p);
                if (!MULTIMEDIA_ROOT.matcher(xml).find()) {
                    continue;
                }
                index.parse(xml);
                index.sourceFiles.add(p.toString());
            } catch (IOException e) {
                // Datei nicht lesbar - ueberspringen.
            }
        }
        return index;
    }

    /**
     * Parst den Inhalt einer Multimedia-XML.
     *
     * <p>Die Datei kann auch abgeschnitten sein. Deshalb wird nicht
     * auf eine vollstaendige Struktur vertraut, sondern jedes
     * {@code <File>}-Segment einzeln ausgewertet: ein Block mit
     * {@code <Path>} und {@code <Iv>} ist auch dann nutzbar, wenn
     * {@code <Iv>} am Ende abgeschnitten wurde.
     */
    private void parse(String xml) {
        int pos = 0;
        while (true) {
            int start = xml.indexOf("<File", pos);
            if (start < 0) {
                break;
            }
            int end = xml.indexOf("</File>", start);
            String block = end < 0 ? xml.substring(start) : xml.substring(start, end);
            pos = end < 0 ? xml.length() : end + 7;

            Matcher pm = PATH_TAG.matcher(block);
            if (!pm.find()) {
                continue;
            }
            String path = pm.group(1).trim();
            if (path.isEmpty()) {
                continue;
            }
            Matcher vm = IV_TAG.matcher(block);
            if (!vm.find()) {
                // Abgeschnittene IV - die Datei bleibt unentschluesselbar.
                continue;
            }
            String iv = vm.group(1).trim();
            if (iv.length() < 32) {
                continue;
            }
            pathToIv.put(normalize(path), iv);
        }
    }

    /**
     * Liefert die IV zu einem Pfad.
     *
     * <p>Der Pfad wird in mehreren Schreibweisen gesucht, weil der
     * absolute Pfad aus der XML und der relative Pfad im Backup
     * selten identisch sind.
     *
     * @param file die Datei im Backup
     * @return IV (Hex) oder null
     */
    public String ivFor(Path file, Path backupRoot) {
        List<String> candidates = new ArrayList<>();
        String rel = null;
        try {
            rel = backupRoot.relativize(file).toString();
        } catch (IllegalArgumentException e) {
            rel = file.toString();
        }
        candidates.add(normalize(rel));
        candidates.add(normalize(file.getFileName().toString()));
        // Ohne Suffix (der Index nennt oft den Namen ohne Endung).
        String name = file.getFileName().toString();
        int dot = name.lastIndexOf('.');
        if (dot > 0) {
            candidates.add(normalize(name.substring(0, dot)));
        }
        String parent = file.getParent() == null ? "" : file.getParent().getFileName().toString();
        if (!parent.isEmpty()) {
            candidates.add(normalize(parent + "/" + name));
        }

        for (String c : candidates) {
            String iv = pathToIv.get(c);
            if (iv != null) {
                return iv;
            }
        }
        // Notfalls ueber das Dateiende der Pfadliste stichprobenartig suchen.
        for (Map.Entry<String, String> e : pathToIv.entrySet()) {
            String key = e.getKey();
            if (!key.isEmpty() && (key.endsWith("/" + normalize(file.getFileName().toString()))
                    || key.equals(normalize(file.getFileName().toString())))) {
                return e.getValue();
            }
        }
        return null;
    }

    /** Alle gefundenen Pfad->IV-Paare. */
    public Map<String, String> entries() {
        return pathToIv;
    }

    /** Anzahl gefundener IVs. */
    public int size() {
        return pathToIv.size();
    }

    /** Die XML-Dateien, aus denen die IVs stammen. */
    public List<String> sourceFiles() {
        return sourceFiles;
    }

    /**
     * Normalisiert Pfade: Trennzeichen vereinheitlichen, fuehrende
     * Trenner und {@code ./} entfernen, Kleinschreibung.
     */
    private static String normalize(String p) {
        String s = p.replace('\\', '/').trim();
        while (s.startsWith("./")) {
            s = s.substring(2);
        }
        while (s.startsWith("/")) {
            s = s.substring(1);
        }
        return s.toLowerCase(Locale.ROOT);
    }

    /** Liest eine Datei als Text (UTF-8, mit Fallback auf ISO-8859-1). */
    private static String readText(Path p) throws IOException {
        byte[] raw;
        try (InputStream in = Files.newInputStream(p)) {
            raw = in.readAllBytes();
        }
        String s = new String(raw, StandardCharsets.UTF_8);
        // Ein UTF-16-BOM deutet auf eine breitere Kodierung hin.
        if (s.startsWith("\uFEFF")) {
            s = new String(raw, StandardCharsets.UTF_16LE);
        }
        return s;
    }
}
