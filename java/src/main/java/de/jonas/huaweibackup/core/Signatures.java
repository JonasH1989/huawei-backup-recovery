package de.jonas.huaweibackup.core;

/**
 * Dateisignaturen zur Verifikation der Entschluesselung.
 *
 * Nach dem Entschluesseln wird der Anfang des Klartextes geprueft. Erst
 * eine erkannte Signatur gilt als Beweis, dass der Schluessel stimmt -
 * unabhaengig davon, ob der Index noch intakt ist.
 */
public final class Signatures {

    private Signatures() {
    }

    /** Bekannte Magic-Bytes -> Endung. Reihenfolge ist relevant (laengere zuerst). */
    private static final byte[][] MAGICS = {
        {(byte) 0xff, (byte) 0xd8, (byte) 0xff},          // JPEG
        {(byte) 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a}, // PNG
        {0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00}, // SQLite
        {0x52, 0x49, 0x46, 0x46},                          // RIFF (WAV/AVI)
        {(byte) 0x1a, 0x45, (byte) 0xdf, (byte) 0xa3},    // Matroska
        {0x66, 0x4c, 0x61, 0x43},                          // FLAC
        {0x49, 0x44, 0x33},                                // MP3 (ID3)
        {0x3c, 0x3f, 0x78, 0x6d, 0x6c},                    // XML
        {0x50, 0x4b, 0x03, 0x04},                          // ZIP
    };

    private static final String[] EXTS = {
        ".jpg", ".png", ".db", ".riff", ".mkv", ".flac", ".mp3", ".xml", ".zip",
    };

    /** MP4/MOV: 'ftyp' steht bei Byte 4, die Brand bei Byte 8. */
    private static final String[] MP4_BRANDS = {
        "isom", "mp42", "mp41", "avc1", "qt  ", "MSNV", "3gp", "dash",
    };

    /**
     * Erkennt den Dateityp am Klartextanfang.
     *
     * @return die Endung inklusive Punkt, oder null wenn unbekannt
     */
    public static String detect(byte[] head) {
        if (head == null || head.length == 0) {
            return null;
        }
        for (int i = 0; i < MAGICS.length; i++) {
            if (startsWith(head, MAGICS[i])) {
                return EXTS[i];
            }
        }
        // MP4/MOV
        if (head.length >= 12
                && head[4] == 'f' && head[5] == 't' && head[6] == 'y' && head[7] == 'p') {
            String brand = new String(head, 8, 4, java.nio.charset.StandardCharsets.US_ASCII);
            for (String b : MP4_BRANDS) {
                if (b.equals(brand)) {
                    return ".mp4";
                }
            }
            return ".mp4";
        }
        return null;
    }

    private static boolean startsWith(byte[] data, byte[] prefix) {
        if (data.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (data[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }
}
