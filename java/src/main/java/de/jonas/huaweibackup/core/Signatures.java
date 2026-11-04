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
        {0x4f, 0x67, 0x67, 0x53},                          // OGG (Vorbis/Opus)
        {0x3c, 0x3f, 0x78, 0x6d, 0x6c},                    // XML
        {0x50, 0x4b, 0x03, 0x04},                          // ZIP
    };

    private static final String[] EXTS = {
        ".jpg", ".png", ".db", ".riff", ".mkv", ".flac", ".mp3", ".ogg", ".xml", ".zip",
    };

    /** Bitraten in kBit/s, Index = Bitratenfeld. */
    private static final int[] BITRATES = {
        0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0
    };

    /** Abtastraten fuer MPEG 1 in Hz. */
    private static final int[] SAMPLERATES_M1 = {44100, 48000, 32000, 0};

    /** Abtastraten fuer MPEG 2/2.5 in Hz. */
    private static final int[] SAMPLERATES_M2 = {22050, 24000, 16000, 0};

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
        // MP3 ohne ID3-Tag: der MPEG-Frame-Sync beginnt mit 11 Einsen.
        // Wichtig fuer Huawei-Sprachnachrichten, die oft ohne ID3
        // gespeichert werden.
        //
        // WICHTIG: ein einzelner Sync reicht NICHT als Beweis. In
        // Zufallsdaten tritt 0xFFEx alle ~5.600 Byte auf - bei einer
        // 4-KB-Probe waere ein Fehlalarm wahrscheinlich. Deshalb
        // werden mehrere aufeinanderfolgende Frames geprueft.
        if (looksLikeMp3Stream(head)) {
            return ".mp3";
        }
        return null;
    }

    /**
     * Prueft, ob der Anfang eine Folge gueltiger MPEG-Audio-Frames ist.
     *
     * <p>Mindestens drei aufeinanderfolgende Frames muessen an den
     * erwarteten Positionen liegen. Erst das schliesst einen
     * Zufallstreffer aus.
     *
     * @param head Anfang des Klartextes
     * @return true, wenn die Frame-Kette stimmt
     */
    public static boolean looksLikeMp3Stream(byte[] head) {
        if (head == null || head.length < 32) {
            return false;
        }
        // ID3 am Anfang: die Frame-Kette beginnt dahinter.
        int start = 0;
        if (head[0] == 'I' && head[1] == 'D' && head[2] == '3') {
            if (head.length < 10) {
                return false;
            }
            int size = ((head[6] & 0x7f) << 21) | ((head[7] & 0x7f) << 14)
                    | ((head[8] & 0x7f) << 7) | (head[9] & 0x7f);
            start = 10 + size;
            if (start >= head.length) {
                // ID3-Header allein reicht als Beweis.
                return true;
            }
        }
        return countFrames(head, start) >= 3;
    }

    /**
     * Zaehlt aufeinanderfolgende gueltige MPEG-Frames ab Position {@code p}.
     *
     * @return Anzahl der Frames in der Kette
     */
    public static int countFrames(byte[] b, int p) {
        int count = 0;
        while (p + 4 <= b.length && count < 64) {
            if (!isMpegFrameSync(b, p)) {
                break;
            }
            int len = mpegFrameLength(b, p);
            if (len < 4) {
                break;
            }
            count++;
            p += len;
        }
        return count;
    }

    /** Prueft den Sync an einer bestimmten Position. */
    private static boolean isMpegFrameSync(byte[] head, int p) {
        if (p + 4 > head.length) {
            return false;
        }
        int b0 = head[p] & 0xff;
        int b1 = head[p + 1] & 0xff;
        int b2 = head[p + 2] & 0xff;
        if (b0 != 0xff || (b1 & 0xe0) != 0xe0) {
            return false;
        }
        int version = (b1 >> 3) & 0x03;
        int layer = (b1 >> 1) & 0x03;
        if (version == 1 || layer == 0) {
            return false;
        }
        int bitrateIndex = (b2 >> 4) & 0x0f;
        int samplerateIndex = (b2 >> 2) & 0x03;
        return bitrateIndex != 0x0f && samplerateIndex != 3;
    }

    /**
     * Berechnet die Laenge eines MPEG-Frames in Byte.
     *
     * @return Frame-Laenge, oder 0 wenn unbestimmbar
     */
    private static int mpegFrameLength(byte[] b, int p) {
        int b1 = b[p + 1] & 0xff;
        int b2 = b[p + 2] & 0xff;
        int version = (b1 >> 3) & 0x03;
        int layer = (b1 >> 1) & 0x03;
        int bitrateIndex = (b2 >> 4) & 0x0f;
        int samplerateIndex = (b2 >> 2) & 0x03;
        int padding = (b2 >> 1) & 1;

        int bitrate = BITRATES[bitrateIndex];
        int samplerate = (version == 3) ? SAMPLERATES_M1[samplerateIndex]
                : SAMPLERATES_M2[samplerateIndex];
        if (bitrate == 0 || samplerate == 0) {
            return 0;
        }
        if (layer == 3) {
            return (12 * bitrate * 1000 / samplerate + padding) * 4;
        }
        if (layer == 2) {
            return 144 * bitrate * 1000 / samplerate + padding;
        }
        if (version == 3) {
            return 144 * bitrate * 1000 / samplerate + padding;
        }
        return 72 * bitrate * 1000 / samplerate + padding;
    }

    /**
     * Prueft, ob der Anfang ein gueltiger MPEG-Audio-Frame-Header ist.
     *
     * <p>Ein Frame beginnt mit 11 Einsen. Danach folgen:
     * <pre>
     *   Byte 1: 111 VV LL P   (Version 2 Bit, Layer 2 Bit, Protection)
     *   Byte 2: BBBB SS Pd    (Bitrate, Samplerate, Padding)
     * </pre>
     *
     * <p>Damit Zufallstreffer ausgeschlossen sind, muessen Layer und
     * Version gueltig sein und die Bitrate/Samplerate-Indizes keine
     * reservierten Werte tragen.
     */
    public static boolean isMpegFrameSync(byte[] head) {
        return isMpegFrameSync(head, 0);
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
