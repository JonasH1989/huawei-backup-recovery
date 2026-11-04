package de.jonas.huaweibackup;

import de.jonas.huaweibackup.core.Crypto;
import de.jonas.huaweibackup.core.Signatures;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Erzeugt synthetische Huawei-Backups zum Testen des Recovery-Tools.
 *
 * <p>Deckt beide Schemata ab:
 * <ul>
 *   <li>Schema A (KoBackup v10..v12, AES-256-CTR)</li>
 *   <li>Schema B (KoBackup v13 / HiSuite 11+, AES-256-GCM)</li>
 * </ul>
 *
 * <p>Zusaetzlich je ein Fall mit zerstoertem {@code info.xml}, bei dem
 * der Abbruch mitten im Attribut passiert - exakt das Szenario aus dem
 * echten Backup.
 */
public final class TestBackupBuilder {

    public static final String PASSWORD = "TestPasswort123!";

    private TestBackupBuilder() {
    }

    /** Die Testinhalte - als relative Pfade. */
    public static Map<String, byte[]> payloads() throws IOException {
        Map<String, byte[]> map = new LinkedHashMap<>();
        map.put("photo/DCIM/IMG_0001.jpg", jpg(3000));
        map.put("photo/DCIM/IMG_0002.jpg", jpg(3000));
        map.put("photo/DCIM/IMG_0003.png", png(2000));
        map.put("video/Movies/VID_0001.mp4", mp4(4000));
        map.put("video/Movies/VID_0002.mp4", mp4(4000));
        // MP3 OHNE ID3-Tag - so speichert Huawei Sprachnachrichten.
        // Der Test stellt sicher, dass die MPEG-Frame-Erkennung
        // greift und nicht nur die ID3-Signatur.
        map.put("soundrecorder/AUD-20261026-WA0001.mp3", mp3Frames(6000));
        return map;
    }

    /**
     * Baut eine MP3-Datei aus echten MPEG-Frames (ohne ID3-Tag).
     *
     * <p>MPEG-1 Layer III, 128 kBit/s, 44,1 kHz, kein Padding.
     * Frame-Laenge = 144 * 128000 / 44100 = 417 Byte.
     */
    private static byte[] mp3Frames(int n) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // Frame-Header: 0xFF 0xFB (MPEG1, Layer III, kein CRC),
        // 0x90 (Bitrate 128, Samplerate 44100), 0x00 (Kanal Joint Stereo)
        byte[] header = new byte[]{(byte) 0xff, (byte) 0xfb, (byte) 0x90, (byte) 0x00};
        byte[] payload = "MP3DATA".repeat(n / 7).getBytes(StandardCharsets.US_ASCII);
        int pos = 0;
        while (pos < payload.length) {
            out.writeBytes(header);
            int take = Math.min(417 - header.length, payload.length - pos);
            out.write(payload, pos, take);
            pos += take;
            // Frame auffuellen, damit die Laenge exakt 417 Byte betraegt.
            int written = header.length + take;
            if (written < 417) {
                out.write(new byte[417 - written]);
            }
        }
        return out.toByteArray();
    }

    private static byte[] jpg(int n) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(new byte[]{(byte) 0xff, (byte) 0xd8, (byte) 0xff, (byte) 0xe0});
        out.writeBytes(new byte[]{0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0x01, 0x01, 0x00,
                0x00, 0x01, 0x00, 0x01, 0x00, 0x00});
        out.writeBytes(new byte[]{(byte) 0xff, (byte) 0xfe});
        byte[] payload = "JPEGDATA".repeat(n / 7).getBytes(StandardCharsets.US_ASCII);
        out.writeBytes(new byte[]{(byte) (payload.length >>> 8), (byte) payload.length});
        out.writeBytes(payload);
        out.writeBytes(new byte[]{(byte) 0xff, (byte) 0xd9});
        return out.toByteArray();
    }

    private static byte[] png(int n) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(new byte[]{(byte) 0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a});
        out.writeBytes("PNGDATA".repeat(n / 7).getBytes(StandardCharsets.US_ASCII));
        return out.toByteArray();
    }

    private static byte[] mp4(int n) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(new byte[]{0x00, 0x00, 0x00, 0x18, 'f', 't', 'y', 'p', 'i', 's', 'o', 'm'});
        out.writeBytes("MP4DATA".repeat(n / 7).getBytes(StandardCharsets.US_ASCII));
        return out.toByteArray();
    }

    // -----------------------------------------------------------------
    // Schema A - KoBackup v10..v12, AES-256-CTR
    // -----------------------------------------------------------------

    public static void buildSchemaA(Path root, boolean corruptInfo) throws Exception {
        Files.createDirectories(root);

        byte[] pwkeySalt = Crypto.randomBytes(32);
        byte[] k = Crypto.pbkdf2(PASSWORD.getBytes(StandardCharsets.UTF_8),
                Arrays.copyOfRange(pwkeySalt, 0, 16), Crypto.PBKDF2_ITER_BKEY, 32);

        // bkey ist laut Schema ein 32-stelliger HEX-STRING (als UTF-8 bytes),
        // nicht beliebige Bytes.
        byte[] bkeyBytes = hex(Crypto.randomBytes(16)).getBytes(StandardCharsets.UTF_8);

        // 16-Byte-Nonce - am echten Backup verifiziert.
        byte[] nonce = Arrays.copyOfRange(pwkeySalt, 16, 32);
        // doFinal() liefert bei GCM Chiffrat || Tag - daraus ergibt sich
        // e_perbackupkey (= Chiffrat || GCM-Tag).
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "AES"),
                new GCMParameterSpec(128, nonce));
        byte[] combined = gcm.doFinal(bkeyBytes);
        byte[] epbk = new byte[48];
        System.arraycopy(combined, 0, epbk, 0, 32);
        System.arraycopy(combined, 32, epbk, 32, 16);

        byte[] encmsgv3 = Crypto.randomBytes(48);
        String bkeyStr = new String(bkeyBytes, StandardCharsets.UTF_8);
        byte[][] keyAndIv = Crypto.deriveFileKeyA(bkeyStr, encmsgv3);
        byte[] fileKey = keyAndIv[0];
        byte[] iv = keyAndIv[1];

        Path session = root.resolve("backupFiles1/20261104020000");
        Files.createDirectories(session);

        for (Map.Entry<String, byte[]> e : payloads().entrySet()) {
            Path dst = root.resolve("media/20261104020000").resolve(e.getKey());
            Files.createDirectories(dst.getParent());
            // WICHTIG: jede Datei wird UNABHAENGIG verschluesselt - der
            // Counter startet pro Datei neu.
            Files.write(dst, Crypto.decryptCtr(fileKey, iv, e.getValue()));
        }

        String encHex = hex(encmsgv3);
        String info = """
                <?xml version="1.0" encoding="utf-8"?>
                <root>
                  <row table="BackupFilesTypeInfo">
                    <column name="e_perbackupkey"><value String="%s"/></column>
                    <column name="pwkey_salt"><value String="%s"/></column>
                  </row>
                  <row table="BackupFileModuleInfo_Media">
                    <column name="name"><value String="media"/></column>
                    <column name="encMsgV3"><value String="%s"/></column>
                  </row>
                </root>
                """.formatted(hex(epbk), hex(pwkeySalt), encHex);

        Path infoPath = session.resolve("info.xml");
        if (corruptInfo) {
            // Abbruch mitten im Attribut -> XML nicht wohlgeformt
            Files.writeString(infoPath, info.replace(encHex, encHex.substring(0, 40)));
            // Rohtext-Rettung: der vollstaendige Wert liegt an
            // anderer Stelle im Backup als Text (so wie im echten
            // HiSuite-Backup).
            Files.writeString(root.resolve("cinfoset.dat"), encHex + "\n");
        } else {
            Files.writeString(infoPath, info);
        }
    }

    // -----------------------------------------------------------------
    // Schema B - KoBackup v13 / HiSuite 11+, AES-256-GCM
    // -----------------------------------------------------------------

    public static void buildSchemaB(Path root, boolean corruptInfo) throws Exception {
        Files.createDirectories(root);

        byte[] encmsgv3 = Crypto.randomBytes(48);
        byte[][] keyAndNonce = Crypto.deriveKeyB(PASSWORD, encmsgv3);
        byte[] key = keyAndNonce[0];
        byte[] nonce = keyAndNonce[1];

        for (Map.Entry<String, byte[]> e : payloads().entrySet()) {
            Path dst = root.resolve(e.getKey());
            Files.createDirectories(dst.getParent());

            Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
            gcm.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, nonce));
            byte[] ct = gcm.doFinal(e.getValue());
            Files.write(dst, ct);
        }

        String encHex = hex(encmsgv3);
        String info = """
                <?xml version="1.0" encoding="utf-8"?>
                <root>
                  <row table="BackupFileModuleInfo">
                    <column name="name"><value String="media"/></column>
                    <column name="encMsgV3"><value String="%s"/></column>
                  </row>
                </root>
                """.formatted(encHex);

        Path p = root.resolve("check/info.xml");
        Files.createDirectories(p.getParent());
        if (corruptInfo) {
            Files.writeString(p, info.replace(encHex, encHex.substring(0, 40)));
            // Realistischer Fall: cinfoset.dat ist eine KOPIE des Index und
            // kann unbeschaedigt sein, waehrend check/info.xml abgeschnitten
            // wurde. Genau danach sucht das Recovery-Tool.
            Files.write(root.resolve("cinfoset.dat"),
                    info.getBytes(StandardCharsets.UTF_16LE));
        } else {
            Files.writeString(p, info);
        }
    }

    private static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] hexBytes(byte[] data) {
        return hex(data).getBytes(StandardCharsets.US_ASCII);
    }

    /** Signatur-Erkennung muss mit den Testdaten uebereinstimmen. */
    public static void checkSignatures() throws IOException {
        for (Map.Entry<String, byte[]> e : payloads().entrySet()) {
            String detected = Signatures.detect(e.getValue());
            String expected = e.getKey().substring(e.getKey().lastIndexOf('.'));
            if (!expected.equals(detected)) {
                throw new IllegalStateException(
                        "Signatur-Erkennung falsch fuer " + e.getKey()
                                + ": erwartet " + expected + ", erkannt " + detected);
            }
        }
    }
}
