package de.jonas.huaweibackup.core;

import java.util.Arrays;

/**
 * Ein Schluessel-Kandidat: Schluessel + IV/Nonce + Bezeichnung des Herkunfts.
 *
 * <p>Die Bezeichnung sagt, wie der Schluessel zustande kam:
 * <ul>
 *   <li>{@code B(passwort)} - Schema B, direkt aus Passwort + Salt</li>
 *   <li>{@code A(bkey)}      - Schema A, ueber den abgeleiteten bkey</li>
 * </ul>
 */
public final class KeyCandidate {

    private final String label;
    private final byte[] key;
    private final byte[] iv;

    public KeyCandidate(String label, byte[] key, byte[] iv) {
        this.label = label;
        this.key = key;
        this.iv = iv;
    }

    public String label() {
        return label;
    }

    public byte[] key() {
        return key;
    }

    public byte[] iv() {
        return iv;
    }

    /** Schema des Kandidaten: "A" oder "B". */
    public String schema() {
        return label.startsWith("B") ? "B" : "A";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof KeyCandidate)) {
            return false;
        }
        KeyCandidate other = (KeyCandidate) o;
        return label.equals(other.label)
                && Arrays.equals(key, other.key)
                && Arrays.equals(iv, other.iv);
    }

    @Override
    public int hashCode() {
        return label.hashCode() * 31 + Arrays.hashCode(key) * 17 + Arrays.hashCode(iv);
    }

    @Override
    public String toString() {
        return label;
    }
}
