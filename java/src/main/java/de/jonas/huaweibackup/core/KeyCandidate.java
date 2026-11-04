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
 *
 * <p>{@code module} nennt das Backup-Modul, zu dem der Kandidat gehoert
 * (z. B. {@code calllog}). Ohne diese Zuordnung wuerde jedes Modul
 * jeden Schluessel probieren - bei einem 20-GB-Backup ein Vielfaches
 * der Laufzeit.
 */
public final class KeyCandidate {

    private final String label;
    private final byte[] key;
    private final byte[] iv;
    private final String module;

    public KeyCandidate(String label, byte[] key, byte[] iv) {
        this(label, key, iv, null);
    }

    public KeyCandidate(String label, byte[] key, byte[] iv, String module) {
        this.label = label;
        this.key = key;
        this.iv = iv;
        this.module = module;
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

    /** Zugehoeriges Backup-Modul oder null, wenn moduluebergreifend. */
    public String module() {
        return module;
    }

    /** Schema des Kandidaten: "A", "B" oder "M" (Media). */
    public String schema() {
        if (label.startsWith("B")) {
            return "B";
        }
        if (label.startsWith("M")) {
            return "M";
        }
        return "A";
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
        return module == null ? label : label + "[" + module + "]";
    }
}
