package de.jonas.huaweibackup.core;

/**
 * Wird geworfen, wenn das Passwort nicht zum Backup passt.
 *
 * <p>Der GCM-Tag aus {@code e_perbackupkey[32:48]} ist die
 * Passwort-Pruefung des Schemas A: passt er nicht, ist das Passwort
 * falsch - nicht etwa die Datei beschaedigt.
 */
public class BadPasswordException extends Exception {

    private static final long serialVersionUID = 1L;

    public BadPasswordException(String message) {
        super(message);
    }
}
