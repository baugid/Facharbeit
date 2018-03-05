package block;

import utils.CryptoUtils;
import xml.NoteXML;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * Darstellung einer Note.
 */
public class Note {
    /**
     * Die Zensur.
     */
    private short zensur;
    /**
     * Das Fach.
     */
    private short fach;
    /**
     * Der Fachlehrer.
     */
    private PublicKey fachlehrer;

    /**
     * Erzeugt eine Note aus einer XML-Repräsentation.
     *
     * @param noteXML Die XML-Repräsentation.
     * @return Die Note.
     * @see InvalidKeySpecException
     * @see NoSuchAlgorithmException
     */
    public static Note fromXML(NoteXML noteXML) throws InvalidKeySpecException, NoSuchAlgorithmException {
        Note n = new Note();
        n.zensur = noteXML.zensur;
        n.fach = noteXML.fach;
        n.fachlehrer = CryptoUtils.toPublicKey(noteXML.fachlehrer);
        return n;
    }

    /**
     * Getter für die Zensur.
     *
     * @return die Zensur.
     */
    public short getZensur() {
        return zensur;
    }

    /**
     * Getter für das Fach.
     *
     * @return Das Fach.
     */
    public short getFach() {
        return fach;
    }

    /**
     * Getter für den Fachlehrer.
     *
     * @return Der Fachlehrer.
     */
    public PublicKey getFachlehrer() {
        return fachlehrer;
    }
}
