package block;

import utils.CryptoUtils;
import xml.NoteXML;
import xml.ZeugnisXML;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

/**
 * Repräsentation eines vollständigen Zeugnisses.
 */
public class Zeugnis {
    /**
     * Die Noten.
     */
    private final List<Note> noten = new ArrayList<>();
    /**
     * Die Version.
     */
    private short vers;
    /**
     * Der Schüler.
     */
    private PublicKey schueler;
    /**
     * Das Jahr.
     */
    private short jahr;
    /**
     * Die Schulnr.
     */
    private int schulnr;
    /**
     * Die Schule.
     */
    private PublicKey schule;
    /**
     * Die Erziehungsberechtigten.
     */
    private List<PublicKey> erziehungsberechtigte;
    /**
     * Die sonstigen Besitzer.
     */
    private List<PublicKey> sonstige;
    /**
     * Die Zeugnisbemerkungen.
     */
    private String bemerkungen;

    /**
     * Erzeugt ein Zeugnis aus einer XML-Repräsentation.
     *
     * @param zeugnisXML Die XML-Repräsentation.
     * @return Das Zeugnis.
     * @see InvalidKeySpecException
     * @see NoSuchAlgorithmException
     */
    public static Zeugnis fromXML(ZeugnisXML zeugnisXML) throws InvalidKeySpecException, NoSuchAlgorithmException {
        Zeugnis z = new Zeugnis();
        z.vers = zeugnisXML.vers;
        z.jahr = zeugnisXML.jahr;
        z.schulnr = zeugnisXML.schule.schulnr;
        z.bemerkungen = zeugnisXML.bemerkungen;
        z.schueler = CryptoUtils.toPublicRSAKey(zeugnisXML.Schueler);
        z.schule = CryptoUtils.toPublicRSAKey(zeugnisXML.schule.publicKey);
        z.erziehungsberechtigte = CryptoUtils.convertAllToRSA(zeugnisXML.besitzer.erziehungsberechtigte);
        z.sonstige = CryptoUtils.convertAllToRSA(zeugnisXML.besitzer.sonstige);
        for (NoteXML note : zeugnisXML.noten.noten) {
            z.noten.add(Note.fromXML(note));
        }
        return z;
    }

    /**
     * Getter für die Version.
     *
     * @return Die Version.
     */
    public short getVers() {
        return vers;
    }

    /**
     * Getter für den Schüler.
     *
     * @return Den Schüler.
     */
    public PublicKey getSchueler() {
        return schueler;
    }

    /**
     * Getter für das Jahr.
     *
     * @return Das Jahr.
     */
    public short getJahr() {
        return jahr;
    }

    /**
     * Getter für die Schulnr.
     *
     * @return Die Schulnr.
     */
    public int getSchulnr() {
        return schulnr;
    }

    /**
     * Getter für die Schule.
     *
     * @return Die Schule.
     */
    public PublicKey getSchule() {
        return schule;
    }

    /**
     * Getter für die Erziehungsberechtigten.
     *
     * @return Die Erziehungsberechtigten.
     */
    public List<PublicKey> getErziehungsberechtigte() {
        return erziehungsberechtigte;
    }

    /**
     * Getter für die sonstigen Besitzer.
     *
     * @return Die sonstigen Besitzer.
     */
    public List<PublicKey> getSonstige() {
        return sonstige;
    }

    /**
     * Getter für die Noten.
     *
     * @return Die Noten.
     */
    public List<Note> getNoten() {
        return noten;
    }

    /**
     * Getter für die Zeugnisbemerkungen.
     *
     * @return Die Zeugnisbemerkungen.
     */
    public String getBemerkungen() {
        return bemerkungen;
    }
}
