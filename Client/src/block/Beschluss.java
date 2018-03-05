package block;

import xml.BeschlussXML;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

/**
 * Zusammenfassung eines Zeugnisses und dessen Metadaten.
 */
public class Beschluss {
    /**
     * Metadaten des Zeugnisses.
     */
    private Metadaten meta;
    /**
     * Das Zeugnis.
     */
    private Zeugnis zeugnis;

    /**
     * Erzeugt einen Beschluss aus einer XML-Repräsentation.
     *
     * @param xml Die XML-Repräsentation.
     * @return Der Beschluss.
     * @see InvalidKeySpecException
     * @see NoSuchAlgorithmException
     */
    public static Beschluss fromXML(BeschlussXML xml) throws InvalidKeySpecException, NoSuchAlgorithmException {
        Beschluss b = new Beschluss();
        b.meta = Metadaten.fromXML(xml.meta);
        b.zeugnis = Zeugnis.fromXML(xml.zeugnis);
        return b;
    }

    /**
     * Getter für den Schüler.
     *
     * @return Der Schüler.
     */
    public PublicKey getSchueler() {
        return zeugnis.getSchueler();
    }

    /**
     * Getter für die Version.
     *
     * @return Die Version.
     */
    public short getVersion() {
        return zeugnis.getVers();
    }

    /**
     * Getter für das Jahr.
     *
     * @return Das Jahr.
     */
    public short getYear() {
        return zeugnis.getJahr();
    }

    /**
     * Getter für die Schulleitung.
     *
     * @return Die Schulleitung.
     */
    public KeyPair getSchulleitung() {
        return meta.getSchulleitung();
    }

    /**
     * Getter für die Klassenleitung.
     *
     * @return Die Klassenleitung.
     */
    public KeyPair getKlassenleitung() {
        return meta.getKlassenlehrer();
    }

    /**
     * Getter für die Anzahl der Besitzer.
     *
     * @return Die Anzahl der Besitzer.
     */
    public short getOwnerCount() {
        return (short) (zeugnis.getErziehungsberechtigte().size() + zeugnis.getSonstige().size() + 2);
    }

    /**
     * Getter für die Schule.
     *
     * @return Die Schule.
     */
    public PublicKey getSchule() {
        return zeugnis.getSchule();
    }

    /**
     * Getter für die Schulnr.
     *
     * @return Die Schulnr.
     */
    public int getSchulnr() {
        return zeugnis.getSchulnr();
    }

    /**
     * Getter für sämtliche Erziehungsberechtigte.
     *
     * @return Sämtliche Erziehungsberechtigte.
     */
    public List<PublicKey> getErziehungsberechtigte() {
        return zeugnis.getErziehungsberechtigte();
    }

    /**
     * Getter für sämtliche Sonstige.
     *
     * @return Sämtliche Sonstige.
     */
    public List<PublicKey> getSonstige() {
        return zeugnis.getSonstige();
    }

    /**
     * Getter für sämtliche Noten.
     *
     * @return Sämtliche Noten.
     */
    public List<Note> getNoten() {
        return zeugnis.getNoten();
    }

    /**
     * Getter für den privaten Key des Fachlehrers.
     *
     * @param key Der öffentliche Key des Fachlehrers.
     * @return Der private Key des Fachlehrers.
     */
    public PrivateKey getFLKey(PublicKey key) {
        return meta.getFLKey(key);
    }

    /**
     * Getter für die Zeugnisbemerkungen.
     *
     * @return Die Zeugnisbemerkungen.
     */
    public String getBemerkungen() {
        return zeugnis.getBemerkungen();
    }
}
