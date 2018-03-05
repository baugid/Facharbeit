package block;

import utils.CryptoUtils;
import xml.FachlehrerXML;
import xml.MetadatenXML;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Metainformationen zu einem Zeugnis.
 */
public class Metadaten {
    /**
     * Die Fachlehrer.
     */
    private final List<KeyPair> fachlehrer = new ArrayList<>();
    /**
     * Die Klassenleitung.
     */
    private KeyPair klassenlehrer;
    /**
     * Die Schulleitung.
     */
    private KeyPair schulleitung;

    /**
     * Erzeugt ein Objekt aus einer XML-Repräsentation.
     *
     * @param metaXML Die XML-Repräsentation.
     * @return Das Metadatenobjekt.
     * @see NoSuchAlgorithmException
     * @see InvalidKeySpecException
     */
    public static Metadaten fromXML(MetadatenXML metaXML) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Metadaten m = new Metadaten();
        m.klassenlehrer = CryptoUtils.toKeyPair(metaXML.klassenlehrer.publicKey, metaXML.klassenlehrer.privateKey);
        m.schulleitung = CryptoUtils.toKeyPair(metaXML.schulleiterung.publicKey, metaXML.schulleiterung.privateKey);
        for (FachlehrerXML f : metaXML.alleFachlehrer.fachlehrer) {
            m.fachlehrer.add(CryptoUtils.toKeyPair(f.publicKey, f.privateKey));
        }
        return m;
    }

    /**
     * Sucht den privaten Key eines Fachlehrers zu seinem öffentlichen Key.
     *
     * @param fl Der öffentliche Key.
     * @return Der private Key.
     */
    public PrivateKey getFLKey(PublicKey fl) {
        //suche den Fachlehrer, der diesen public Key hat, und gib seinen private Key oder null zurueck
        return fachlehrer.stream().filter(keyPair -> keyPair.getPublic().equals(fl)).findFirst().flatMap(keyPair -> Optional.of(keyPair.getPrivate())).orElse(null);
    }

    /**
     * Getter für die Klassenleitung.
     *
     * @return die Klassenleitung.
     */
    public KeyPair getKlassenlehrer() {
        return klassenlehrer;
    }

    /**
     * Getter für die Schulleitung.
     *
     * @return die Schulleitung.
     */
    public KeyPair getSchulleitung() {
        return schulleitung;
    }
}
