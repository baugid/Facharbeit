import block.Beschluss;
import block.Block;
import network.BlockchainConnection;
import xml.BeschlussXML;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;


@SuppressWarnings("WeakerAccess")
public class ClientMain {
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage java -jar this.jar zeugnis.xml ip:port");
            return;
        }
        //Verbindung aufbauen
        String[] address = args[1].split(":");
        BlockchainConnection connection;
        try {
            connection = new BlockchainConnection(address[0], Integer.parseInt(address[1]));
        } catch (IOException e) {
            System.err.println("Fehler beim Verbindungsaufbau: " + e.getLocalizedMessage());
            return;
        }

        try {
            //Block laden
            Beschluss beschluss = Beschluss.fromXML(load(args[0]));
            Block b = new Block(beschluss);
            //Block erzeugen
            b.evaluate(connection.getLastHash());
            //Block versenden
            sendBlock(b, connection);
        } catch (InvalidKeyException | InvalidKeySpecException e) {
            System.err.println("Mindestens einer der angegebenen Schlüssel ist defekt!");
        } catch (GeneralSecurityException e) {
            System.err.println("Das System scheint die benötigten kryptographischen Algorithmen nicht zu unterstützen!");
        } catch (UnsupportedEncodingException e) {
            System.err.println("Das System unterstützt keine UTF-8 Kodierung");
        } catch (IOException e) {
            System.err.println("Fehler bei der Kommunikation mit dem Server!\nNachricht: " + e.getLocalizedMessage());
        } catch (JAXBException e) {
            System.err.println("Das XML-Dokument ist defekt!\nNachricht: " + e.getLocalizedMessage());
        }
        try {
            connection.close();
        } catch (IOException ignored) {
        }
    }

    /**
     * Versucht zehn mal einen Block an den Server zu senden.
     *
     * @param b Der Block.
     * @param c Die Verbindung zum Server.
     * @see NoSuchAlgorithmException
     * @see InvalidKeyException
     * @see SignatureException
     * @see IOException
     */
    private static void sendBlock(Block b, BlockchainConnection c) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
        for (int i = 0; i < 10 && c.isValid(); i++) {
            try {
                if (c.sendBlock(b.getFinalData())) {
                    System.out.println("Block erfolgreich versandt!\nHash: " + b.getBlockHash());
                    return;
                } else {
                    b.updateHash(c.getLastHash());
                }
            } catch (IOException e) {
                if (i == 9)
                    throw e;
            }
        }
        System.err.println("Konnte den Block nicht senden! Stelle sicher, dass das XML-Dokument korrekt und der richtige Server ausgewählt ist!");
    }

    /**
     * Läd einen Beschluss aus einer XML-Datei.
     *
     * @param filepath Der Pfad zur XML-Datei.
     * @return Die Repräsentation der Datei als Objekt.
     * @see JAXBException
     */
    private static BeschlussXML load(String filepath) throws JAXBException {
        Unmarshaller m = JAXBContext.newInstance(BeschlussXML.class).createUnmarshaller();
        return (BeschlussXML) m.unmarshal(new File(filepath));
    }
}
