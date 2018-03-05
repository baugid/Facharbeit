package data;

import utils.ByteUtils;
import utils.CryptoUtils;

import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * Stellt einen Block dar, der geparsed wurde.
 */
public class Block {
    /**
     * Die Rohdaten.
     */
    private final byte[] raw;
    /**
     * Der Schüler.
     */
    private PublicKey student;
    /**
     * Die Schulleitung.
     */
    private PublicKey direx;
    /**
     * Die Klassenleitung.
     */
    private PublicKey kl;
    /**
     * Der Blockhash.
     */
    private byte[] hash;
    //interne Marker
    private int klSigBegin;
    private int direxSigBegin;

    /**
     * Erzeugt einen neuen Block aus {@code data}.
     *
     * @param blockData Die binären und unveränderten Blockdaten,
     *                  aus denen der Block erzeugt wird.
     * @see InvalidKeySpecException
     * @see NoSuchAlgorithmException
     */
    Block(byte[] blockData) throws InvalidKeySpecException, NoSuchAlgorithmException {
        raw = Arrays.copyOf(blockData, blockData.length);
        parseBlock();
    }

    /**
     * Errechnet den Hash des Genesisblockes.
     *
     * @return Der Genesishash.
     */
    public static byte[] getGenesisHash() {
        try {
            return MessageDigest.getInstance("Sha-256").digest(("Die Debatte um die Länge des gymnasialen Bildungsgangs (G8 oder G9) hat die schulpolitische Auseinandersetzung in Nordrhein-Westfalen – wie auch in anderen Bundesländern – seit fast 20 Jahren in unterschiedlicher Intensität geprägt. Trotz einer im Grundsatz politisch einvernehmlichen G8-Einführung im Jahr 2005 hat die praktische Umsetzung von G8 nicht dauerhaft die notwendige Akzeptanz an Schulen und in der Öffentlichkeit gefunden, um es als einzige Gymnasialoption fortzuführen. Dies hat – insbesondere seit 2015 – zu verstärkten politischen und bürgerschaftlichen Aktivitäten geführt.\n" +
                    "\n" +
                    "CDU und FDP haben diese Entwicklung zur Kenntnis genommen und in ihrem Koalitionsvertrag mit einer Leitentscheidung für G9 hierauf reagiert. Diesen Beschluss wird die Landesregierung umsetzen. Die Leitentscheidung bedeutet, dass zum Schuljahr 2019/2020 alle Gymnasien zu G9 zurückkehren sollen, die sich nicht aktiv für eine Beibehaltung von G8 aussprechen. Die Aufrechterhaltung einer G8-Option ist dadurch begründet, dass es auch einen nennenswerten Anteil von Schülerinnen und Schülern, Eltern und Lehrkräften gibt, die G8 positiv gegenüberstehen. Die NRW-Koalition setzt darauf, dass die Betroffenen vor Ort selbst am besten wissen, was ihren Bedürfnissen entspricht. Deshalb erhalten sie für den Umstellungszeitpunkt 2019/2020 die Freiheit, im Rahmen der Schulkonferenz mit einer Mehrheit von mehr als zwei Dritteln selbst über die Länge des gymnasialen Bildungsgangs an ihrer Schule zu entscheiden. Damit kann keine der Beteiligtengruppen (Eltern, Schülerinnen und Schüler, Lehrkräfte) vollständig überstimmt werden, zentrale Rechte des Schulträgers bleiben gesichert.\n" +
                    "\n" +
                    "Die Umstellung auf G 9 beginnt mit dem Schuljahr 2019/2020. Sie umfasst die Jahrgänge 5 und 6 des Gymnasiums, also auch die Kinder, die zum Schuljahr 2018/2019 im Gymnasium aufgenommen wurden. Eine Erstreckung auf weitere Jahrgänge ist wegen der dann bereits fortgeschrittenen Schullaufbahn nicht beabsichtigt.\n" +
                    "\n" +
                    "Kommunale Kosten für die Umstellung fallen für die Vorbereitung zum Schuljahr 2026/2027 an, in dem der 6. Jahrgang des Jahres 2019/2020 in die 13. Klasse kommt. Höhere Kosten für die Lernmittelfreiheit fallen mit dem Schuljahr 2023/2024 an. Über die Höhe der Kosten verhandelt das Land mit den Kommunalen Spitzenverbänden unter Einschaltung eines Gutachters.\n" +
                    "\n" +
                    "Durch die erweiterte Entscheidungsfreiheit der Schulen, eine sorgfältig vorbereitete und qualitativ abgesicherte Umstellung, einen dauerhaft verlässlichen Rahmen sowie eine gleichzeitige Stärkung der gymnasialen Bildung insgesamt soll die größtmögliche Akzeptanz bei den Beteiligten erreicht werden.  Dazu bedarf es eines fachlichen Austausches mit den Beteiligten sowie mit den anderen Bundesländern. All diese Prozesse wie auch die Änderung des Schulgesetzes, der Ausbildungs- und Prüfungsordnungen sowie der Kernlehrpläne bedürfen einer sorgfältigen Planung sowie einer gründlichen Umsetzung. An dieser Stelle werden fortlaufend die Entscheidungen veröffentlicht, die die Landesregierung in Sachen gymnasialer Bildungsgang trifft.").getBytes("UTF-8"));
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            return new byte[32];
        }
    }

    /**
     * Parsed einen Block.
     *
     * @see InvalidKeySpecException
     * @see NoSuchAlgorithmException
     */
    private void parseBlock() throws InvalidKeySpecException, NoSuchAlgorithmException {
        //parse student Key
        int position;
        {
            position = 2 + 32;
            short keyLen = ByteUtils.toShort(Arrays.copyOfRange(raw, position, position += 2));
            byte[] studentKeyBytes = Arrays.copyOfRange(raw, position, position += keyLen);
            student = CryptoUtils.toPublicRSAKey(studentKeyBytes);
        }
        //parse direx Key
        {
            short keyLen = ByteUtils.toShort(Arrays.copyOfRange(raw, position, position += 2));
            byte[] direxKeyBytes = Arrays.copyOfRange(raw, position, position += keyLen);
            direx = CryptoUtils.toPublicECKey(direxKeyBytes);
        }
        //skip year and schoolnr.
        {
            position += 6;
        }
        //skip owners
        {
            short amount = ByteUtils.toShort(Arrays.copyOfRange(raw, position, position += 2));
            position += amount * 256 + 2;
        }
        //read kl Key
        {
            short keyLen = ByteUtils.toShort(Arrays.copyOfRange(raw, position, position += 2));
            byte[] klKeyBytes = Arrays.copyOfRange(raw, position, position += keyLen);
            kl = CryptoUtils.toPublicECKey(klKeyBytes);
        }
        //skip encrypted
        {
            int encryptedLength = ByteUtils.toInt(Arrays.copyOfRange(raw, position, position += 4));
            position += encryptedLength;
        }
        klSigBegin = position;
        //calculate direxSigBegin
        {
            byte siglen = raw[position];
            position += siglen + 1;
            direxSigBegin = position;
        }
        //calculate blockhash
        {
            MessageDigest md = MessageDigest.getInstance("Sha-256");
            hash = md.digest(raw);
        }
    }

    /**
     * Getter für die binären Daten.
     *
     * @return Die binären Daten.
     */
    public byte[] getData() {
        return raw;
    }

    /**
     * Getter für den Blockhash.
     *
     * @return Der Blockhash.
     */
    public byte[] getHash() {
        return hash;
    }

    /**
     * Getter für den Schüler.
     *
     * @return Der Schüler.
     */
    public PublicKey getStudent() {
        return student;
    }

    /**
     * Verifiziert den Block.
     *
     * @param previousHash Der Hash des vorangegangenen Blockes.
     * @return Gibt {@code true} zurück, wenn der Block korrekt scheint.
     */
    public boolean verify(byte[] previousHash) {
        //Verify Hash
        if (!Arrays.equals(previousHash, Arrays.copyOfRange(raw, 2, 34))) return false;
        //Verify signatures
        byte[] toSignKl = Arrays.copyOfRange(raw, 0, klSigBegin);
        byte klSignatureLength = raw[klSigBegin];
        byte[] toSignDirex = Arrays.copyOfRange(raw, 0, direxSigBegin);
        byte direxSignatureLength = raw[direxSigBegin];
        try {
            return CryptoUtils.verify(kl, toSignKl, Arrays.copyOfRange(raw, klSigBegin + 1, klSigBegin + 1 + klSignatureLength)) &&
                    CryptoUtils.verify(direx, toSignDirex, Arrays.copyOfRange(raw, direxSigBegin + 1, direxSigBegin + 1 + direxSignatureLength));
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            return false;
        }
    }
}
