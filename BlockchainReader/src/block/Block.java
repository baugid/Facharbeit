package block;

import utils.ByteUtils;
import utils.CryptoUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Stellt einen Block dar, der geparsed wurde.
 */
public class Block {
    /**
     * Rohe Binärdaten
     */
    private final byte[] raw;
    /**
     * Entschlüsselte Noten
     */
    private List<Note> noten;
    /**
     * Entschlüsselte Bemerkung
     */
    private String bemerkungen;
    /**
     * Zur Signaturüberprüfung benötigter Schlüssel des Klassenlehrers
     */
    private PublicKey kl;
    //Positionsmarken
    private int encrBegin;
    private int ownersBegin;
    private int klSigBegin;
    /**
     * Anzahl der Erziehungsberechtigten
     */
    private short parentCount;
    /**
     * Jahr des Zeugnisses
     */
    private short year;
    /**
     * Ausstellende Schule
     */
    private int schoolnr;
    /**
     * Zeugnishash
     */
    private byte[] hash;
    /**
     * Hashwert des Besitzerabschnittes als Initialisierungsvektor für die Verschlüsselung
     */
    private byte[] ownerHash;

    /**
     * Erzeugt einen neuen Block aus {@code data}.
     *
     * @param data Die binären und unveränderten Blockdaten,
     *             aus denen der Block erzeugt wird.
     * @throws NoSuchAlgorithmException sollte ein benötigter Algorithmus nicht existieren.
     */
    public Block(byte[] data) throws NoSuchAlgorithmException {
        raw = Arrays.copyOf(data, data.length);
        basicParse();
    }

    /**
     * Parsed den Block soweit ohne Entschlüsselung möglich.
     *
     * @throws NoSuchAlgorithmException sollte ein benötigter Algorithmus nicht existieren.
     */
    private void basicParse() throws NoSuchAlgorithmException {
        //skip student Key
        int position;
        {
            position = 2 + 32;
            short keyLen = ByteUtils.toShort(Arrays.copyOfRange(raw, position, position += 2));
            position += keyLen;
        }
        //skip direx Key
        {
            short keyLen = ByteUtils.toShort(Arrays.copyOfRange(raw, position, position += 2));
            position += keyLen;
        }
        //parse year and schoolnr.
        {
            year = ByteUtils.toShort(Arrays.copyOfRange(raw, position, position += 2));
            schoolnr = ByteUtils.toInt(Arrays.copyOfRange(raw, position, position += 4));
        }
        //mark owners
        {
            short amount = ByteUtils.toShort(Arrays.copyOfRange(raw, position, position += 2));
            ownersBegin = position;
            position += 2 * 256;
            parentCount = ByteUtils.toShort(Arrays.copyOfRange(raw, position, position += 2));
            position += (amount - 2) * 256;
        }
        //hash owners as iv
        {
            ownerHash = CryptoUtils.calculateSha256(Arrays.copyOfRange(raw, ownersBegin, position));
        }
        //store kl Key
        {
            short keyLen = ByteUtils.toShort(Arrays.copyOfRange(raw, position, position += 2));
            try {
                kl = CryptoUtils.toPublicECKey(Arrays.copyOfRange(raw, position, position += keyLen));
            } catch (InvalidKeySpecException e) {
                System.err.println("Der Schlüssel des Klassenlehrers scheint defekt zu sein!");
            }
        }
        //mark encrypted
        {
            int encryptedLength = ByteUtils.toInt(Arrays.copyOfRange(raw, position, position += 4));
            encrBegin = position;
            position += encryptedLength;
        }
        klSigBegin = position;
        //calculate blockhash
        {
            hash = CryptoUtils.calculateSha256(raw);
        }
    }

    /**
     * Parsed den verschlüsselten Teil des Blockes.
     *
     * @param key      Der private Schlüssel, mit dem man den Key aus dem Block auslesen kann.
     * @param position Die Position des Schlüssels in der Besitzergruppe (beginnend mit 1).
     * @param type     Die Besitzergruppe, aus der der {@code key} ist.
     * @see IllegalBlockSizeException
     * @see BadPaddingException
     * @see NoSuchPaddingException
     * @see NoSuchAlgorithmException
     * @see InvalidKeyException
     * @see InvalidAlgorithmParameterException
     */
    public void parseEncrypted(PrivateKey key, int position, OwnerType type) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        //Get AES key
        int positionOffset;
        switch (type) {
            case SCHOOL:
                positionOffset = 256;
                break;
            case PARENT:
                positionOffset = 256 * 2 + 2;
                break;
            case OTHER:
                positionOffset = 256 * (2 + parentCount) + 2;
                break;
            case STUDENT:
            default:
                positionOffset = 0;
        }
        positionOffset += 256 * (position - 1);
        byte[] cipherKey = Arrays.copyOfRange(raw, positionOffset + ownersBegin, positionOffset + ownersBegin + 256);
        SecretKey k = CryptoUtils.toAESKey(CryptoUtils.decryptRSA(key, cipherKey));
        //Decrypt body
        byte[] cipherBody = Arrays.copyOfRange(raw, encrBegin, klSigBegin);
        byte[] body = CryptoUtils.decryptAES(k, cipherBody, ownerHash);
        //parse body
        {
            noten = new ArrayList<>();
            int parserPosition = 0;
            //parse grades
            {
                short amountOfGrades = ByteUtils.toShort(Arrays.copyOfRange(body, parserPosition, parserPosition += 2));
                for (int i = 0; i < amountOfGrades; i++) {
                    short zensur = ByteUtils.toShort(Arrays.copyOfRange(body, parserPosition, parserPosition += 2));
                    short fach = ByteUtils.toShort(Arrays.copyOfRange(body, parserPosition, parserPosition += 2));
                    //skip signatures
                    byte[] signatures;
                    {
                        int sigBegin = parserPosition;
                        short keyLen = ByteUtils.toShort(Arrays.copyOfRange(body, parserPosition, parserPosition += 2));
                        parserPosition += keyLen;
                        byte sigLen = body[parserPosition];
                        parserPosition += sigLen + 1;
                        sigLen = body[parserPosition];
                        parserPosition += sigLen + 1;
                        signatures = Arrays.copyOfRange(body, sigBegin, parserPosition);
                    }
                    noten.add(new Note(zensur, fach, signatures));
                }
            }
            //parse comment
            {
                int commentSize = ByteUtils.toInt(Arrays.copyOfRange(body, parserPosition, parserPosition += 4));
                bemerkungen = new String(Arrays.copyOfRange(body, parserPosition, parserPosition + commentSize), StandardCharsets.UTF_8);
            }
        }
    }

    /**
     * Getter für die Noten.
     *
     * @return Die Noten als Liste.
     */
    public List<Note> getNoten() {
        return noten;
    }

    /**
     * Getter für die Bemerkung
     *
     * @return Die Bemerkung.
     */
    public String getBemerkungen() {
        return bemerkungen;
    }

    /**
     * Getter für das Jahr
     *
     * @return Das Jahr.
     */
    public short getYear() {
        return year;
    }

    /**
     * Getter für die Schulnr.
     *
     * @return Die Schulnr.
     */
    public int getSchoolnr() {
        return schoolnr;
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
     * Überprüft sämtliche Signaturen.
     *
     * @return Gibt {@code true} zurück, wenn alle Signaturen korrekt sind und es keine Fehler gab.
     * Sonst wird {@code false} zurückgegeben
     * @throws NoSuchAlgorithmException sollte ein verwendeter Algorithmus nicht vorhanden sein.
     */
    public boolean verifyGrades() throws NoSuchAlgorithmException {
        if (kl == null)
            return false;
        try {
            for (Note n : noten) {
                if (!n.verifySignatures(kl))
                    return false;
            }
        } catch (NoSuchAlgorithmException e) {
            throw e;
        } catch (GeneralSecurityException e) {
            return false;
        }
        return true;
    }
}
