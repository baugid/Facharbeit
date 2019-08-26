package block;

import utils.CryptoUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static utils.ByteUtils.*;

/**
 * Repräsentation eines Blockes
 */
public class Block {
    /**
     * Der Beschluss, der als Quelle für sämtliche Daten genutzt werden soll.
     */
    private final Beschluss b;
    /**
     * Die Liste mit allen Bytes des Blockes.
     */
    private final List<Byte> finalData;
    /**
     * Der Schlüssel für den verschlüsselten Teil des Blockes.
     */
    private SecretKey docKey;
    /**
     * Marker für den Anfang der Signaturen.
     */
    private int tailStart;

    /**
     * Erstellt einen Block aus einem Beschluss.
     *
     * @param b Der zu verwendende Beschluss.
     */
    public Block(Beschluss b) {
        this.b = b;
        finalData = new ArrayList<>(10_000);
    }

    /**
     * Baut den Block aus dem Beschluss
     *
     * @param prevHash Der Hash des vorherigen Blockes
     */
    public void evaluate(byte[] prevHash) throws NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, SignatureException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
        finalData.clear();
        byte[] initVector = writeHead(prevHash);
        appendEncryptedPart(initVector);
        writeTail();
    }

    /**
     * Fügt den Blockkopf an finalData an.
     *
     * @param prevHash Der Hash des vorherigen Blockes.
     * @return Der Initialisierungsvektor für die Verschlüsselung.
     * @see NoSuchAlgorithmException
     * @see InvalidKeyException
     * @see BadPaddingException
     * @see NoSuchPaddingException
     * @see IllegalBlockSizeException
     * @see InvalidKeySpecException
     */
    private byte[] writeHead(byte[] prevHash) throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        finalData.addAll(toByteCollection(toBytes(b.getVersion())));
        finalData.addAll(toByteCollection(prevHash));
        byte[] key = CryptoUtils.encodeRSAKey(b.getSchueler());
        finalData.addAll(toByteCollection(toBytes((short) key.length)));
        finalData.addAll(toByteCollection(key));
        key = CryptoUtils.encodeKey(b.getSchulleitung().getPublic());
        finalData.addAll(toByteCollection(toBytes((short) key.length)));
        finalData.addAll(toByteCollection(key));
        finalData.addAll(toByteCollection(toBytes(b.getYear())));
        finalData.addAll(toByteCollection(toBytes(b.getSchulnr())));
        finalData.addAll(toByteCollection(toBytes(b.getOwnerCount())));
        byte[] initVector = appendOwners();
        key = CryptoUtils.encodeKey(b.getKlassenleitung().getPublic());
        finalData.addAll(toByteCollection(toBytes((short) key.length)));
        finalData.addAll(toByteCollection(key));
        return initVector;

    }

    /**
     * Hängt die Besitzer des Blockes an diesen an.
     *
     * @return Der Hash des Besitzerabschnittes als Initialisierungsvektor.
     * @see NoSuchAlgorithmException
     * @see IllegalBlockSizeException
     * @see InvalidKeyException
     * @see BadPaddingException
     * @see NoSuchPaddingException
     */
    private byte[] appendOwners() throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        docKey = CryptoUtils.generateEncryptionKey();
        List<Byte> buffer = new ArrayList<>();
        //Einer ist 256 byte groß (RSA mit 2048bit)
        buffer.addAll(toByteCollection(CryptoUtils.encrypt(b.getSchueler(), docKey.getEncoded())));
        buffer.addAll(toByteCollection(CryptoUtils.encrypt(b.getSchule(), docKey.getEncoded())));
        buffer.addAll(toByteCollection(toBytes((short) b.getErziehungsberechtigte().size())));
        for (PublicKey k : b.getErziehungsberechtigte()) {
            buffer.addAll(toByteCollection(CryptoUtils.encrypt(k, docKey.getEncoded())));
        }
        for (PublicKey k : b.getSonstige()) {
            buffer.addAll(toByteCollection(CryptoUtils.encrypt(k, docKey.getEncoded())));
        }
        finalData.addAll(buffer);
        return CryptoUtils.sha256(toArray(buffer));
    }

    /**
     * Hängt den verschlüsselten Teil des Blockes an diesen an.
     *
     * @param initVector Der Initialisierungsvektor der Verschlüsselung.
     * @see InvalidKeySpecException
     * @see NoSuchAlgorithmException
     * @see SignatureException
     * @see InvalidKeyException
     * @see NoSuchPaddingException
     * @see BadPaddingException
     * @see IllegalBlockSizeException
     * @see InvalidAlgorithmParameterException
     */
    private void appendEncryptedPart(byte[] initVector) throws InvalidKeySpecException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        List<Byte> buffer = new ArrayList<>();
        appendGrades(buffer);
        byte[] bemerkungsbytes = b.getBemerkungen().getBytes(StandardCharsets.UTF_8);
        buffer.addAll(toByteCollection(toBytes(bemerkungsbytes.length)));
        buffer.addAll(toByteCollection(bemerkungsbytes));
        int beginPos = finalData.size();
        finalData.addAll(toByteCollection(CryptoUtils.encrypt(docKey, toArray(buffer), initVector)));
        finalData.addAll(beginPos, toByteCollection(toBytes(finalData.size() - beginPos)));
    }

    /**
     * Hängt die Noten an eine Liste an.
     *
     * @param buffer Die {@code List<Byte>}, an die die Noten angehangen werden.
     * @see InvalidKeySpecException
     * @see NoSuchAlgorithmException
     * @see SignatureException
     * @see InvalidKeyException
     */
    private void appendGrades(List<Byte> buffer) throws InvalidKeySpecException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        buffer.addAll(toByteCollection(toBytes((short) b.getNoten().size())));
        byte[] key;
        for (Note n : b.getNoten()) {
            List<Byte> gradeBuffer = new ArrayList<>();
            gradeBuffer.addAll(toByteCollection(toBytes(n.getZensur())));
            gradeBuffer.addAll(toByteCollection(toBytes(n.getFach())));
            key = CryptoUtils.encodeKey(n.getFachlehrer());
            gradeBuffer.addAll(toByteCollection(toBytes((short) key.length)));
            gradeBuffer.addAll(toByteCollection(key));
            PrivateKey flKey = b.getFLKey(n.getFachlehrer());
            byte[] signature = CryptoUtils.sign(flKey, toArray(gradeBuffer));
            gradeBuffer.add((byte) signature.length);
            gradeBuffer.addAll(toByteCollection(signature));
            signature = CryptoUtils.sign(b.getKlassenleitung().getPrivate(), toArray(gradeBuffer));
            gradeBuffer.add((byte) signature.length);
            gradeBuffer.addAll(toByteCollection(signature));
            buffer.addAll(gradeBuffer);
        }
    }

    /**
     * Hängt die Signaturen an den Block an.
     *
     * @see NoSuchAlgorithmException
     * @see InvalidKeyException
     * @see SignatureException
     */
    private void writeTail() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        tailStart = finalData.size();
        byte[] signature = CryptoUtils.sign(b.getKlassenleitung().getPrivate(), toArray(finalData));
        finalData.add((byte) signature.length);
        finalData.addAll(toByteCollection(signature));
        signature = CryptoUtils.sign(b.getSchulleitung().getPrivate(), toArray(finalData));
        finalData.add((byte) signature.length);
        finalData.addAll(toByteCollection(signature));
    }

    /**
     * Getter für den Block als Bytearray.
     *
     * @return Der Block.
     */
    public byte[] getFinalData() {
        return toArray(finalData);
    }

    /**
     * Aktualisiert den Hash und die Signaturen im Block.
     *
     * @param newHash Der neue Hashwert.
     * @see NoSuchAlgorithmException
     * @see InvalidKeyException
     * @see SignatureException
     */
    public void updateHash(byte[] newHash) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        List<Byte> hash = finalData.subList(2, 34);
        hash.clear();
        hash.addAll(toByteCollection(newHash));
        List<Byte> signatures = finalData.subList(tailStart, finalData.size());
        signatures.clear();
        writeTail();
    }

    /**
     * Berechnet den Base64 codierten Blockhash.
     *
     * @return Der Hash.
     * @see NoSuchAlgorithmException
     */
    public String getBlockHash() throws NoSuchAlgorithmException {
        MessageDigest sha = MessageDigest.getInstance("Sha-256");
        Base64.Encoder enc = Base64.getEncoder();
        return enc.encodeToString(sha.digest(toArray(finalData)));
    }
}
