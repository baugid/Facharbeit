package block;

import utils.ByteUtils;
import utils.CryptoUtils;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;

/**
 * Stellt eine Note dar, die geparsed wurde.
 */
public class Note {
    /**
     * Die gespeicherte Zensur.
     */
    private final short zensur;
    /**
     * Das gespeicherte Fach.
     */
    private final short fach;
    /**
     * Die rohen Signaturen.
     */
    private final byte[] signatures;

    /**
     * Erzeugt eine Note aus den Parametern.
     *
     * @param zensur     Die Zensur.
     * @param fach       Das Fach.
     * @param signatures Die Signaturen in unveränderter Form.
     */
    public Note(short zensur, short fach, byte[] signatures) {
        this.zensur = zensur;
        this.fach = fach;
        this.signatures = signatures;
    }

    /**
     * Getter für die Zensur.
     *
     * @return Die Zensur.
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
     * Verifiziert die Signaturen.
     *
     * @param kl Der öffentliche Schlüssel des Klassenlehrers.
     * @return Gibt {@code true} zurück, wenn beide Signaturen korrekt sind. Anderen falls wird {@code false} zurückgegeben.
     * @see InvalidKeySpecException
     * @see NoSuchAlgorithmException
     * @see SignatureException
     * @see InvalidKeyException
     */
    public boolean verifySignatures(PublicKey kl) throws InvalidKeySpecException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        //Convert zensur und fach to List<Byte>
        List<Byte> data = ByteUtils.toByteCollection(ByteUtils.toBytes(zensur));
        data.addAll(ByteUtils.toByteCollection(ByteUtils.toBytes(fach)));
        //seperate key and signatures
        int parserPos = 0;
        //get the key length
        byte[] keyLenBytes = Arrays.copyOfRange(signatures, parserPos, parserPos += 2);
        short keyLen = ByteUtils.toShort(keyLenBytes);
        data.addAll(ByteUtils.toByteCollection(keyLenBytes));
        //get the key
        byte[] keyBytes = Arrays.copyOfRange(signatures, parserPos, parserPos += keyLen);
        PublicKey flKey = CryptoUtils.toPublicECKey(keyBytes);
        data.addAll(ByteUtils.toByteCollection(keyBytes));
        //get the signature
        byte sigLen = signatures[parserPos];
        ++parserPos;
        byte[] signature = Arrays.copyOfRange(signatures, parserPos, parserPos += sigLen);
        //verify it
        if (!CryptoUtils.verify(flKey, ByteUtils.toArray(data), signature))
            return false;
        data.add(sigLen);
        data.addAll(ByteUtils.toByteCollection(signature));
        //get the second signature
        sigLen = signatures[parserPos];
        ++parserPos;
        signature = Arrays.copyOfRange(signatures, parserPos, parserPos + sigLen);
        //verify it
        return CryptoUtils.verify(kl, ByteUtils.toArray(data), signature);
    }
}
