package utils;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/**
 * Enthält Funktionalität für die benötigte Kryptographie.
 */
public class CryptoUtils {
    /**
     * Wandelt ein Bytearray in einen {@code PublicKey} um, der für elliptische Kurven eingesetzt werden kann.
     *
     * @param publicKey Der Key als Bytearray.
     * @return Den Key als {@code PublicKey}.
     * @see NoSuchAlgorithmException
     * @see InvalidKeySpecException
     */
    public static PublicKey toPublicECKey(byte[] publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory factory = KeyFactory.getInstance("EC");
        return factory.generatePublic(new X509EncodedKeySpec(publicKey));
    }

    /**
     * Wandelt ein Bytearray in einen öffentlichen RSA-Key um.
     *
     * @param publicKey Der Key als Bytearray.
     * @return Der umgewandelte Key.
     * @see NoSuchAlgorithmException
     * @see InvalidKeySpecException
     */
    public static PublicKey toPublicRSAKey(byte[] publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(new X509EncodedKeySpec(publicKey));
    }

    /**
     * Überprüft eine gegebene Signatur.
     *
     * @param key       Der zum Überprüfen zu verwendende Key.
     * @param message   Die signierte Nachricht.
     * @param signature Die Signatur.
     * @return Gibt {@code true} zurück, wenn die Signatur korrekt ist. Ansonsten wird {@code false} zurückgegeben.
     * @see NoSuchAlgorithmException
     * @see SignatureException
     * @see InvalidKeyException
     */
    public static boolean verify(PublicKey key, byte[] message, byte[] signature) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        Signature sig = Signature.getInstance("SHA256WITHECDSA");
        sig.initVerify(key);
        sig.update(message);
        return sig.verify(signature);
    }
}
