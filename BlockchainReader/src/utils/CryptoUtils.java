package utils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

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
     * Wandelt einen öffentlichen RSA-Key in ein Bytearray um.
     *
     * @param key Der umzuwandelnde Key.
     * @return Der Key als Bytearray.
     * @see InvalidKeySpecException
     * @see NoSuchAlgorithmException
     */
    public static byte[] encodeRSAKey(PublicKey key) throws InvalidKeySpecException, NoSuchAlgorithmException {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.getKeySpec(key, X509EncodedKeySpec.class).getEncoded();
    }

    /**
     * Wandelt einen Base64 codierten Key in einen öffentlichen RSA-Key um.
     *
     * @param publicKey Der Key als String.
     * @return Der Key als {@code PublicKey}.
     * @see NoSuchAlgorithmException
     * @see InvalidKeySpecException
     */
    public static PublicKey toPublicRSAKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Base64.Decoder dec = Base64.getDecoder();
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(new X509EncodedKeySpec(dec.decode(publicKey)));
    }

    /**
     * Entschlüsselt ein mit RSA verschlüsseltes Bytearray.
     *
     * @param key        Der zum Entschlüsseln zu verwendende Key.
     * @param cipherText Der Geheimtext.
     * @return Der Klartext.
     * @see InvalidKeyException
     * @see BadPaddingException
     * @see IllegalBlockSizeException
     * @see NoSuchPaddingException
     * @see NoSuchAlgorithmException
     */
    public static byte[] decryptRSA(PrivateKey key, byte[] cipherText) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
        c.init(Cipher.DECRYPT_MODE, key);
        return c.doFinal(cipherText);
    }

    /**
     * Entschlüsselt ein mit AES verschlüsseltes Bytearray.
     *
     * @param key        Der zum Entschlüsseln zu verwendende Key.
     * @param cipherText Der Geheimtext.
     * @param initVector Der Initialisierungsvektor.
     * @return Der Klartext.
     * @see InvalidKeyException
     * @see BadPaddingException
     * @see IllegalBlockSizeException
     * @see NoSuchPaddingException
     * @see NoSuchAlgorithmException
     * @see InvalidAlgorithmParameterException
     */
    public static byte[] decryptAES(SecretKey key, byte[] cipherText, byte[] initVector) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        Cipher c = Cipher.getInstance("AES_256/CFB/NOPADDING");
        c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(initVector, 0, 16));
        return c.doFinal(cipherText);
    }

    /**
     * Wandelt ein Bytearray in einen {@code SecretKey} uum.
     *
     * @param key Das Bytearray.
     * @return Der {@code SecretKey}
     */
    public static SecretKey toAESKey(byte[] key) {
        return new SecretKeySpec(key, "AES");
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

    /**
     * Wandelt einen Base64 codierten Key in einen privaten RSA-Key um.
     *
     * @param privateKey Der Key als String.
     * @return Der Key als {@code PrivateKey}.
     * @see NoSuchAlgorithmException
     * @see InvalidKeySpecException
     */
    public static PrivateKey toPrivateRSAKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Base64.Decoder dec = Base64.getDecoder();
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePrivate(new PKCS8EncodedKeySpec(dec.decode(privateKey)));
    }

    /**
     * Berechnet den Sha-256 Hash der Nachricht.
     *
     * @param data Die Nachricht.
     * @return Der Hashwert der Nachricht.
     * @see NoSuchAlgorithmException
     */
    public static byte[] calculateSha256(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("Sha-256");
        return md.digest(data);
    }
}
