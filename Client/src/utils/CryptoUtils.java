package utils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Enthält Funktionalität für die benötigte Kryptographie.
 */
public class CryptoUtils {
    /**
     * Wandelt einen String in einen {@code PublicKey} um, der für elliptische Kurven eingesetzt werden kann.
     *
     * @param publicKey Der Key als String.
     * @return Den Key als {@code PublicKey}.
     * @see NoSuchAlgorithmException
     * @see InvalidKeySpecException
     */
    public static PublicKey toPublicKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Base64.Decoder dec = Base64.getDecoder();
        KeyFactory factory = KeyFactory.getInstance("EC");
        return factory.generatePublic(new X509EncodedKeySpec(dec.decode(publicKey)));
    }

    /**
     * Wandelt zwei Strings in ein Keypair um.
     *
     * @param publicKey  Der public Key als String.
     * @param privateKey Der private Key als String.
     * @return Beide Schlüssel in einem Keypair.
     * @see NoSuchAlgorithmException
     * @see InvalidKeySpecException
     */
    public static KeyPair toKeyPair(String publicKey, String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Base64.Decoder dec = Base64.getDecoder();
        KeyFactory factory = KeyFactory.getInstance("EC");
        return new KeyPair(factory.generatePublic(new X509EncodedKeySpec(dec.decode(publicKey))), factory.generatePrivate(new PKCS8EncodedKeySpec(dec.decode(privateKey))));
    }

    /**
     * Erzeugt einen zufälligen AES-Key.
     *
     * @return Der erzeugte Key.
     * @see NoSuchAlgorithmException
     */
    public static SecretKey generateEncryptionKey() throws NoSuchAlgorithmException {
        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(256);
        return gen.generateKey();
    }

    /**
     * Verschlüsselt eine Nachricht mit dem öffentlichen Key.
     *
     * @param key     Der öffentliche Key.
     * @param message Die zu verschlüsselnde Nachricht.
     * @return Den Schlüsseltext.
     * @see NoSuchPaddingException
     * @see NoSuchAlgorithmException
     * @see InvalidKeyException
     * @see BadPaddingException
     * @see IllegalBlockSizeException
     */
    public static byte[] encrypt(PublicKey key, byte[] message) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(message);
    }

    /**
     * Verschlüsselt eine Nachricht mit dem symmetrischen Schlüssel.
     *
     * @param key        Der Schlüssel.
     * @param message    Die Nachricht.
     * @param initVector Der Initialisierungsvektor.
     * @return Den Schlüsseltext.
     * @see NoSuchPaddingException
     * @see NoSuchAlgorithmException
     * @see InvalidKeyException
     * @see BadPaddingException
     * @see IllegalBlockSizeException
     * @see InvalidAlgorithmParameterException
     */
    public static byte[] encrypt(SecretKey key, byte[] message, byte[] initVector) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Cipher c = Cipher.getInstance("AES_256/CFB/NOPADDING");
        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(initVector, 0, 16), new SecureRandom());
        return c.doFinal(message);
    }

    /**
     * Kodiert einen öffentlichen Key für elliptische Kurven in ein Bytearray.
     *
     * @param key Der umzuwandelnde Key.
     * @return Der Key als Bytearray.
     * @see InvalidKeySpecException
     * @see NoSuchAlgorithmException
     */
    public static byte[] encodeKey(PublicKey key) throws InvalidKeySpecException, NoSuchAlgorithmException {
        KeyFactory factory = KeyFactory.getInstance("EC");
        return factory.getKeySpec(key, X509EncodedKeySpec.class).getEncoded();
    }

    /**
     * Kodiert einen öffentlichen RSA-Key als Bytearray.
     *
     * @param key Der zu kodierende Schlüssel.
     * @return Der Key als Bytearray.
     * @see InvalidKeySpecException
     * @see NoSuchAlgorithmException
     */
    public static byte[] encodeRSAKey(PublicKey key) throws InvalidKeySpecException, NoSuchAlgorithmException {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.getKeySpec(key, X509EncodedKeySpec.class).getEncoded();
    }

    /**
     * Signiert eine Nachricht mit dem gegebenen privaten Schlüssel.
     *
     * @param key     Der Schlüssel.
     * @param message Die zu signierende Nachricht.
     * @return Die Signatur.
     * @see NoSuchAlgorithmException
     * @see InvalidKeyException
     * @see SignatureException
     */
    public static byte[] sign(PrivateKey key, byte[] message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance("SHA256WITHECDSA");
        sig.initSign(key);
        sig.update(message);
        return sig.sign();
    }

    /**
     * Wandelt einen String in einen öffentlichen RSA-Key um.
     *
     * @param publicKey Der Key als String.
     * @return Der umgewandelte Key.
     * @see NoSuchAlgorithmException
     * @see InvalidKeySpecException
     */
    public static PublicKey toPublicRSAKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Base64.Decoder dec = Base64.getDecoder();
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(new X509EncodedKeySpec(dec.decode(publicKey)));
    }

    /**
     * Wandelt die gesamte Liste von Strings in öffentliche RSA-Keys um.
     *
     * @param publicKeys Die Liste von Strings mit den Schlüsseln.
     * @return Die Schlüssel.
     * @see InvalidKeySpecException
     * @see NoSuchAlgorithmException
     */
    public static List<PublicKey> convertAllToRSA(List<String> publicKeys) throws InvalidKeySpecException, NoSuchAlgorithmException {
        ArrayList<PublicKey> result = new ArrayList<>();
        for (String key : publicKeys) {
            result.add(toPublicRSAKey(key));
        }
        return result;
    }

    /**
     * Berechnet den Sha-256 Hash der Nachricht.
     *
     * @param message Die zu hashende Nachricht.
     * @return Der Hash der Nachricht.
     * @see NoSuchAlgorithmException
     */
    public static byte[] sha256(byte[] message) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("Sha-256");
        return md.digest(message);
    }
}
