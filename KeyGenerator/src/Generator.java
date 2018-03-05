import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@SuppressWarnings("WeakerAccess")
public class Generator {
    public static void main(String[] args) throws Exception {
        if (args.length == 0 || args[0].equalsIgnoreCase("EC")) {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
            gen.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());
            KeyPair pair = gen.generateKeyPair();
            Base64.Encoder enc = Base64.getEncoder();
            KeyFactory factory = KeyFactory.getInstance("EC");
            System.out.println("PublicKey: " + enc.encodeToString(factory.getKeySpec(pair.getPublic(), X509EncodedKeySpec.class).getEncoded()));
            System.out.println("PrivateKey: " + enc.encodeToString(factory.getKeySpec(pair.getPrivate(), PKCS8EncodedKeySpec.class).getEncoded()));
        } else if (args[0].equalsIgnoreCase("RSA")) {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048, new SecureRandom());
            KeyPair pair = gen.generateKeyPair();
            Base64.Encoder enc = Base64.getEncoder();
            KeyFactory factory = KeyFactory.getInstance("RSA");
            System.out.println("PublicKey: " + enc.encodeToString(factory.getKeySpec(pair.getPublic(), X509EncodedKeySpec.class).getEncoded()));
            System.out.println("PrivateKey: " + enc.encodeToString(factory.getKeySpec(pair.getPrivate(), PKCS8EncodedKeySpec.class).getEncoded()));
        }
    }
}
