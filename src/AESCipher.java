import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class AESCipher {
    private Cipher cipher;
    private IvParameterSpec iv;
    private SecretKeySpec secretKeySpec;

    AESCipher(Key key, String iv) throws NoSuchPaddingException, NoSuchAlgorithmException {
        this(key.getEncoded(), iv.getBytes());
    }

    AESCipher(byte[] secretKey, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException {
        String cryptoAlgorithm = "AES";
        String transformation = "AES/CBC/PKCS5PADDING";
        initialize(secretKey, iv, cryptoAlgorithm, transformation);
    }

    private void initialize(byte[] key, byte[] iv, String cryptoAlgorithm, String transformation) throws NoSuchPaddingException, NoSuchAlgorithmException {
        secretKeySpec = new SecretKeySpec(Arrays.copyOf(key, 16), cryptoAlgorithm);
        this.iv = new IvParameterSpec(iv);
        cipher = Cipher.getInstance(transformation);
    }

    public String encrypt(String stringToEncrypt) {
        try {
            Cipher cipher = getCipher(Cipher.ENCRYPT_MODE);

            return Encoder.encode(cipher.doFinal(stringToEncrypt.getBytes(StandardCharsets.UTF_8)));

        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public String decrypt(String stringToDecrypt) {
        try {
            Cipher cipher = getCipher(Cipher.DECRYPT_MODE);

            return new String(cipher.doFinal(Encoder.decode(stringToDecrypt)));

        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    private Cipher getCipher(int encryptMode) throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.init(encryptMode, getSecretKeySpec(), iv);
        return cipher;
    }

    private SecretKeySpec getSecretKeySpec() {
        return secretKeySpec;
    }

    private static class Encoder {
        public static String encode(byte[] stringToEncode) {
            return Base64.getEncoder()
                    .encodeToString(stringToEncode);
        }

        public static byte[] decode(String stringToDecode) {
            return Base64.getDecoder().
                    decode(stringToDecode);
        }
    }
}
