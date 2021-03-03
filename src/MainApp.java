import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;

public class MainApp {

    /**
     * TO READ:
     * https://coding-stream-of-consciousness.com/2019/07/16/all-about-java-key-stores-jks-a-presto-example-including-checking-validity-dates/#:~:text=Certificates%20are%20made%20with%20an,for%20JKS%20is%2090%20days.
     *
     * GENERATE KS:
     * keytool -genseckey -keystore aes-keystore.jck -storetype jceks -storepass mystorepass -keyalg AES -keysize 256 -alias jceksaes -keypass mykeypass
     * @param args
     */

    public static void main(String args[]) {
        String originalString = "joshin";
        String iv = "1234567890123456";

        String keystoreFileLocation = "C:\\Zoshyn\\Project\\JavaFX\\CryPee\\resources\\aes-keystore.jck";
        String storePass = "mystorepass";
        String alias = "jceksaes";
        String keyPass = "mykeypass";

        AESCipher cipher = null;

        try {
            Key key = getKeyFromKeyStore(keystoreFileLocation, storePass, alias, keyPass);

            cipher = new AESCipher(key, iv);
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        String encryptedString = cipher.encrypt(originalString);
        String decryptedString = cipher.decrypt(encryptedString);

        System.out.println(originalString);
        System.out.println(encryptedString);
        System.out.println(decryptedString);
    }

    public static Key getKeyFromKeyStore(final String keystoreLocation, final String keystorePass, final String alias, final String keyPass) {
        try {
            InputStream keystoreStream = new FileInputStream(keystoreLocation);
            KeyStore keystore = KeyStore.getInstance("JCEKS");
            keystore.load(keystoreStream, keystorePass.toCharArray());

            Key key = keystore.getKey(alias, keyPass.toCharArray());

            return key;

        } catch (NoSuchAlgorithmException | IOException | CertificateException | UnrecoverableKeyException | KeyStoreException e) {
            e.printStackTrace();
        }

        return null;
    }
}
