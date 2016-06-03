package samples.esaulpaugh.encryptednotepad;

import android.util.Base64;

import java.nio.charset.Charset;

/**
 * Created by esaulpaugh on 3/20/16.
 */
public class Constants {

    private static final String PREFIX = "EncryptedNotepad_";

    static final String SHARED_PREFS_NAME = PREFIX + "sharedPrefs";

    static final String RSA_WRAPPING_ALGORITHM_PREF = PREFIX + "rsaWrappingAlgorithm";

//    static final String PASSWORD = "password";
    static final String PREF_SCRYPT_PARAMS = PREFIX + "scrypt_params";
//    static final String PREF_WRAPPED_KEY_ENCODED = PREFIX + "wrappedKeyEncoded";

    static final String ENCODED_ENCRYPTED_WRAPPED_BYTES = PREFIX + "ENCODED_ENCRYPTED_WRAPPED_BYTES";

    static final String KEY_ALGORITHM_AES = "AES";
    static final String KEY_ALGORITHM_RSA = "RSA";
//    static final String RSA_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";


    static final String[] RSA_ALGORITHMS = new String[] {
            "RSA/None/OAEPWithSHA-384AndMGF1Padding",
            "RSA/ECB/OAEPWithSHA-384AndMGF1Padding",

            "RSA/None/OAEPWithSHA-512AndMGF1Padding",
            "RSA/ECB/OAEPWithSHA-512AndMGF1Padding",

            "RSA/None/OAEPWithSHA-256AndMGF1Padding",
            "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",

            "RSA/None/OAEPWithSHA-224AndMGF1Padding",
            "RSA/ECB/OAEPWithSHA-224AndMGF1Padding",

            "RSA/None/OAEPWithSHA-1AndMGF1Padding",
            "RSA/ECB/OAEPWithSHA-1AndMGF1Padding",

            "RSA/None/OAEPPadding",
            "RSA/ECB/OAEPPadding",

            "RSA/None/PKCS1Padding",
            "RSA/ECB/PKCS1Padding",

            "RSA/None/NoPadding",
            "RSA/ECB/NoPadding"
    };

//
//
//
//    static final String RSA_NONE_OAEP_PADDING = "RSA/None/OAEPPadding";
//    static final String RSA_ECB_OAEP_PADDING = "RSA/ECB/OAEPPadding";
//    static final String RSA_ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding"; // "RSA/None/OAEPWithSHA-256AndMGF1Padding"; // RSA/ECB/OAEPWithSHA-256AndMGF1Padding

    static final int RSA_KEY_SIZE = 2048; // 3072

    static final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";
    static final String MAC_ALGORITHM = "HmacSHA256";

    static final String ENCRYPTION_KEY_ALGORITHM = "AES";
    static final String MAC_KEY_ALGORITHM = MAC_ALGORITHM;

    static final int IV_LENGTH_BYTES = 16;
    static final int MAC_LENGTH_BYTES = 32;

    static final int ENCRYPTION_KEY_LENGTH = 16;
    static final int MAC_KEY_LENGTH = 32;
    static final int TOTAL_KEY_LENGTH = ENCRYPTION_KEY_LENGTH + MAC_KEY_LENGTH;

    static final int BASE_64_FLAGS = Base64.NO_PADDING | Base64.NO_WRAP | Base64.URL_SAFE;

    static final Charset UTF_8 = Charset.forName("UTF-8");

    static final String ROOT = "root";
    static final String DIR = "dir";

}
