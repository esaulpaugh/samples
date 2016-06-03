/*
*
* MIT License
*
* Copyright (c) 2016 Evan J. Saulpaugh
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*
*/

package samples.esaulpaugh.encryptednotepad;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyInfo;
import android.util.Log;
import android.widget.Toast;

import com.lambdaworks.crypto.SCrypt;

import org.json.JSONException;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static samples.esaulpaugh.encryptednotepad.Constants.ENCODED_ENCRYPTED_WRAPPED_BYTES;
import static samples.esaulpaugh.encryptednotepad.Constants.ENCRYPTION_KEY_ALGORITHM;
import static samples.esaulpaugh.encryptednotepad.Constants.ENCRYPTION_KEY_LENGTH;
import static samples.esaulpaugh.encryptednotepad.Constants.MAC_KEY_ALGORITHM;
import static samples.esaulpaugh.encryptednotepad.Constants.MAC_KEY_LENGTH;
import static samples.esaulpaugh.encryptednotepad.Constants.PREF_SCRYPT_PARAMS;
import static samples.esaulpaugh.encryptednotepad.Constants.RSA_ALGORITHMS;
import static samples.esaulpaugh.encryptednotepad.Constants.RSA_WRAPPING_ALGORITHM_PREF;
import static samples.esaulpaugh.encryptednotepad.Constants.SHARED_PREFS_NAME;

/**
 * Created by esaulpaugh on 3/20/16.
 */
public class KeyUtils {

//    // TODO ******* tune at setup and generate these & write to preferences? *********
//    private static final int SCRYPT_N = 65536; // CPU cost parameter
//    private static final int SCRYPT_R = 2; // block size parameter
//    private static final int SCRYPT_P = 1; // parallelization parameter
//
//    private static final int SCRYPT_OUTPUT_BYTES = 64;

    public static AuthEncryptionKey createKey(Activity activity, String password)
            throws IOException, GeneralSecurityException {

        byte[] salt = generateSalt();

        Key applicationKey = KeyStoreUtils.keyGen(activity);

        byte[] keyBytes = Utils.secureRandomBytes(ENCRYPTION_KEY_LENGTH + MAC_KEY_LENGTH);

        return storeKey(activity, password, salt, applicationKey, keyBytes, false);
    }

    private static AuthEncryptionKey toAuthEncryptionKey(byte[] keyBytes) throws IllegalArgumentException {

        if(keyBytes.length != ENCRYPTION_KEY_LENGTH + MAC_KEY_LENGTH) {
            throw new IllegalArgumentException("key length must be " + (ENCRYPTION_KEY_LENGTH + MAC_KEY_LENGTH));
        }

        return new AuthEncryptionKey(
                new SecretKeySpec(keyBytes, 0, ENCRYPTION_KEY_LENGTH, ENCRYPTION_KEY_ALGORITHM),
                new SecretKeySpec(keyBytes, ENCRYPTION_KEY_LENGTH, MAC_KEY_LENGTH, MAC_KEY_ALGORITHM));
    }

//    public static byte[] getSalt(Context context) {
//        SharedPreferences prefs = context.getSharedPreferences(SHARED_PREFS_NAME, Context.MODE_PRIVATE);
//        String value = prefs.getString(PREF_SALT, null);
//        return value != null ? Utils.decode(value) : null;
//    }

    public static ScryptTuner.ScryptParams getScryptParams(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(SHARED_PREFS_NAME, Context.MODE_PRIVATE);
        String value = prefs.getString(PREF_SCRYPT_PARAMS, null);
        try {
            return value != null ? ScryptTuner.ScryptParams.fromString(value) : null;
        } catch (JSONException e) {
            e.printStackTrace();
            return null;
        }
//        return value != null ? Utils.decode(value) : null;
    }

    // rsaPublicKey
    private static AuthEncryptionKey storeKey(final Activity activity, String password, byte[] salt, Key applicationKey, byte[] rawKeyBytes, boolean overwrite) throws GeneralSecurityException,
            IOException {

        if (password == null) {
            throw new IllegalArgumentException("password is null");
        }

        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(activity, "Securing encryption key...", Toast.LENGTH_SHORT).show();
            }
        });

        ScryptTuner.ScryptParams params = ScryptTuner.tune();

        System.out.println(params.toString());

        params.setSalt(salt);

        try {
            Thread.sleep(200, 1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        EncryptionManager em = getEncryptionManagerForPassword(password, params);

        String wrappingAlgorithm = null;

        final byte[] wrappedBytes;
        if(applicationKey == null) {
            System.out.println("SKIPPING KEY WRAP -- applicationKey == null");
            wrappedBytes = rawKeyBytes;
        } else if(applicationKey instanceof SecretKey) {
            Log.i("YAYA", "Wrapping bytes symmetrically...");
            EncryptionManager applicationEncryptionManager = new EncryptionManager(toAuthEncryptionKey(applicationKey.getEncoded()));
            wrappedBytes = applicationEncryptionManager.encrypt(rawKeyBytes).getBytes();
        } else {
            Log.i("YAYA", "Wrapping bytes...");
            Cipher wrapper = getWrappingCipher(applicationKey);
            wrappingAlgorithm = wrapper.getAlgorithm();
            wrappedBytes = KeyUtils.wrap(new SecretKeySpec(rawKeyBytes, "AES"), wrapper, applicationKey);
        }

        Log.i("YAYA", "Encrypting bytes...");
        byte[] encryptedWrappedBytes = em.encrypt(wrappedBytes).getBytes();

        Log.i("YAYA", "Encoding bytes...");
        String encodedEncryptedWrappedBytes = Utils.encode(encryptedWrappedBytes);

        SharedPreferences prefs = activity.getSharedPreferences(SHARED_PREFS_NAME, Context.MODE_PRIVATE);
        prefs.edit()
                .putString(ENCODED_ENCRYPTED_WRAPPED_BYTES, encodedEncryptedWrappedBytes)
                .putString(RSA_WRAPPING_ALGORITHM_PREF, wrappingAlgorithm) // TODO add HMAC for authenticity?
                .commit();

        setScryptParams(activity, params, overwrite, true);

        return toAuthEncryptionKey(rawKeyBytes);
    }

    public static AuthEncryptionKey openKey(final Activity activity, String password)
            throws GeneralSecurityException, IOException {

        if(password == null) {
            throw new IllegalArgumentException("password is null");
        }

        System.gc();

        ScryptTuner.ScryptParams params = getScryptParams(activity);

        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(activity, "Extracting encryption key...", Toast.LENGTH_SHORT).show();
            }
        });

        EncryptionManager em = getEncryptionManagerForPassword(password, params);

        Key applicationKey = KeyStoreUtils.getApplicationKey();

        return openKeys(activity, em, applicationKey);
    }

    private static byte[] generateSalt() {
        System.out.println("generating salt");
        return Utils.secureRandomBytes(16);
    }

    private static void setScryptParams(Context context, ScryptTuner.ScryptParams params, boolean overwrite, boolean commit) {
        System.out.println("setting salt");
        SharedPreferences prefs = context.getSharedPreferences(Constants.SHARED_PREFS_NAME, Context.MODE_PRIVATE);
        boolean exists = prefs.contains(PREF_SCRYPT_PARAMS);

        if(overwrite) {
            if(!exists) {
                throw new IllegalStateException("cannot overwrite: params not found");
            }
        } else {
            if(exists) {
                throw new IllegalStateException("params already exist");
            }
        }

        SharedPreferences.Editor editor = prefs.edit().putString(PREF_SCRYPT_PARAMS, params.toString());
        if(commit) {
            editor.commit();
        } else {
            editor.apply();
        }
    }

//
//    private static EncryptionManager getEncryptionManagerForPassword(Context context, String password) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
//        EncryptionManager em = getEncryptionManagerForPassword(password, );
//    }

//    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
//    public static String bytesToHex(byte[] bytes) {
//        char[] hexChars = new char[bytes.length << 1];
//        for ( int j = 0; j < bytes.length; j++ ) {
//            int v = bytes[j] & 0xFF;
//            hexChars[j * 2] = hexArray[v >>> 4];
//            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
//        }
//        return new String(hexChars);
//    }

    private static EncryptionManager getEncryptionManagerForPassword(String password, ScryptTuner.ScryptParams params) throws GeneralSecurityException {

        long start, end;
        double elapsed;

//        https://paragonie.com/blog/2016/02/how-safely-store-password-in-2016
        System.out.println("N = " + params.getN());
        System.out.println("r = " + params.getR());
        System.out.println("p = " + params.getP());

//        byte[] x = SCrypt.scrypt("".getBytes(UTF_8), "".getBytes(UTF_8), 16, 1, 1, 64);
//        System.out.println(bytesToHex(x));
//        x = SCrypt.scrypt("password".getBytes(UTF_8), "NaCl".getBytes(UTF_8), 1024, 8, 16, 64);
//        System.out.println(bytesToHex(x));
//        x = SCrypt.scrypt("pleaseletmein".getBytes(UTF_8), "SodiumChloride".getBytes(UTF_8), 16384, 8, 1, 64);
//        System.out.println(bytesToHex(x));


//        String bcryptHash = BCrypt.hashpw(new String(sha512.digest(password.getBytes(UTF_8)), UTF_8), salt);

        if(password.isEmpty()) {
            password = "\0";
        }

        start = System.nanoTime();
        byte[] keyBytes = SCrypt.scrypt(password.getBytes(Constants.UTF_8), params.getSalt(), params.getN(), params.getR(), params.getP(), params.getDkLen());
        end = System.nanoTime();
        elapsed = (end - start) / 1000000.0;
        System.out.println("elapsed millis = " + elapsed);

        return new EncryptionManager(new AuthEncryptionKey(
                new SecretKeySpec(keyBytes, 0, ENCRYPTION_KEY_LENGTH, ENCRYPTION_KEY_ALGORITHM),
                new SecretKeySpec(keyBytes, ENCRYPTION_KEY_LENGTH, MAC_KEY_LENGTH, MAC_KEY_ALGORITHM)));
    }

    private static String getWrappingAlgorithm(SharedPreferences prefs) {

        // TODO verify HMAC for authenticity?

        return prefs.getString(RSA_WRAPPING_ALGORITHM_PREF, null);
    }

    // hardwareBackedRsaPrivateKey
    private static AuthEncryptionKey openKeys(Context context, EncryptionManager em, Key applicationKey) throws CertificateException, InvalidKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchPaddingException, UnrecoverableEntryException, IOException, NoSuchProviderException {

        SharedPreferences prefs = context.getSharedPreferences(SHARED_PREFS_NAME, Context.MODE_PRIVATE);
        String encodedEncryptedWrappedBytes = prefs.getString(ENCODED_ENCRYPTED_WRAPPED_BYTES, null);

        Log.i("YAYA", "Decoding bytes...");
        byte[] encryptedWrappedBytes = Utils.decode(encodedEncryptedWrappedBytes);

//        Log.i("YAYA", "encryptedWrappedBytes = " + Utils.encode(encryptedWrappedBytes));

        Log.i("YAYA", "Decrypting bytes...");
        byte[] wrappedBytes = em.decrypt(new EncryptionManager.EncryptedMessage(encryptedWrappedBytes));

//        Log.i("YAYA", "decrypted = " + Utils.encode(wrappedBytes));

        String algorithm = getWrappingAlgorithm(prefs);

        final byte[] keyBytes;
        if(applicationKey == null) {
            keyBytes = wrappedBytes;
        } else if(algorithm != null) {
            Log.i("YAYA", "Unwrapping bytes...");
            keyBytes = unwrap(wrappedBytes, algorithm, applicationKey).getEncoded();
        } else {
            EncryptionManager applicationEncryptionManager = new EncryptionManager(toAuthEncryptionKey(applicationKey.getEncoded()));
            keyBytes = applicationEncryptionManager.decrypt(new EncryptionManager.EncryptedMessage(wrappedBytes));
        }

        return new AuthEncryptionKey(
                new SecretKeySpec(keyBytes, 0, ENCRYPTION_KEY_LENGTH, ENCRYPTION_KEY_ALGORITHM),
                new SecretKeySpec(keyBytes, ENCRYPTION_KEY_LENGTH, MAC_KEY_LENGTH, MAC_KEY_ALGORITHM)
        );
    }

    private static class GetEncryptionManagerThread extends Thread {

        private final String password;
        private final ScryptTuner.ScryptParams params;

        private EncryptionManager result;

        public GetEncryptionManagerThread(String password, ScryptTuner.ScryptParams params) {
            this.password = password;
            this.params = params;
        }

        public EncryptionManager getResult() {
            return result;
        }

        @Override
        public void run() {
            try {
                result = getEncryptionManagerForPassword(password, params);
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            }
        }

    }

    public static boolean changePassword(Activity activity, String oldPassword, String newPassword) {

        SharedPreferences prefs = activity.getSharedPreferences(SHARED_PREFS_NAME, Context.MODE_PRIVATE);
        String encodedEncryptedWrappedBytes = prefs.getString(ENCODED_ENCRYPTED_WRAPPED_BYTES, null);
        byte[] encryptedWrappedBytes = Utils.decode(encodedEncryptedWrappedBytes);

        try {

            ScryptTuner.ScryptParams oldScryptParams = getScryptParams(activity);

            GetEncryptionManagerThread oldEncrypterThread = new GetEncryptionManagerThread(oldPassword, oldScryptParams);
            oldEncrypterThread.start();

            String algorithm = getWrappingAlgorithm(prefs);
//            KeyStore.PrivateKeyEntry privateKeyEntry = KeyStoreUtils.getPrivateKeyEntry();

            Key applicationKey = KeyStoreUtils.getApplicationKey();

            byte[] newSalt = generateSalt();

            oldEncrypterThread.join();

            EncryptionManager oldEncrypter = oldEncrypterThread.getResult();
            byte[] wrappedBytes = oldEncrypter.decrypt(new EncryptionManager.EncryptedMessage(encryptedWrappedBytes));

            byte[] keyBytes;
            if(algorithm != null) {
//            Key encryptionKey = unwrap(algorithm, privateKeyEntry.getPrivateKey(), wrappedBytes);
                keyBytes = unwrap(wrappedBytes, algorithm, applicationKey).getEncoded();
            } else {
                EncryptionManager applicationEncryptionManager = new EncryptionManager(toAuthEncryptionKey(applicationKey.getEncoded()));
                keyBytes = applicationEncryptionManager.decrypt(new EncryptionManager.EncryptedMessage(wrappedBytes));
            }

            // newRsaPublicKey
            applicationKey = KeyStoreUtils.keyGen(activity);

            storeKey(activity, newPassword, newSalt, applicationKey, keyBytes, true);

            return true;

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private static Cipher getWrappingCipher(Key applicationKey) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {

//        if(applicationKey instanceof SecretKey) {
//            return Cipher.getInstance("AES/CBC/PKCS7Padding"); // , "AndroidOpenSSL" PKCS7Padding
//        }

        Cipher wrapper = null;

        final int len = RSA_ALGORITHMS.length;
        for(int i = 0; i < len; i++) {
            String algorithm = RSA_ALGORITHMS[i];
            try {
                wrapper = Cipher.getInstance(algorithm, "AndroidOpenSSL"); // , "AndroidOpenSSL"
//                if(!wrapper.getProvider().getName().equals("AndroidOpenSSL")) {
//                    wrapper = Cipher.getInstance(algorithm, "AndroidOpenSSL");
//                }
                break;
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                System.out.println(algorithm + " not found");
                if(i == len - 1) {
                    throw e;
                }
            }
        }

        // TODO for authenticity, HMAC the wrapping algorithm used?

        assert wrapper != null;

        System.out.println("wrapping algorithm = " + wrapper.getAlgorithm());


        return wrapper;
    }

    // TODO move into KeyStoreUtils, as algorithm is dependent on what the AndroidKeyStore supports
    public static byte[] wrap(Key targetKey, Cipher wrapper, Key wrappingKey) throws InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, IOException, CertificateException, NoSuchProviderException, InvalidAlgorithmParameterException {

        wrapper.init(Cipher.WRAP_MODE, wrappingKey);

        return wrapper.wrap(targetKey);
    }

//    public static Key unwrap(String algorithm, PrivateKey hardwareBackedRsaPrivateKey, byte[] wrapped) throws KeyStoreException, CertificateException, NoSuchAlgorithmException,
//            IOException, UnrecoverableEntryException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException {
//
//        System.out.println("wrapped size = " + (wrapped.length << 3) + " bits");
//
//        System.out.println("Unwrapping with " + algorithm);
//
//
//        KeyFactory factory = KeyFactory.getInstance(hardwareBackedRsaPrivateKey.getAlgorithm(), "AndroidKeyStore");
//        KeyInfo keyInfo;
//        try {
//            keyInfo = factory.getKeySpec(hardwareBackedRsaPrivateKey, KeyInfo.class);
//            if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
//                System.out.println("isInsideSecureHardware = " + keyInfo.isInsideSecureHardware());
//                System.out.println("origin = " + keyInfo.getOrigin());
//                for(String s : keyInfo.getSignaturePaddings()) {
//                    System.out.println("padding " + s);
//                }
//                for(String s : keyInfo.getEncryptionPaddings()) {
//                    System.out.println("enc padding " + s);
//                }
//                for(String s : keyInfo.getBlockModes()) {
//                    System.out.println("block mode " + s);
//                }
//            }
//        } catch (InvalidKeySpecException e) {
//            e.printStackTrace();
//            // Not an Android KeyStore key.
//        }
//
//
//        try {
//            Cipher unwrapper = Cipher.getInstance(algorithm);
//            unwrapper.init(Cipher.UNWRAP_MODE, hardwareBackedRsaPrivateKey);
//            long start, end;
//            double elapsed;
//
//            start = System.nanoTime();
//
//            Key k = unwrapper.unwrap(wrapped, ENCRYPTION_KEY_ALGORITHM, Cipher.SECRET_KEY);
//
//            end = System.nanoTime();
//            elapsed = (end - start) / 1000000.0;
//            System.out.println("elapsed " + elapsed + " millis -- " + start + ", " + end);
//
//            return k;
//
//        } catch (Exception e) {
//            e.printStackTrace();
//            throw e;
//        }
//    }


    // TODO move into KeyStoreUtils, as algorithm is dependent on what the AndroidKeyStore supports
    private static Key unwrap(byte[] wrappedKeyBytes, String algorithm, Key unwrappingKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {

        System.out.println("wrappedKeyBytes size = " + (wrappedKeyBytes.length << 3) + " bits");

        System.out.println("Unwrapping with " + algorithm);

        try {
            KeyFactory factory = KeyFactory.getInstance(unwrappingKey.getAlgorithm(), "AndroidKeyStore");
            KeyInfo keyInfo = factory.getKeySpec(unwrappingKey, KeyInfo.class);
            if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                System.out.println("isInsideSecureHardware = " + keyInfo.isInsideSecureHardware());
                System.out.println("origin = " + keyInfo.getOrigin());
                for(String s : keyInfo.getSignaturePaddings()) {
                    System.out.println("padding " + s);
                }
                for(String s : keyInfo.getEncryptionPaddings()) {
                    System.out.println("enc padding " + s);
                }
                for(String s : keyInfo.getBlockModes()) {
                    System.out.println("block mode " + s);
                }
            }
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            // Not an Android KeyStore key.
        } catch (NoSuchAlgorithmException nsae) {
            nsae.printStackTrace();
            ;
            // yee
        }

        try {
            Cipher unwrapper = Cipher.getInstance(algorithm);
            unwrapper.init(Cipher.UNWRAP_MODE, unwrappingKey);
            long start, end;
            double elapsed;

            start = System.nanoTime();

            Key k = unwrapper.unwrap(wrappedKeyBytes, ENCRYPTION_KEY_ALGORITHM, Cipher.SECRET_KEY);

            end = System.nanoTime();
            elapsed = (end - start) / 1000000.0;
            System.out.println("elapsed " + elapsed + " millis -- " + start + ", " + end);

            return k;

        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
    }

//    public static Pair<SecretKeySpec, SecretKeySpec> deriveKeys(String password) throws NoSuchAlgorithmException {
//
//        password = new String(sha512(password.getBytes(UTF_8)), UTF_8);
//
//        String passwordHash = BCrypt.hashpw(password, BCrypt.gensalt(NUM_BCRYPT_ROUNDS));
//
//        System.out.println(passwordHash);
//
//        byte[] keyBytes = sha512(passwordHash.getBytes(UTF_8));
//
//        return new Pair<>(
//                new SecretKeySpec(keyBytes, 0, ENCRYPTION_KEY_LENGTH, ENCRYPTION_KEY_ALGORITHM),
//                new SecretKeySpec(keyBytes, ENCRYPTION_KEY_LENGTH, MAC_KEY_LENGTH, MAC_KEY_ALGORITHM)
//        );
//    }

}
