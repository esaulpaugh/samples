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

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Calendar;

import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

import static samples.esaulpaugh.encryptednotepad.Constants.KEY_ALGORITHM_RSA;
import static samples.esaulpaugh.encryptednotepad.Constants.RSA_KEY_SIZE;

/**
 * Created by esaulpaugh on 3/20/16.
 */
public class KeyStoreUtils {

    private static final String KEY_STORE_ALIAS = "EncryptedNotepadRSAKeyAlias";


//        Object o = ((KeyStore.PrivateKeyEntry) e).getCertificate();

//        System.out.println(o.getClass() + " " + o);

//        Class c = ClassLoader.getSystemClassLoader().loadClass("android.security.keystore.AndroidKeyStoreSpi$KeyStoreX509Certificate");

//        Class<?> clazz = null;
//        try {
////            clazz = Class.forName("android.security.keystore.AndroidKeyStoreSpi$KeyStoreX509Certificate");
//            clazz = Class.forName("java.security.KeyStore.PrivateKeyEntry");
//
////            Object cert = clazz.newInstance();
//
//            Field[] fields = clazz.getDeclaredFields();
//
//            for(Field f : fields) {
//                System.out.println("f " + f.getName() + " " + f.toString());
//            }
//
//        } catch (ClassNotFoundException e1) {
//            e1.printStackTrace();
//        }

    static Key getApplicationKey() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException {

        if(Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR2) {
            return getKeyPreAPI18();
        }

        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);

        KeyStore.Entry entry = ks.getEntry(KEY_STORE_ALIAS, null);

        if(entry instanceof KeyStore.PrivateKeyEntry) {
            return ((KeyStore.PrivateKeyEntry) ks.getEntry(KEY_STORE_ALIAS, null)).getPrivateKey();
        }

        return ((KeyStore.SecretKeyEntry) ks.getEntry(KEY_STORE_ALIAS, null)).getSecretKey();
    }

//    static KeyStore.PrivateKeyEntry getPrivateKeyEntry() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException {
//        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
//        ks.load(null);
//
//        return (KeyStore.PrivateKeyEntry) ks.getEntry(KEY_STORE_ALIAS, null);
//    }

    @TargetApi(Build.VERSION_CODES.KITKAT)
    private static KeyPairGeneratorSpec getKeyPairGeneratorSpec(Context context, int apiLevel, boolean encryptionRequired, String alias) throws NoSuchAlgorithmException {
        Calendar notAfter = Calendar.getInstance();
        notAfter.add(Calendar.YEAR, 20);

        KeyPairGeneratorSpec.Builder builder = new KeyPairGeneratorSpec.Builder(context);

        System.out.println("encryptionRequired = " + encryptionRequired);

        if(encryptionRequired) {
            builder.setEncryptionRequired();
        }

        builder
                .setAlias(alias)
                .setSubject(new X500Principal(String.format("CN=%s, OU=%s", KEY_STORE_ALIAS, context.getPackageName())))
                .setSerialNumber(BigInteger.ONE)
                .setStartDate(Calendar.getInstance().getTime())
                .setEndDate(notAfter.getTime());

        if(apiLevel >= Build.VERSION_CODES.KITKAT) {
            builder.setKeyType(KeyProperties.KEY_ALGORITHM_RSA); // compile with API 23+
            builder.setKeySize(RSA_KEY_SIZE);
        }

        return builder.build();
    }

    @TargetApi(Build.VERSION_CODES.M)
    private static KeyGenParameterSpec getSymmetricKeyGenParameterSpec() {
        return new KeyGenParameterSpec.Builder(KEY_STORE_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT) //  | KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
//                .setBlockModes(KeyProperties.BLOCK_MODE_CTR)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .setKeySize(128)
                .setRandomizedEncryptionRequired(true)
                .build();
    }

    @TargetApi(Build.VERSION_CODES.M)
    private static KeyGenParameterSpec getKeyGenParameterSpec() {
        return new KeyGenParameterSpec.Builder(KEY_STORE_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT) //  | KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
                .setDigests(KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512, KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA224, KeyProperties.DIGEST_SHA1)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP, KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .setKeySize(RSA_KEY_SIZE)
                .setRandomizedEncryptionRequired(true)
                .build();
//
//
//        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(KEY_STORE_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);
//        return builder
//                .setKeySize(128)
//                .setBlockModes("CTR")
//                .setEncryptionPaddings("PKCS7Padding")
//                .setRandomizedEncryptionRequired(true)
////                    .setUserAuthenticationRequired(true)
////                    .setUserAuthenticationValidityDurationSeconds(5 * 60)
//                .build();

    }

//    public static PublicKey keyGen(Context context) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, NoSuchProviderException, InvalidAlgorithmParameterException {
//        PublicKey k = _keyGen(context);
//
//        KeyStore.PrivateKeyEntry e = (KeyStore.PrivateKeyEntry) ks.getEntry(KEY_STORE_ALIAS, null);
//
//
//    }

    static Key getKeyPreAPI18() {
        org.nick.androidkeystore.android.security.KeyStore ks = org.nick.androidkeystore.android.security.KeyStore.getInstance();

        String s = "state = " + ks.state().name() + " " + ks.state().ordinal();

        System.out.println(s);

        byte[] keyBytes = ks.get(KEY_STORE_ALIAS);

        if(keyBytes == null) {
            return null;
        }

        return new SecretKeySpec(keyBytes, "AES");
    }

    static Key keyGenPreAPI18() {

        org.nick.androidkeystore.android.security.KeyStore ks = org.nick.androidkeystore.android.security.KeyStore.getInstance();

        String s = "state = " + ks.state().name() + " " + ks.state().ordinal();

        System.out.println(s);

        ks.delete(KEY_STORE_ALIAS);

        byte[] keyBytes = Utils.secureRandomBytes(48); // 128 bits + 256 bits

        boolean success = ks.put(KEY_STORE_ALIAS, keyBytes);

        if (!success) {
            int errorCode = ks.getLastError();

            if(org.nick.androidkeystore.android.security.KeyStore.UNINITIALIZED == errorCode) {
                // skip keywrap entirely *********
            }

            new RuntimeException("Keystore error: " + errorCode).printStackTrace();

            return null;
        }

        return new SecretKeySpec(keyBytes, "AES");
    }

    static Key keyGen(Context context) throws CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException, KeyStoreException, NoSuchProviderException, InvalidAlgorithmParameterException {
        return Build.VERSION.SDK_INT < 18 ? keyGenPreAPI18() : _keyGen(context);
    }

    static Key _keyGen(Context context) throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException, IOException, CertificateException, KeyStoreException, UnrecoverableEntryException {

        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        ks.deleteEntry(KEY_STORE_ALIAS);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM_RSA, "AndroidKeyStore");

        final int apiLevel = Build.VERSION.SDK_INT;
        if(apiLevel < Build.VERSION_CODES.JELLY_BEAN_MR2) { // TODO minSdkVersion is 18 -- support devices without AndroidKeyStore

//            return keyGenPreAPI18();

            keyPairGenerator.initialize(RSA_KEY_SIZE);
            return keyPairGenerator.generateKeyPair().getPublic();
        } else if(apiLevel < Build.VERSION_CODES.M) {



            keyPairGenerator.initialize(getKeyPairGeneratorSpec(context, apiLevel, true, KEY_STORE_ALIAS));
            try {
                return keyPairGenerator.generateKeyPair().getPublic();
            } catch (Exception e) {
                System.out.println(e.getMessage() + " -- setting encryptionRequired to false");
                // try without encryptionRequired
                keyPairGenerator.initialize(getKeyPairGeneratorSpec(context, apiLevel, false, KEY_STORE_ALIAS));
                return keyPairGenerator.generateKeyPair().getPublic();
            }
        } else {

//            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "AndroidKeyStore");
//            keyGenerator.init(getSymmetricKeyGenParameterSpec());
//            SecretKey k = keyGenerator.generateKey();

//            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
//            keyGen.init(128);
//            SecretKey k0 =  keyGen.generateKey();
//
////            ks.put(KEY_STORE_ALIAS, k0);
//
//
////            return new KeyGenParameterSpec.Builder(KEY_STORE_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT) //  | KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
//////                .setBlockModes(KeyProperties.BLOCK_MODE_CTR)
////                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
////                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
////                    .setKeySize(128)
////                    .setRandomizedEncryptionRequired(true)
////                    .build();
//
//            KeyProtection kp = new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
//                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
//                               .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
//                    .setRandomizedEncryptionRequired(true)
//                  .build();
//
////            KeyStore.PasswordProtection pp = new KeyStore.PasswordProtection("YOYO".toCharArray());
//
//            ks.setEntry(KEY_STORE_ALIAS, new KeyStore.SecretKeyEntry(k0), kp);
//
//            // key retrieval
//
//            KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) ks.getEntry(KEY_STORE_ALIAS, null); // kp
//            SecretKey k1 = entry.getSecretKey();
//
//            try {
//                Cipher c = Cipher.getInstance("AES/CBC/PKCS7Padding", "AndroidOpenSSL");
//
//                c.init(Cipher.ENCRYPT_MODE, k0);
//
//                byte[] resu = c.doFinal(new byte[]{0, 0, 0});
//
//                TestUtils.print(resu);
//
//            } catch (NoSuchPaddingException e) {
//                e.printStackTrace();
//            } catch (InvalidKeyException e) {
//                e.printStackTrace();
//            } catch (BadPaddingException e) {
//                e.printStackTrace();
//            } catch (IllegalBlockSizeException e) {
//                e.printStackTrace();
//            }
//
//            try {
//                Cipher c = Cipher.getInstance("AES/CBC/PKCS7Padding", "AndroidOpenSSL");
//
//                c.init(Cipher.ENCRYPT_MODE, k1);
//
//                byte[] resu = c.doFinal(new byte[]{0, 0, 0});
//
//                TestUtils.print(resu);
//
//            } catch (NoSuchPaddingException e) {
//                e.printStackTrace();
//            } catch (InvalidKeyException e) {
//                e.printStackTrace();
//            } catch (BadPaddingException e) {
//                e.printStackTrace();
//            } catch (IllegalBlockSizeException e) {
//                e.printStackTrace();
//            }
//
//            return k1;

            keyPairGenerator.initialize(getKeyGenParameterSpec());
            return keyPairGenerator.generateKeyPair().getPublic();
        }
    }

//    @TargetApi(Build.VERSION_CODES.M)
//    static SecretKey keyGenAndroidM() throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException, IOException, CertificateException, KeyStoreException {
//        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
//        ks.load(null);
//        ks.deleteEntry(KEY_STORE_ALIAS);
//
//        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "AndroidKeyStore");
//
//        keyGenerator.init(getSymmetricKeyGenParameterSpec());
//
//        return keyGenerator.generateKey();
//    }

}
