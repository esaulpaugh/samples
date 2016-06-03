package samples.esaulpaugh.encryptednotepad;

import android.util.Base64;

import java.security.SecureRandom;

import static samples.esaulpaugh.encryptednotepad.Constants.BASE_64_FLAGS;

/**
 * Created by esaulpaugh on 3/20/16.
 */
public class Utils {

    private static final long RESEED_INTERVAL_MILLIS = 20L * 60 * 1000; // 20 minutes

    private static final ThreadLocal<SecurePRNG> SECURE_PRNG_THREAD_LOCAL = new ThreadLocal<SecurePRNG>() {
        @Override
        public SecurePRNG initialValue() {
            return new SecurePRNG(RESEED_INTERVAL_MILLIS);
        }
    };

    /**
     * Not synchronized internally -- not inherently thread-safe
     */
    private static class SecurePRNG {

        private final long reseedIntervalMillis;

        private SecureRandom secureRandom;
        private static long lastReseedTimeMillis = 0;

        private SecurePRNG(long reseedIntervalMillis) {
            seed();
            this.reseedIntervalMillis = reseedIntervalMillis;
        }

        private void seed() {
            secureRandom = new SecureRandom();
            lastReseedTimeMillis = System.currentTimeMillis();
        }

        private SecureRandom getSecureRandom() {

            System.out.println("getSecureRandom()");

            if(System.currentTimeMillis() - lastReseedTimeMillis > reseedIntervalMillis) {
                seed();
            }

            return secureRandom;
        }

    }

    public static byte[] secureRandomBytes(int n) {
        byte[] bytes = new byte[n];

        secureRandomBytes(bytes);

        return bytes;
    }

    public static synchronized void secureRandomBytes(byte[] buffer) {
        SECURE_PRNG_THREAD_LOCAL.get().getSecureRandom().nextBytes(buffer);
    }

    public static String secureRandomString(int len) {
        byte[] bytes = secureRandomBytes((int) Math.ceil(len / 4.0 * 3.0));
        return encode(bytes).substring(0, len);
    }

    public static String encode(byte[] bytes) {
        return Base64.encodeToString(bytes, BASE_64_FLAGS);
    }

    public static byte[] decode(String encoded) {
        return Base64.decode(encoded, BASE_64_FLAGS);
    }

}
