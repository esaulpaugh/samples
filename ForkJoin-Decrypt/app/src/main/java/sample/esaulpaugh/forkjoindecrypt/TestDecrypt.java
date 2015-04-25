/*
 * Copyright 2015 Evan Saulpaugh
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sample.esaulpaugh.forkjoindecrypt;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author esaulpaugh
 */
public class TestDecrypt {

    private static final int TEST_PLAINTEXT_BYTE_LENGTH = 9 * 1024 * 1024;
    private static final int MULTITHREADED_NUM_THREADS = 9;// i.e. Runtime.getRuntime().availableProcessors() + 1
    private static final int CUSTOM_FORK_JOIN_DIVISOR = ((int) Math.pow(2, 9)) - 1;// 511

//    private static final int TEST_PLAINTEXT_BYTE_LENGTH = 8176;// or 8160 + padding
//    private static final int MULTITHREADED_NUM_THREADS = 511;
//    private static final int CUSTOM_FORK_JOIN_DIVISOR = 511;

    private static final int TIMEOUT_SECONDS = 60;

    private static final double NANOS_PER_MILLI = 1000000.0;

    private static final int SINGLE_THREADED = 0, MULTI_THREADED = 1, FORK_JOIN = 2;

    private static final int[] TESTS_TO_RUN= { SINGLE_THREADED, MULTI_THREADED, FORK_JOIN };// MULTI_THREADED

    private static boolean testRunSuccess;

    public static AtomicInteger forkCount = new AtomicInteger(0);

    private static double sTotal = 0.0;
    private static double mTotal = 0.0;
    private static double fTotal = 0.0;

    private static double minSingleThreadedTime = Integer.MAX_VALUE;
    private static double minMultithreadedTime = Integer.MAX_VALUE;
    private static double minForkJoinTime = Integer.MAX_VALUE;

    private static final String PROVIDER_BOUNCY_CASTLE = "BC";
    private static final String[] BOUNCY_CASTLE_ALGORITHMS = new String[] {
            "AES/CBC/PKCS5Padding",
            "AES/ECB/PKCS5Padding",
            "AES/CFB/PKCS5Padding",

            "DES/CBC/PKCS5Padding",
            "DES/ECB/PKCS5Padding",
            "DES/CFB/PKCS5Padding",

            "DESede/CBC/PKCS5Padding",
            "DESede/ECB/PKCS5Padding",
            "DESede/CFB/PKCS5Padding",

            "Blowfish/CBC/PKCS5Padding",
            "Blowfish/ECB/PKCS5Padding",
            "Blowfish/CFB/PKCS5Padding",

            "AES/CBC/NoPadding",
            "AES/ECB/NoPadding",
            "AES/CFB/NoPadding",

            "DES/CBC/NoPadding",
            "DES/ECB/NoPadding",
            "DES/CFB/NoPadding",

            "DESede/CBC/NoPadding",
            "DESede/ECB/NoPadding",
            "DESede/CFB/NoPadding",

            "Blowfish/CBC/NoPadding",
            "Blowfish/ECB/NoPadding",
            "Blowfish/CFB/NoPadding",
    };

    private static final String PROVIDER_ANDROID_OPEN_SSL = "AndroidOpenSSL";
    private static final String[] ANDROID_OPEN_SSL_ALGORITHMS = new String[] {
            "AES/CBC/PKCS5Padding",
            "AES/ECB/PKCS5Padding",

            "DESede/CBC/PKCS5Padding",
            "DESede/ECB/PKCS5Padding",

            "AES/CBC/NoPadding",
            "AES/ECB/NoPadding",
            "AES/CFB/NoPadding",

            "DESede/CBC/NoPadding",
            "DESede/ECB/NoPadding",
            "DESede/CFB/NoPadding",
    };

    private static final String PROVIDER_SUN_JCE = "SunJCE";
    private static final String[] SUN_JCE_ALGORITHMS = BOUNCY_CASTLE_ALGORITHMS;

/*
            "Camellia",
            "CAST5"
            "CAST6"
            "GOST28147"
            "IDEA"
            "Noekeon",
            "RC2",
            "RC6",
            "Rijndael",
            "SEED",
            "Serpent",
            "Shacal2",
            "Skipjack",
            "TEA",
            "Threefish",
            "Twofish",
            "XTEA",
*/

    private static String decryptMethodToString(int decryptMethod) {
        switch (decryptMethod) {
        case SINGLE_THREADED: return "Single-threaded";
        case MULTI_THREADED: return "Multithreaded";
        case FORK_JOIN: return "ForkJoin";
        }
        return null;
    }

    private static byte[] secureRandomBytes(int n) {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[n];
        random.nextBytes(bytes);
        return bytes;
    }

    public static void printBytes(byte[] bytes) {
        printBytes(bytes, bytes.length);
    }

    public static void printChars(byte[] bytes) {
        printChars(bytes, bytes.length);
    }

    public static void printBytes(byte[] bytes, int lim) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < lim; i++) {
            sb.append(bytes[i]).append(", ");
        }
        System.out.println(sb.toString());
    }

    public static void printChars(byte[] bytes, int lim) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append((char) b).append(" ");
        }
        System.out.println(sb.toString());
    }

    private static byte[] encrypt(String algorithm, Provider provider, byte[] input, SecretKeySpec key, AlgorithmParameterSpec params) {
        try {
            Cipher c = Cipher.getInstance(algorithm, provider);
            c.init(Cipher.ENCRYPT_MODE, key, params);
            return c.doFinal(input);
        } catch (NoSuchAlgorithmException
                | InvalidKeyException
                | NoSuchPaddingException
                | BadPaddingException
                | IllegalBlockSizeException
                | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] forkJoinDecrypt(CipherPool cipherPool, byte[] input, SecretKeySpec key, AlgorithmParameterSpec params, int outputLen, int maxPartLength) {
        ForkJoinPool pool = new ForkJoinPool(Runtime.getRuntime().availableProcessors());
        byte[] output = new byte[outputLen];
        ForkJoinDecryptTask task = new ForkJoinDecryptTask(cipherPool, key, params, input, output, maxPartLength);
        pool.invoke(task);
        pool.awaitQuiescence(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        pool.shutdownNow();
        return output;
    }

    private static SecretKeySpec generateKey(String algorithm) {
        final String KEY_ALG = algorithm.substring(0, algorithm.indexOf('/'));
        final int KEY_SIZE = algorithm.startsWith("AES/")
                ? 16
                : (algorithm.startsWith("DESede") ? 24 : 8);
        byte[] keyBytes = secureRandomBytes(KEY_SIZE);
        return new SecretKeySpec(keyBytes, KEY_ALG);
    }

    private static void simulateDecryptFailure(byte[] decrypted, double probability) {
        Random r = new Random();
        r.setSeed(System.nanoTime() * System.nanoTime() * System.nanoTime());
        if(r.nextDouble() < probability) {// Math.random()
            decrypted[decrypted.length / 2]++;
            System.out.println("*** simulated failure ***");
        }
    }

    private static byte[] execute(int decryptMethod, CipherPool cipherPool, byte[] ciphertext, SecretKeySpec key, AlgorithmParameterSpec params, int outputBufferLen) {
//        System.out.println("execute " + decryptMethodToString(decryptMethod) + " " + cipherPool.getAlgorithm());
        switch (decryptMethod) {
        case SINGLE_THREADED:
            return ControlTests.decryptSingleThreaded(cipherPool, ciphertext, key, params);
        case MULTI_THREADED:
            return ControlTests.decryptMultithreaded(cipherPool, ciphertext, key, params, outputBufferLen, MULTITHREADED_NUM_THREADS);// Runtime.getRuntime().availableProcessors()
        case FORK_JOIN:
            return forkJoinDecrypt(cipherPool, ciphertext, key, params, outputBufferLen, ciphertext.length / CUSTOM_FORK_JOIN_DIVISOR);
        default:
            return null;
        }
    }

    private static void test(final String algorithm, final Provider provider, final byte[] plaintext, final int decryptMethod) throws Exception {

        System.out.println(decryptMethodToString(decryptMethod) + ": " + algorithm + ", " + provider);

        final int BLOCK_SIZE = algorithm.startsWith("AES/") ? 16 : 8;

        SecretKeySpec key = generateKey(algorithm);

//        printBytes(plaintext, 35);

        byte[] ivBytes = secureRandomBytes(BLOCK_SIZE);
        AlgorithmParameterSpec params = algorithm.contains("-CBC")
                || algorithm.contains("/CBC/")
                || algorithm.contains("/CTR/")
                || algorithm.contains("/PCBC/")
                || algorithm.contains("/CFB/")
                || algorithm.contains("/OFB/")
                ? new IvParameterSpec(ivBytes)
                : null;

        byte[] ciphertext = encrypt(algorithm, provider, plaintext, key, params);

//        System.out.println("ciphertext len = " + ciphertext.length);
//        printBytes(ciphertext);

        final int outputBufferLen;
        if (provider.getName().equals(PROVIDER_ANDROID_OPEN_SSL) && decryptMethod != SINGLE_THREADED) {
            outputBufferLen = plaintext.length + 32;// https://bugs.openjdk.java.net/browse/JDK-4513830
        } else {
            outputBufferLen = plaintext.length;
        }

        long start, end;


        byte[] output;
        CipherPool cipherPool = new CipherPool(algorithm, provider);

        // warmup
        execute(decryptMethod, cipherPool, ciphertext, key, params, outputBufferLen);

        forkCount.set(0);

        start = System.nanoTime();
        output = execute(decryptMethod, cipherPool, ciphertext, key, params, outputBufferLen);
        end = System.nanoTime();

//        if(decryptMethod == FORK_JOIN)
//            System.out.println("forkjoin tasks created = " + forkCount.get() + " fork join divisor = " + FORK_JOIN_DIVISOR);


        final byte[] decrypted;
        if (provider.getName().equals(PROVIDER_ANDROID_OPEN_SSL)) {
            decrypted = new byte[plaintext.length];
            System.arraycopy(output, 0, decrypted, 0, decrypted.length);
        } else {
            decrypted = output;
        }

//        simulateDecryptFailure(decrypted, 0.02);

//        printBytes(decrypted, 35);

        boolean decryptSuccess = Arrays.equals(plaintext, decrypted);

        testRunSuccess &= decryptSuccess;

//        if(!success)
//            throw new Exception("FAILURE");

        long elapsed = end - start;
        if (decryptMethod == SINGLE_THREADED) {
            sTotal += elapsed;
            minSingleThreadedTime = Math.min(minSingleThreadedTime, elapsed);
        } else if (decryptMethod == MULTI_THREADED) {
            mTotal += elapsed;
            minMultithreadedTime = Math.min(minMultithreadedTime, elapsed);
        } else {
            fTotal += elapsed;
            minForkJoinTime = Math.min(minForkJoinTime, elapsed);
        }
        String message = "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t" + (decryptSuccess ? "SUCCESS" : "*** FAILURE ***") + " (" + (end - start) / NANOS_PER_MILLI + " ms)";
        System.out.println(message);
    }

    public static void test() throws Exception {

        for (Provider p : Security.getProviders()) {
            System.out.println("------- " + p.getName() + " -------");
            for (Provider.Service s : p.getServices()) {
                System.out.println(s.getAlgorithm());
            }
        }
        System.out.println();


//        final byte[] plaintext =
//                  "abcdefghij______"
//                + "0123456789ABCDEF"
//                + "hhhhhhhhhhiiiiii"
//                + "0123456789012345".getBytes(java.nio.charset.Charset.forName("UTF-8"));

        ControlTests.startSingleThreadExecutor();
        try {

            Provider bouncyCastle = Security.getProvider(PROVIDER_BOUNCY_CASTLE);
            Provider androidOpenSSL = Security.getProvider(PROVIDER_ANDROID_OPEN_SSL);
            Provider sunJCE = Security.getProvider(PROVIDER_SUN_JCE);
            int NUM_RUNS = 200;

//        for (int y = 1; y < 2; y++) {//TEST_PLAINTEXT_BYTE_LENGTH *= 2

            final byte[] plaintext = secureRandomBytes(TEST_PLAINTEXT_BYTE_LENGTH);

//            for (int j = 2; j < 2 + NUM_RUNS; j += 1) {
            testRunSuccess = true;

            try {

                for (int x = 0; x < TESTS_TO_RUN.length; x++) {
                    if (bouncyCastle != null) {
                        // Bouncy Castle
                        for (int i = 0; i < BOUNCY_CASTLE_ALGORITHMS.length; i++)
                            test(BOUNCY_CASTLE_ALGORITHMS[i], bouncyCastle, plaintext, TESTS_TO_RUN[x]);
                    }
                    if (androidOpenSSL != null) {
                        // AndroidOpenSSL
                        for (int i = 0; i < ANDROID_OPEN_SSL_ALGORITHMS.length; i++)
                            test(ANDROID_OPEN_SSL_ALGORITHMS[i], androidOpenSSL, plaintext, TESTS_TO_RUN[x]);
                    }
                    if (sunJCE != null) {
                        // Sun Java Cryptography Extension
                        for (int i = 0; i < SUN_JCE_ALGORITHMS.length; i++)
                            test(SUN_JCE_ALGORITHMS[i], sunJCE, plaintext, TESTS_TO_RUN[x]);
                    }
                }

            } catch (Throwable t) {
                testRunSuccess = false;
                t.printStackTrace();
            }

            if (testRunSuccess) {
                System.out.println("\n*** TEST RUN SUCCESS ***\n");
            } else {
                System.err.println("\n*** TEST RUN FAILURE ***\n");
            }
//            }

            if (BOUNCY_CASTLE_ALGORITHMS.length == 1) {
                System.out.println("algorithm = " + BOUNCY_CASTLE_ALGORITHMS[0] + ", " + sunJCE);// bouncyCastle, androidOpenSSL
                System.out.println("multithreaded num threads = " + MULTITHREADED_NUM_THREADS);
                System.out.println("file size = " + TEST_PLAINTEXT_BYTE_LENGTH);
                System.out.println("minSingleThreadedTime = " + minSingleThreadedTime / NANOS_PER_MILLI);
                System.out.println("minMultithreadedTime = " + minMultithreadedTime / NANOS_PER_MILLI);
                System.out.println("minForkJoinTime = " + minForkJoinTime / NANOS_PER_MILLI);

                System.out.println("sAverage = " + sTotal / NUM_RUNS / NANOS_PER_MILLI);
                System.out.println("mAverage = " + mTotal / NUM_RUNS / NANOS_PER_MILLI);
                System.out.println("fAverage = " + fTotal / NUM_RUNS / NANOS_PER_MILLI);
            }

//        }

        } finally {
            ControlTests.killSingleThreadExecutor();
        }
    }

    public static void main(String[] args0) throws Exception {
        test();
    }
/*
    algorithm = AES/ECB/NoPadding, SunJCE version 1.8
    forkCount = 1022 fork join factor = 511
    multithreaded num threads = 9
    file size = 9437184
    minSingleThreadedTime = 7.708151
    minMultithreadedTime = 3.124018
    minForkJoinTime = 2.717494
    sAverage = 9.15207982
    mAverage = 4.779768545
    fAverage = 3.595807565
*/
}
