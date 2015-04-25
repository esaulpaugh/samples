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
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.concurrent.RecursiveAction;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A recursive divide-and-conquer approach to decryption in parallel.
 * @author esaulpaugh
 */
public class ForkJoinDecryptTask extends RecursiveAction {
    private static final long serialVersionUID = 1863501128822072914L;

    private static final String ANDROID_OPEN_SSL = "AndroidOpenSSL";
    private static final String SUFFIX_NO_PADDING = "/NoPadding";

    private static final int DEFAULT_FORK_JOIN_DIVISOR = ((int) Math.pow(2, 9)) - 1;// 511

    private final ForkJoinJDecryptParams params;
    private final int offset;
    private final int inputLen;
    private final AlgorithmParameterSpec cipherParams;
    private final boolean finalPart;

    /**
     * Does not accept inputs less than 511 blocks in length (511 * 16 = 8176 bytes, 511 * 8 = 4088 bytes).
     * @param algorithm
     * @param key
     * @param input
     * @param output
     */
    public ForkJoinDecryptTask(String algorithm, SecretKeySpec key, byte[] input, byte[] output) {
        this(algorithm, key, null, input, output);
    }

    /**
     * Does not accept inputs less than 511 blocks in length (511 * 16 = 8176 bytes, 511 * 8 = 4088 bytes).
     * @param algorithm
     * @param key
     * @param cipherParams
     * @param input
     * @param output
     */
    public ForkJoinDecryptTask(String algorithm, SecretKeySpec key, AlgorithmParameterSpec cipherParams, byte[] input, byte[] output) {
        this(algorithm, null, key, cipherParams, input, output, input.length / DEFAULT_FORK_JOIN_DIVISOR);
    }

    public ForkJoinDecryptTask(String algorithm, Provider provider, SecretKeySpec key, AlgorithmParameterSpec cipherParams, byte[] input, byte[] output, int maxPartLength) {
        this(new CipherPool(algorithm, provider), key, cipherParams, input, output, maxPartLength);
    }

    /**
     *
     * @param cipherPool
     * @param key
     * @param cipherParams
     * @param input
     * @param output
     * @param maxPartLength
     */
    public ForkJoinDecryptTask(CipherPool cipherPool, SecretKeySpec key, AlgorithmParameterSpec cipherParams, byte[] input, byte[] output, int maxPartLength) {
        this(new ForkJoinJDecryptParams(cipherPool, key, input, output, maxPartLength), 0, input.length, cipherParams, true);
    }

    private ForkJoinDecryptTask(ForkJoinJDecryptParams params, int offset, int inputLen, AlgorithmParameterSpec cipherParams, boolean finalPart) {
        this.params = params;
        this.cipherParams = cipherParams;
        this.offset = offset;
        this.inputLen = inputLen;
        this.finalPart = finalPart;
//        TestDecrypt.forkCount.incrementAndGet();
    }

    public static CipherPool getNoPaddingCipherPool(CipherPool regular) {
        String algorithm = regular.getAlgorithm();
        if (algorithm.endsWith(SUFFIX_NO_PADDING))
            return regular;
        String algorithmNoPadding = algorithm.substring(0, algorithm.lastIndexOf('/')) + SUFFIX_NO_PADDING;
        return new CipherPool(algorithmNoPadding, regular.getProvider(), regular.getCipherBlockSize());
    }

    /**
     * Holds parameters whose values are common to all sub-tasks.
     * @author esaulpaugh
     */
    private static class ForkJoinJDecryptParams {
        final CipherPool regularCipherPool;
        final CipherPool noPaddingCipherPool;
        final int cipherBlockSize;
        final SecretKeySpec key;
        final byte[] input;
        final byte[] output;
        final int maxPartLength;

        public ForkJoinJDecryptParams(CipherPool cipherPool, SecretKeySpec key, byte[] input, byte[] output, int maxPartLength) {
            String algorithm = cipherPool.getAlgorithm();
            checkNotSupported(algorithm);
            this.regularCipherPool = cipherPool;
            this.noPaddingCipherPool = getNoPaddingCipherPool(cipherPool);
            this.key = key;
            this.input = input;
            this.output = output;
            this.cipherBlockSize = cipherPool.getCipherBlockSize();
            if(maxPartLength < cipherPool.getCipherBlockSize()) {
                throw new IllegalArgumentException("maxPartLength cannot be less than cipher block size: "
                        + maxPartLength + " < " + cipherPool.getCipherBlockSize());
            }
            this.maxPartLength = maxPartLength;
        }
    }

    /**
     * Rejects algorithms that do not allow for parallelized decryption by recursive decomposition.
     * @param algorithm
     */
    private static void checkNotSupported(final String algorithm) {
        if(algorithm.contains("PBE") && (algorithm.contains("SHA") || algorithm.contains("MD5")))
            throw new UnsupportedOperationException("Unsupported algorithm: " + algorithm
                    + "\tThis class does not support password-based encryption algorithms.");
        int idx = algorithm.indexOf('/');
        if(idx == -1)
            return;
        int modeStart = idx + 1;
        String mode = algorithm.substring(modeStart, algorithm.indexOf('/', modeStart));
        switch(mode) {
        case "CTR":
        case "OFB":
        case "PCBC":
            throw new UnsupportedOperationException("Unsupported algorithm: " + algorithm
                    + '\t' + mode + " mode does not allow for parallelized decryption");
        case "CCM":
        case "OCB":
        case "EAX":
        case "GCM":
            throw new UnsupportedOperationException("Unsupported algorithm: " + algorithm
                    + "\tThis class does not support authenticated encryption algorithms.");
        }
    }

    /**
     * Borrows a cipher instance from the appropriate {@link CipherPool}.
     * @param forFinalPart
     * @return
     */
    private Cipher getCipher(boolean forFinalPart) {
        return forFinalPart
                ? params.regularCipherPool.getCipher()
                : params.noPaddingCipherPool.getCipher();
    }

    /**
     * Returns a cipher instance to the appropriate {@link CipherPool}.
     * @param cipher
     * @param forFinalPart
     */
    private void returnCipher(Cipher cipher, boolean forFinalPart) {
        if (forFinalPart) {
            params.regularCipherPool.returnCipher(cipher);
        } else {
            params.noPaddingCipherPool.returnCipher(cipher);
        }
    }

    private void doWork() {
        Cipher cipher = getCipher(finalPart);
        try {
            cipher.init(Cipher.DECRYPT_MODE, params.key, cipherParams);
            if(!finalPart) {
                cipher.update(params.input, offset, inputLen, params.output, offset);
            } else {
                cipher.doFinal(params.input, offset, inputLen, params.output, offset);
            }
        } catch (InvalidKeyException | InvalidAlgorithmParameterException
                | IllegalBlockSizeException | BadPaddingException ex) {
            ex.printStackTrace();
        } catch (ShortBufferException sbe) {
            sbe.printStackTrace();
            System.err.println(cipher.getAlgorithm() + " " + cipher.getProvider());
            if (sbe.getMessage().contains("output buffer too small during update")
                    && cipher.getProvider().getName().equals(ANDROID_OPEN_SSL)) {
                if (!cipher.getAlgorithm().endsWith(SUFFIX_NO_PADDING)) {
                    new BadPaddingException(cipher.getProvider() + " " + cipher.getAlgorithm()
                            + " Try a different provider or give a larger output buffer, or use /NoPadding."
                            + " See https://bugs.openjdk.java.net/browse/JDK-4513830 for related information.")
                            .printStackTrace();
                }
            }
        } finally {
//            System.out.println("i" + params.input.length + " " + "o" + params.output.length + "\t " + offset + "\t-->\t" + (offset + inputLen));
            returnCipher(cipher, finalPart);
        }
    }

    /**
     * Returns the initialization vector for a given offset in a ciphertext produced by CBC.
     * @param newOffset
     * @return
     */
    private IvParameterSpec getCBCIVForOffset(int newOffset) {
        byte[] initializationVector = new byte[params.cipherBlockSize];
        System.arraycopy(params.input, newOffset - params.cipherBlockSize, initializationVector, 0, params.cipherBlockSize);
        return new IvParameterSpec(initializationVector);
    }

    @Override
    protected void compute() {
        if (inputLen > params.maxPartLength) {
            /* Split work in half and recurse */
            final int len1 = (inputLen / 2 / params.cipherBlockSize * params.cipherBlockSize);// round midpoint down to nearest multiple of block size
            final int offset2 = offset + len1;
            final int len2 = inputLen - len1;
            final AlgorithmParameterSpec cipherParams2 = cipherParams == null ? null : getCBCIVForOffset(offset2);

            try {
                /* invoke sub-tasks and wait for them to complete */
                invokeAll(
                        new ForkJoinDecryptTask(params, offset, len1, cipherParams, false),// is not finalPart
                        new ForkJoinDecryptTask(params, offset2, len2, cipherParams2, finalPart)// is finalPart if this task was
                );
            } catch (OutOfMemoryError oome) {
                System.out.println("active threads = " + Thread.activeCount());
                throw oome;
            }
        } else {
            doWork();
        }
    }
}