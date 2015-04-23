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
import java.security.spec.AlgorithmParameterSpec;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Should be thread-safe.
 * Created by Evan Saulpaugh on 4/22/15.
 */
public class ControlTests {

    private static ExecutorService singleThreadExecutor;

    static void startSingleThreadExecutor() {
        singleThreadExecutor = Executors.newSingleThreadExecutor();
    }

    static void killSingleThreadExecutor() {
        singleThreadExecutor.shutdownNow();
    }

    public static byte[] decryptSingleThreaded(final CipherPool cipherPool, final byte[] input, final SecretKeySpec keySpec, final AlgorithmParameterSpec params) {
        final Callable call = new Callable() {
            @Override
            public Object call() throws Exception {
                Cipher cipher = cipherPool.getCipher();
                try {
                    cipher.init(Cipher.DECRYPT_MODE, keySpec, params);
                    return cipher.doFinal(input);
                } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
                    ex.printStackTrace();
                } finally {
                    cipherPool.returnCipher(cipher);
                }
                return null;
            }
        };

        final Future future = singleThreadExecutor.submit(call);

        try {
            return (byte[]) future.get();
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (ExecutionException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static class PartialDecrypt implements Runnable {
        private final CipherPool cipherPool;
        private final byte[] input;
        private final int offset;
        private final int inputLen;
        private final byte[] output;
        private final SecretKeySpec keySpec;
        private final AlgorithmParameterSpec params;

        public PartialDecrypt(CipherPool cipherPool, byte[] input, int offset, int inputLen, byte[] output, SecretKeySpec keySpec, AlgorithmParameterSpec params) {
            this.cipherPool = cipherPool;
            this.input = input;
            this.offset = offset;
            this.inputLen = inputLen;
            this.output = output;
            this.keySpec = keySpec;
            this.params = params;
        }

        @Override
        public void run() {
            Cipher cipher = cipherPool.getCipher();
            try {
                cipher.init(Cipher.DECRYPT_MODE, keySpec, params);
//                System.out.println(offset + " --> " + (offset + inputLen) + "" + cipher.getAlgorithm());
                cipher.doFinal(input, offset, inputLen, output, offset);
            } catch (InvalidKeyException | InvalidAlgorithmParameterException | ShortBufferException | IllegalBlockSizeException | BadPaddingException ex) {
                ex.printStackTrace();
            } finally {
                cipherPool.returnCipher(cipher);
            }
        }
    }

    /**
     * Returns the initialization vector for a given offset in a ciphertext produced by CBC.
     * @param input
     * @param newOffset
     * @param cipherBlockSize
     * @return
     */
    private static IvParameterSpec getCBCIVForOffset(byte[] input, int newOffset, int cipherBlockSize) {
        byte[] initializationVector = new byte[cipherBlockSize];
        System.arraycopy(input, newOffset - cipherBlockSize, initializationVector, 0, cipherBlockSize);
        return new IvParameterSpec(initializationVector);
    }

    public static byte[] decryptMultithreaded(final CipherPool cipherPool, byte[] input, SecretKeySpec keySpec, AlgorithmParameterSpec params, final int outputLen, int numThreads) {
        if(numThreads < 1) {
            throw new IllegalArgumentException("numThreads must be greater than 1");
        }
        final int CIPHER_BLOCK_BYTE_LENGTH = cipherPool.getCipherBlockSize();
        final int CHUNK_BYTE_LENGTH = input.length / numThreads / CIPHER_BLOCK_BYTE_LENGTH * CIPHER_BLOCK_BYTE_LENGTH;
        if(CHUNK_BYTE_LENGTH <= 0) {
            int n = input.length / CIPHER_BLOCK_BYTE_LENGTH;
            int inputBlockLength = input.length % CIPHER_BLOCK_BYTE_LENGTH == 0 ? n : n + 1;
            throw new IllegalArgumentException("input block length cannot be less than numThreads: " + inputBlockLength + " < " + numThreads);
//            throw new IllegalArgumentException("input is too short to be split " + (numThreads == 2 ? "between 2 threads" : "among " + numThreads + " threads"));
        }
//        if(numThreads == 1 || CHUNK_BYTE_LENGTH == 0) {
//            return decryptSingleThreaded(cipherPool, input, keySpec, params);
//        }

        // first chunk
        int offset = 0;
        byte[] output = new byte[outputLen];

        CipherPool noPaddingCipherPool = ForkJoinDecryptTask.getNoPaddingCipherPool(cipherPool);

        Thread firstChunk = new Thread(new PartialDecrypt(noPaddingCipherPool, input, offset, CHUNK_BYTE_LENGTH, output, keySpec, params));
        firstChunk.start();

        // middle chunks
        final int NUM_MIDDLE_CHUNKS = numThreads - 2;
        Thread[] middleChunks = new Thread[NUM_MIDDLE_CHUNKS];
        for(int i = 0; i < NUM_MIDDLE_CHUNKS; i++) {
            offset += CHUNK_BYTE_LENGTH;
            AlgorithmParameterSpec newParams = params == null ? null : getCBCIVForOffset(input, offset, CIPHER_BLOCK_BYTE_LENGTH);
            Thread t_i = new Thread(new PartialDecrypt(noPaddingCipherPool, input, offset, CHUNK_BYTE_LENGTH, output, keySpec, newParams));
            t_i.start();
            middleChunks[i] = t_i;
        }

        // last chunk
        offset += CHUNK_BYTE_LENGTH;
        AlgorithmParameterSpec lastParams = params == null ? null : getCBCIVForOffset(input, offset, CIPHER_BLOCK_BYTE_LENGTH);
        new PartialDecrypt(cipherPool, input, offset, input.length - offset, output, keySpec, lastParams).run();// with padding, run on current thread

        // when finished, wait for threads to join
        try {
            firstChunk.join();
            for (Thread t : middleChunks) {
                t.join();
            }
        } catch (InterruptedException ie) {
            ie.printStackTrace();
        }

        return output;
    }
}
