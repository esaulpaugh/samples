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

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.util.Stack;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 * A thread-safe pool of {@link Cipher} instances.
 * @author esaulpaugh
 */
public class CipherPool {

    private final String algorithm;
    private final Provider provider;
    private final Stack<Cipher> pool;
    private final int maxPoolSize;
    private final int cipherBlockSize;

    public CipherPool(String algorithm) {
        this(algorithm, null);
    }

    public CipherPool(String algorithm, Provider provider) {
        this(algorithm, provider, -1);
    }

    public CipherPool(String algorithm, Provider provider, int cipherBlockSize) {
        this(algorithm, provider, cipherBlockSize, 1, Runtime.getRuntime().availableProcessors());
    }

    public CipherPool(String algorithm, Provider provider, int cipherBlockSize, int initialPoolSize, int maxPoolSize) {
        if(initialPoolSize < 0) {
            throw new IllegalArgumentException("initialPoolSize must be non-negative");
        }
        if(initialPoolSize > maxPoolSize) {
            throw new IllegalArgumentException("initialPoolSize cannot be greater than maxPoolSize: "
                    + initialPoolSize + " > " + maxPoolSize);
        }
        this.algorithm = algorithm;
        this.provider = provider;
        this.pool  = new Stack<>();
        this.maxPoolSize = maxPoolSize;
        if(cipherBlockSize == -1) {
            Cipher c = createCipherInstance();
            this.cipherBlockSize = c.getBlockSize();
            if(initialPoolSize > 0) {
                pool.push(c);
            }
        } else {
            this.cipherBlockSize = cipherBlockSize;
        }
        for (int i = pool.size(); i < initialPoolSize; i++) {
            pool.push(createCipherInstance());
        }
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public Provider getProvider() {
        return provider;
    }

    public int getCipherBlockSize() {
        return cipherBlockSize;
    }

    public int getMaxPoolSize() {
        return maxPoolSize;
    }

    public int getSize() {
        return pool.size();
    }

    /**
     * Attempts to borrow a Cipher instance from the pool. If the pool is empty, this method returns a new Cipher instance.
     * @return
     */
    public synchronized Cipher getCipher() {
        if(!pool.isEmpty()) {
            return pool.pop();
        }
        return createCipherInstance();// don't block if pool is empty, create new instance
    }

    /**
     * Attempts to return a Cipher instance to the pool. If the pool is full, this method does nothing.
     * @param cipher
     */
    public synchronized void returnCipher(Cipher cipher) {
        if(pool.size() < maxPoolSize) {// don't overfill pool
            pool.push(cipher);
        }
    }

    /**
     * Returns a new Cipher instance.
     * @return
     */
    private Cipher createCipherInstance() {
//        System.out.println("CREATE " + algorithm + " " + (provider != null ? provider : "????"));
        try {
            return provider == null
                    ? Cipher.getInstance(algorithm)
                    : Cipher.getInstance(algorithm, provider);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            ex.printStackTrace();
        }
        return null;
    }
}
