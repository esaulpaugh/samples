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

import java.lang.reflect.Field;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import static samples.esaulpaugh.encryptednotepad.Constants.*;

/**
 * Created by esaulpaugh on 3/20/16.
 */
public class AuthEncryptionKey implements Destroyable {

    private transient SecretKeySpec encryptionKey;

    private transient SecretKeySpec macKey;

    private boolean destroyed = false;

    public AuthEncryptionKey(SecretKeySpec encryptionKey, SecretKeySpec macKey) {
        if(encryptionKey == null) {
            throw new IllegalArgumentException("encryptionKey is null");
        }
        if(macKey == null) {
            throw new IllegalArgumentException("macKey is null");
        }
        this.encryptionKey = encryptionKey;
        this.macKey = macKey;
    }

    public SecretKeySpec getEncryptionKey() {
        return encryptionKey;
    }

    public SecretKeySpec getMACKey() {
        return macKey;
    }

    @Override
    public void destroy() throws DestroyFailedException {

        synchronized (AuthEncryptionKey.this) {
            if (!destroyed) {
                try {
                    Class<?> encryptionKeyClass = this.encryptionKey.getClass();
                    Class<?> macKeyClass = this.macKey.getClass();

                    Field encryptionKeyField = encryptionKeyClass.getDeclaredField("key");
                    Field macKeyField = macKeyClass.getDeclaredField("key");

                    encryptionKeyField.setAccessible(true);
                    macKeyField.setAccessible(true);

                    byte[] encryptionKeyBytes = (byte[]) encryptionKeyField.get(this.encryptionKey);
                    byte[] macKeyBytes = (byte[]) macKeyField.get(this.macKey);

                    overwriteBytes(encryptionKeyBytes, 2);
                    overwriteBytes(macKeyBytes, 2);

                    this.encryptionKey = null;
                    this.macKey = null;

                    System.gc();

                    destroyed = true;

                } catch (Exception e) {
                    destroyed = false;
                    throw new DestroyFailedException(e.getMessage());
                }
            } else {
                throw new DestroyFailedException("already destroyed");
            }
        }
    }

    private void overwriteBytes(final byte[] bytes, final int numTimes) {
        final int numBytes = bytes.length;
        final byte[] randomBytes = new byte[numBytes];

        int i;
        for(int n = 0; n < numTimes; n++) {
            Utils.secureRandomBytes(randomBytes);
            for (i = 0; i < numBytes; i++) {
                bytes[i] ^= randomBytes[i];
            }
        }
    }

//    private void overwriteKeyBytes(byte[] encryptionKeyBytes, byte[] macKeyBytes) {
//        final int numKeyBytes = encryptionKeyBytes.length + macKeyBytes.length;
//        byte[] randomBytes = Utils.secureRandomBytes(numKeyBytes);
//        int i;
//        for(i = 0; i < encryptionKeyBytes.length; i++) {
//            encryptionKeyBytes[i] ^= randomBytes[i];
//        }
//        for(int j = 0; i < numKeyBytes; i++, j++) {
//            macKeyBytes[j] ^= randomBytes[i];
//        }
//    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }
}
