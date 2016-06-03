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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import samples.esaulpaugh.encryptednotepad.crypto.PrngFixes;

/**
 * Created by esaulpaugh on 3/20/16.
 */
public class EncryptionManager implements Destroyable {

    private static final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding"; // PKCS7Padding
    private static final String MAC_ALGORITHM = "HmacSHA1";

    private static final int IV_LENGTH_BYTES = 16;
    private static final int MAC_LENGTH_BYTES = 20;

    private transient Cipher cipher;
    private transient Mac hmac;

    private transient AuthEncryptionKey authEncryptionKey;

    private transient boolean destroyed = false;

    private static final AtomicBoolean PRNG_FIXED = new AtomicBoolean(false);

    public EncryptionManager(AuthEncryptionKey authEncryptionKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        fixPrng();

        this.authEncryptionKey = authEncryptionKey;

        this.cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        this.hmac = Mac.getInstance(MAC_ALGORITHM);
        this.hmac.init(authEncryptionKey.getMACKey());
    }

    /**
     * Ensures that the PRNG is fixed. Should be used before generating any keys.
     * Will only run once, and every subsequent call should return immediately.
     */
    private static void fixPrng() {
        if (!PRNG_FIXED.get()) {
            synchronized (PrngFixes.class) {
                if (!PRNG_FIXED.get()) {
                    PrngFixes.apply();
                    PRNG_FIXED.set(true);
                }
            }
        }
    }

    public EncryptedMessage encrypt(byte[] input) {

        if(this.destroyed) {
            throw new IllegalStateException("this instance is destroyed");
        }

        try {
            cipher.init(Cipher.ENCRYPT_MODE, authEncryptionKey.getEncryptionKey());

            final int lengthWithoutMAC = IV_LENGTH_BYTES + cipher.getOutputSize(input.length);

            byte[] message = new byte[lengthWithoutMAC + MAC_LENGTH_BYTES];

            cipher.doFinal(input, 0, input.length, message, IV_LENGTH_BYTES);

            System.arraycopy(cipher.getIV(), 0, message, 0, IV_LENGTH_BYTES);

            hmac.update(message, 0, lengthWithoutMAC);
            hmac.doFinal(message, lengthWithoutMAC);

            return new EncryptedMessage(message);
        } catch (InvalidKeyException | BadPaddingException | ShortBufferException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return null;
        }
    }

    public byte[] decrypt(EncryptedMessage message) throws InvalidParameterException {

        if(this.destroyed) {
            throw new IllegalStateException("this instance is destroyed");
        }

        verifyMessage(message);

        final int ciphertextLen = message.message.length - (IV_LENGTH_BYTES + MAC_LENGTH_BYTES);

        try {
            cipher.init(Cipher.DECRYPT_MODE, authEncryptionKey.getEncryptionKey(), message.getIV());
            return cipher.doFinal(message.message, IV_LENGTH_BYTES, ciphertextLen);
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }

    private void verifyMessage(EncryptedMessage message) throws InvalidParameterException {

        final byte[] messageBytes = message.message;
        final int lengthWithMAC = messageBytes.length;

        final boolean valid;
        if (lengthWithMAC < MAC_LENGTH_BYTES) {
            valid = false;
        } else {

            final int lengthWithoutMAC = lengthWithMAC - MAC_LENGTH_BYTES;

            hmac.update(messageBytes, 0, lengthWithoutMAC);
            final byte[] expectedMAC = hmac.doFinal();

            // Perform a constant time comparison to avoid timing attacks.
            int v = 0;
            for (int i = 0, j = lengthWithoutMAC; i < MAC_LENGTH_BYTES; i++, j++) {
                v |= (expectedMAC[i] ^ messageBytes[j]);
            }
            valid = v == 0;
        }

        if(!valid) {
            throw new InvalidParameterException("The message MAC is invalid");
        }
    }

    public byte[] hmac(byte[] data, int truncatedLength) throws IllegalArgumentException {
        if(truncatedLength < 0 || truncatedLength > MAC_LENGTH_BYTES) {
            throw new IllegalArgumentException("truncatedLength must be > 0 and <= " + MAC_LENGTH_BYTES);
        }

        if(truncatedLength == -1 || truncatedLength == MAC_LENGTH_BYTES) {
            return hmac.doFinal(data);
        }

        return Arrays.copyOfRange(hmac.doFinal(data), 0, truncatedLength);
    }

    @Override
    public void destroy() throws DestroyFailedException {

        this.cipher = null;
        this.hmac = null;

        this.authEncryptionKey.destroy();

        this.destroyed = this.authEncryptionKey.isDestroyed();
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    static class EncryptedMessage {

        private final byte[] message;

        public EncryptedMessage(byte[] message) {
            this.message = message;
        }

        public IvParameterSpec getIV() {
            return new IvParameterSpec(message, 0, IV_LENGTH_BYTES);
        }

        public byte[] getBytes() {
            return message;
        }

    }

    public int getIVLength() {
        return IV_LENGTH_BYTES;
    }
}
