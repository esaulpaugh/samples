
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
import java.util.Properties;

/**
 * Copyright 2015 Evan Saulpaugh
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
public class PoorMansTRNG {

    private static final int DEFUALT_CHUNK_LEN = 512;

    private final String hmacAlgorithm;
    private final transient SecretKey hmacKey;
    private final int chunkLen;

    public PoorMansTRNG(String hmacAlgorithm, byte[] hmacKey) throws NoSuchAlgorithmException {
        this(hmacAlgorithm, hmacKey, DEFUALT_CHUNK_LEN);
    }

    public PoorMansTRNG(String hmacAlgorithm, byte[] hmacKey, int chunkLen) throws NoSuchAlgorithmException {
        if(hmacKey == null) {
            throw new IllegalStateException("hmacKey is null");
        }
        Mac.getInstance(hmacAlgorithm);// test for NoSuchAlgorithmException
        this.hmacAlgorithm = hmacAlgorithm;
        this.hmacKey = new SecretKeySpec(hmacKey, hmacAlgorithm);;
        this.chunkLen = chunkLen;
    }

    private static void sample(Mac mac, byte[] buffer) {
        final int len = buffer.length;
        for(int i = 0; i < len; i++) {
            buffer[i] = (byte) (0xFF & System.nanoTime());
        }
        mac.update(buffer);
    }

    public synchronized byte[] generate(final int numSamples, byte[]... additionalData) {

        try {

            Mac hmac = Mac.getInstance(hmacAlgorithm);
            hmac.init(hmacKey);

            byte[] buffer = new byte[chunkLen];

            int samplesRemaining = numSamples;
            while(samplesRemaining > chunkLen) {
                sample(hmac, buffer);
                samplesRemaining -= chunkLen;
            }

            buffer = new byte[samplesRemaining];
            sample(hmac, buffer);

            for(byte[] additional : additionalData) {
                hmac.update(additional);
            }

            return hmac.doFinal();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException ike) {
            ike.printStackTrace();
        }

        throw new IllegalStateException("error");
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {

        byte[] keyBytes = MessageDigest.getInstance("SHA-256")
                .digest(
                        "3.1415".getBytes(Charset.forName("UTF-8"))
                );

        PoorMansTRNG rng = new PoorMansTRNG("HmacSHA256", keyBytes);

        Properties properties = System.getProperties();
        Enumeration enumeration = properties.propertyNames();

        StringBuilder sb = new StringBuilder();
        while (enumeration.hasMoreElements()) {
            String name = (String) enumeration.nextElement();
            sb.append(name)
                    .append(properties.getProperty(name));
        }

        byte[] ad0 = sb.toString().getBytes(Charset.forName("UTF-8"));
        byte[] ad1 = new byte[] { -55, 7, 21, 15, 99, 21, 0, 0, -5, 121, -18 };

        long start, end;

        start = System.nanoTime();
        byte[] seed = rng.generate(8192, ad0, ad1);
        end = System.nanoTime();

        System.out.print(((end - start) / 1000000.0) + "ms elapsed\noutput = ");

        for (byte b : seed) {
            System.out.print(b + ", ");
        }
    }
}
