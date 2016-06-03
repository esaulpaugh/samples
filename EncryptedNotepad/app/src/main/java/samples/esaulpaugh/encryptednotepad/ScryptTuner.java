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

import com.lambdaworks.crypto.SCrypt;

import org.json.JSONException;
import org.json.JSONObject;

import java.security.GeneralSecurityException;

/**
 * Created by esaulpaugh on 5/17/16.
 */
public class ScryptTuner {

//    // TODO ******* tune at setup and generate these & write to preferences? *********
    private static final int DEFAULT_N = 65536; // CPU cost parameter
    private static final int DEFAULT_R = 8; // block size parameter
    private static final int DEFAULT_P = 1; // parallelization parameter


    private static final int STARTING_R = 1;

    private static final int OUTPUT_LEN_BYTES = 64;

    public static class ScryptParams {

        private byte[] salt;
        private int N;
        private int r;
        private int p;
        private int dkLen;

        public byte[] getSalt() {
            return salt != null ? salt.clone() : null;
        }

        public int getN() {
            return N;
        }

        public int getR() {
            return r;
        }

        public int getP() {
            return p;
        }

        public int getDkLen() {
            return dkLen;
        }

        public void setSalt(byte[] salt) {
            this.salt = salt != null ? salt.clone() : null;
        }

        public void setN(int n) {
            N = n;
        }

        public void setR(int r) {
            this.r = r;
        }

        public void setP(int p) {
            this.p = p;
        }

        public void setDkLen(int dkLen) {
            this.dkLen = dkLen;
        }

        public ScryptParams(byte[] salt, int N, int r, int p, int dkLen) {
            this.salt = salt;
            this.N = N;
            this.r = r;
            this.p = p;
            this.dkLen = dkLen;
        }

        private ScryptParams(String json) throws JSONException {
            JSONObject jsonObject = new JSONObject(json);
            String saltString = (String) jsonObject.opt("salt");
            this.salt = saltString != null ? Utils.decode(saltString) : null;
            this.N = (Integer) jsonObject.get("N");
            this.r = (Integer) jsonObject.opt("r");
            this.p = (Integer) jsonObject.get("p");
            this.dkLen = (Integer) jsonObject.get("dkLen");
        }

        @Override
        public String toString() {

            JSONObject jsonObject = new JSONObject();
            try {
                jsonObject.put("salt", salt != null ? Utils.encode(salt) : null);
                jsonObject.put("N", N);
                jsonObject.put("r", r);
                jsonObject.put("p", p);
                jsonObject.put("dkLen", dkLen);
            } catch (JSONException e) {
                e.printStackTrace();
            }
            return jsonObject.toString();
        }

        public static ScryptParams fromString(String json) throws JSONException {
            return new ScryptParams(json);
        }

    }

//        byte[] dummyPass = new byte[] { -11, 1, 17, 124, 98, -6, 0, 0, 41, -99 };
    public static ScryptParams tune() throws GeneralSecurityException {

        System.out.println("TUNING SCRYPT +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");

        byte[] dummyPass = Utils.secureRandomBytes(16);
        byte[] dummySalt = Utils.secureRandomBytes(16);

        int N = DEFAULT_N;
        int r = STARTING_R; // DEFAULT_R;
        int p = DEFAULT_P;

        long start, end;
        double elapsedMillis;

        while(true) {
            System.out.println("tuning...");
            try {
                start = System.nanoTime();
                SCrypt.scrypt(dummyPass, dummySalt, N, r, p, OUTPUT_LEN_BYTES);
                end = System.nanoTime();
                elapsedMillis = (end - start) / 1000000.0;
                System.out.println("elapsedMillis = " + elapsedMillis);
                if(elapsedMillis >= 2000) {
                    break;
                }
                System.out.println(r + " --> " + (r <<= 1));
            } catch (OutOfMemoryError oome) {

                oome.printStackTrace();

                System.out.println(r + " ------> " + (r >>= 1));

                break;
            }
        }

        System.gc();

        return new ScryptParams(null, N, r, p, OUTPUT_LEN_BYTES);

    }

}
