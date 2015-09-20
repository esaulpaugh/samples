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

import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;

public class RotateBlock {

    private static final int BYTES_PER_LONG = 8;// Long.BYTES (Java 1.8)

    /**
     * A lookup table mapping leftward bitwise block rotation distances to the quarter-block distance from a given
     * quarter-block to its new high bits. Rotation for distances 0, 64, 128, and 192 are special cases. These indices
     * are given values of 4, 5, 6, and 7 respectively. Other than these, all values in this table are leftward modular
     * quarter-block distances.
     */
    private static final byte[] LEFT_ROTATION_J_VALUES = {
            4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            5, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            6, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            7, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3};

    /**
     * <pre>
     * A lookup table mapping rightward bitwise block rotation distances to the quarter-block distance from a given
     * quarter-block to its new high bits. Values in this table should be added to the current quarter-block index,
     * on interval [0,3], mod 4 to get the quarter-block index of the current quarter-block's new high bits.
     *
     * Example:
     *
     * Rotate block rightward 168 bits:
     *
     * Original block:
     * CCCCCCCCAAAAAAAA, FFFFFFFFEEEEEEEE, BBBBBBBBAAAAAAAA, BBBBBBBBEEEEEEEE
     *
     * To get the new value for quarter block 3 (index 3):
     *
     * From this table:
     * J-value (quarter-block distance to new high bits) = 1
     * Target index: (3 + 1) % 4 = 0
     * (index 0's low bits will be index 3's new high bits)
     *
     * K-value (quarter-block distance to new low bits) = 2 (derived from J-value)
     * Target index: (3 + 2) % 4 = 1
     * (index 1's high bits will be index 3's new low bits)
     *
     * We shift the long at index 0 left by -168 to turn its low bits into high bits
     * We shift the long index 1 right by 168 to turn its high bits into low bits
     *
     * Note that all but the least significant six bits of the shift distance are ignored by the << and >>> operators
     * when applied to a long. e.g. n << -168 == n << 24 and n >>> 168 == n >>> 40. Logic adapted from {@link Long#rotateRight}.
     *
     * We bitwise OR these shifted values together to get the final value for index 3:
     *
     *    CCAAAAAAAA000000
     * OR 0000000000FFFFFF
     * -------------------
     *    CCAAAAAAAAFFFFFF
     *
     * Relevant bits before and after:
     *
     * ______CCAAAAAAAA, FFFFFF__________, ________________, ________________
     *
     * ________________, ________________, ________________, CCAAAAAAAAFFFFFF
     *
     * Calculations for the other indices:
     *
     * Index 0: (0 + 1) % 4 = 1; (0 + 2) % 4 = 2
     * Index 1: (1 + 1) % 4 = 2; (1 + 2) % 4 = 3
     * Index 2: (2 + 1) % 4 = 3; (2 + 2) % 4 = 0
     *
     * (new high bits, new low bits) --> index
     * (1, 2) --> 0
     * (2, 3) --> 1
     * (3, 0) --> 2
     *
     * Rotated block:
     * FFEEEEEEEEBBBBBB, BBAAAAAAAABBBBBB, BBEEEEEEEECCCCCC, CCAAAAAAAAFFFFFF
     *
     *
     * Note:
     *
     * Rotation for distances 0, 64, 128, and 192 are special cases. These indices are given values of 4, 5, 6, and 7
     * respectively. Other than these, all values in this table are rightward modular quarter-block distances.
     * </pre>
     */
    private static final byte[] RIGHT_ROTATION_J_VALUES = {
            4, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            5, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            6, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    private static void rotateLeft(long[] longs, int distance,
                                   int _0, int _1, int _2, int _3,
                                   long _0hi, long _0lo, long _1hi, long _1lo, long _2hi, long _2lo, long _3hi, long _3lo) {
        final int negativeDistance = -distance;
        longs[_0] = _0hi << distance | _0lo >>> negativeDistance;
        longs[_1] = _1hi << distance | _1lo >>> negativeDistance;
        longs[_2] = _2hi << distance | _2lo >>> negativeDistance;
        longs[_3] = _3hi << distance | _3lo >>> negativeDistance;
    }

    private static void rotateRight(long[] longs, int distance,
                                    int _0, int _1, int _2, int _3,
                                    long _0hi, long _0lo, long _1hi, long _1lo, long _2hi, long _2lo, long _3hi, long _3lo) {
        final int negativeDistance = -distance;
        longs[_0] = _0hi << negativeDistance | _0lo >>> distance;
        longs[_1] = _1hi << negativeDistance | _1lo >>> distance;
        longs[_2] = _2hi << negativeDistance | _2lo >>> distance;
        longs[_3] = _3hi << negativeDistance | _3lo >>> distance;
    }

    /**
     * Rotate a 256-bit block left.
     * @param plaintext array of longs
     * @param offset    offset into the plaintext array of the block
     * @param distance  bit distance to rotate; must be on interval [0,255]
     */
    static void rotateLeft(long[] plaintext, int offset, int distance) {

        final int a = offset;
        final int b = offset + 1;
        final int c = offset + 2;
        final int d = offset + 3;

        final long _a = plaintext[a];
        final long _b = plaintext[b];
        final long _c = plaintext[c];
        final long _d = plaintext[d];

        switch (LEFT_ROTATION_J_VALUES[distance]) {
            case 0: {// [193,255]
                rotateLeft(plaintext, distance, a, b, c, d, _a, _b, _b, _c, _c, _d, _d, _a);
                break;
            }
            case 1: {// [129,191]
                rotateLeft(plaintext, distance, a, b, c, d, _b, _c, _c, _d, _d, _a, _a, _b);
                break;
            }
            case 2: {// [65,127]
                rotateLeft(plaintext, distance, a, b, c, d, _c, _d, _d, _a, _a, _b, _b, _c);
                break;
            }
            case 3: {// [1,63]
                rotateLeft(plaintext, distance, a, b, c, d, _d, _a, _a, _b, _b, _c, _c, _d);
                break;
            }
            case 4: {// distance == 0
                rotateLeft(plaintext, distance, a, b, c, d, _a, _a, _b, _b, _c, _c, _d, _d);
                break;
            }
            case 5: {// distance == 64
                rotateLeft(plaintext, distance, a, b, c, d, _b, _b, _c, _c, _d, _d, _a, _a);
                break;
            }
            case 6: {// distance == 128
                rotateLeft(plaintext, distance, a, b, c, d, _c, _c, _d, _d, _a, _a, _b, _b);
                break;
            }
            case 7: {// distance == 192
                rotateLeft(plaintext, distance, a, b, c, d, _d, _d, _a, _a, _b, _b, _c, _c);
                break;
            }
        }
    }

    /**
     * Rotate a 256-bit block right.
     * @param plaintext array of longs
     * @param offset    offset into the plaintext array of the block
     * @param distance  bit distance to rotate; must be on interval [0,255]
     */
    static void rotateRight(long[] plaintext, int offset, int distance) {

        final int a = offset;
        final int b = offset + 1;
        final int c = offset + 2;
        final int d = offset + 3;

        final long _a = plaintext[a];
        final long _b = plaintext[b];
        final long _c = plaintext[c];
        final long _d = plaintext[d];

        switch (RIGHT_ROTATION_J_VALUES[distance]) {
            case 0: {// [193,255]
                rotateRight(plaintext, distance, a, b, c, d, _a, _b, _b, _c, _c, _d, _d, _a);
                break;
            }
            case 1: {// [129,191]
                rotateRight(plaintext, distance, a, b, c, d, _b, _c, _c, _d, _d, _a, _a, _b);
                break;
            }
            case 2: {// [65,127]
                rotateRight(plaintext, distance, a, b, c, d, _c, _d, _d, _a, _a, _b, _b, _c);
                break;
            }
            case 3: {// [1,63]
                rotateRight(plaintext, distance, a, b, c, d, _d, _a, _a, _b, _b, _c, _c, _d);
                break;
            }
            case 4: {// distance == 0
                rotateRight(plaintext, distance, a, b, c, d, _a, _a, _b, _b, _c, _c, _d, _d);
                break;
            }
            case 5: {// distance == 64
                rotateRight(plaintext, distance, a, b, c, d, _d, _d, _a, _a, _b, _b, _c, _c);
                break;
            }
            case 6: {// distance == 128
                rotateRight(plaintext, distance, a, b, c, d, _c, _c, _d, _d, _a, _a, _b, _b);
                break;
            }
            case 7: {// distance == 192
                rotateRight(plaintext, distance, a, b, c, d, _b, _b, _c, _c, _d, _d, _a, _a);
                break;
            }
        }
    }

    public static String hex(long... longs) {
        final StringBuilder sb = new StringBuilder();
        for (long x : longs) {
            sb.append(HexBin.encode(longsToBytes(x)));
            sb.append(' ');
        }
        return sb.toString();
    }

    public static void printHex(long... longs) {
        System.out.println(hex(longs));
    }

    public static String binary(long... longs) {
        final StringBuilder sb = new StringBuilder();
        for (long x : longs) {
            sb.append(' ');
            final String bits = Long.toBinaryString(x);
            final int n = Long.SIZE - bits.length();
            for (int i = 0; i < n; i++) {
                sb.append('0');
            }
            sb.append(bits);
        }
        return sb.toString();
    }

    public static void printBinary(long... longs) {
        System.out.println(binary(longs));
    }

    public static void putLong(long value, byte[] array, int offset) {
        array[offset]     = (byte) (0xFF & (value >> 56));
        array[offset + 1] = (byte) (0xFF & (value >> 48));
        array[offset + 2] = (byte) (0xFF & (value >> 40));
        array[offset + 3] = (byte) (0xFF & (value >> 32));
        array[offset + 4] = (byte) (0xFF & (value >> 24));
        array[offset + 5] = (byte) (0xFF & (value >> 16));
        array[offset + 6] = (byte) (0xFF & (value >> 8));
        array[offset + 7] = (byte) (0xFF & value);
    }

    public static byte[] longsToBytes(long... longs) {
        final byte[] bytes = new byte[longs.length << 3];// longs.length * BYTES_PER_LONG
        for (int i = 0, offset = 0; i < longs.length; i++, offset += BYTES_PER_LONG) {
            putLong(longs[i], bytes, offset);
        }
        return bytes;
    }

    public static void main(String... blargs) {
        final long[] o = new long[]{ 0xCCCCCCCCAAAAAAAAL, 0xFFFFFFFFEEEEEEEEL, 0xBBBBBBBBAAAAAAAAL, 0xBBBBBBBBEEEEEEEEL };

        printHex(o);

        for (int i = 0; i < 256; i++) {
            long[] x = o.clone();
            rotateLeft(x, 0, i % 256);
            printBinary(x);
        }

        for (int i = 0; i < 256; i++) {
            long[] x = o.clone();
            rotateRight(x, 0, i % 256);
            printBinary(x);
        }
    }

}
