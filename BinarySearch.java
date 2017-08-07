package com.company;

import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.util.Scanner;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * : zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz
 * SHA1 = B693E9FA06A8E658306A64E1166039A14AD36E5A
 * SEARCHING 321572487 TOKENS...
 * >>> FORWARD
 * <<< BACK
 * >>> FORWARD
 * >>> FORWARD
 * <<< BACK
 * >>> FORWARD
 * >>> FORWARD
 * <<< BACK
 * <<< BACK
 * >>> FORWARD
 * <<< BACK
 * >>> FORWARD
 * <<< BACK
 * >>> FORWARD
 * <<< BACK
 * <<< BACK
 * <<< BACK
 * >>> FORWARD
 * >>> FORWARD
 * >>> FORWARD
 * <<< BACK
 * >>> FORWARD
 * <<< BACK
 * <<< BACK
 * >>> FORWARD
 * <<< BACK
 * <<< BACK
 * <<< BACK
 * >>> FORWARD
 * <<< BACK
 *
 * elapsed millis = 0.437397
 * RESULT = null
 */
public class BinarySearch {

    private static final StringBuilder STRING_BUILDER = new StringBuilder();

    private static final int CARRIAGE_RETURN = 13;
    private static final int LINE_FEED = 10;

    private static final int CRLF_LEN_BYTES = 2;

    private static final String FILEPATH = "F:\\pwned-passwords-1.0.txt\\pwned-passwords-1.0.txt";

    private static final RandomAccessFile HASHFILE;

    static {
        try {
            HASHFILE = new RandomAccessFile(FILEPATH, "r");
        } catch (FileNotFoundException fnfe) {
            throw new RuntimeException(fnfe);
        }
    }

    public static void main(String[] args) throws Exception {

        MessageDigest md = MessageDigest.getInstance("SHA-1");

        Scanner scan = new Scanner(System.in);

        System.out.print(": ");

        final int tokenLen = md.getDigestLength() << 1;

        try {

            String password = scan.nextLine();
            do {
                byte[] digest = md.digest(password.getBytes(UTF_8));

                String hex = HexBin.encode(digest);

                System.out.println("SHA1 = " + hex);

                long len = HASHFILE.length();

                System.out.println("SEARCHING " + (len / tokenLen) + " TOKENS...");

                long start, end, elapsed;

                start = System.nanoTime();
                byte[] result = binarySearch(HASHFILE, 0, len / 2, len, hex.getBytes(UTF_8), new byte[tokenLen]);
                end = System.nanoTime();

                elapsed = (end - start);

                System.out.println(STRING_BUILDER.toString());
                STRING_BUILDER.setLength(0);

                System.out.println("elapsed millis = " + elapsed / 1000000.0);

                System.out.println("RESULT = " + (result == null ? null : new String(result)));


                System.out.print(": ");

            } while (!(password = scan.nextLine()).equals("-1"));

        } finally {
            HASHFILE.close();
        }
    }

    // TODO multiply by lineLength to land cleanly on token start
    private static byte[] binarySearch(RandomAccessFile file, long start, long pos, long end, byte[] query, byte[] result) throws IOException {

        final int lineLength = result.length + CRLF_LEN_BYTES;

//        System.out.println(start + ", " + pos + ", " + end + " (" + (end - start) + ", " + (end - pos) + ")");

        if (pos < start) {
            return null;
        }

        file.seek(pos);

        for (int i = 0; i < lineLength; i++) {
            if (file.read() == CARRIAGE_RETURN && file.read() == LINE_FEED) {
//                System.out.println("+" + i);
                break;
            }
        }

        int r = file.read(result);

//        System.out.println("result? = " + new String(result));

        pos = file.getFilePointer();

        final int diff = compare(query, result);
//            final int diff = UnsignedBytes.lexicographicalComparator().compare(query, result);
        if (diff < 0) {
            STRING_BUILDER.append("<<< BACK\n");
            end = pos - lineLength;
            long mid = (start + end) / 2;
            if (end - mid < lineLength) {
                mid = end - lineLength;
            }
            return binarySearch(file, start, mid, end, query, result);
        } else if (diff > 0) {
            STRING_BUILDER.append(">>> FORWARD\n");
            start = pos;
            long mid = (start + end) / 2;
            return binarySearch(file, pos, mid, end, query, result);
        }
        return result;
    }

    private static int compare(byte[] query, byte[] result) {
        for (int i = 0; i < query.length; i++) {
            int a = query[i] & 0xFF;
            int b = result[i] & 0xFF;
            if (a != b)
                return a - b;
        }
        return 0;
    }
}
