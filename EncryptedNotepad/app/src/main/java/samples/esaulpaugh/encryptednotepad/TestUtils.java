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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * Created by esaulpaugh on 3/20/16.
 */
public class TestUtils {

    public static void print(byte[] bytes) {

        StringBuilder sb = new StringBuilder();

        for(byte b  : bytes) {
            sb.append(b).append(", ");
        }

        System.out.println(sb.toString());

    }

    public static void printFile(File file) throws IOException {
        if(file.isDirectory()) {
            if(file.getName().equals("instant-run")) {
                return;
            }
            System.out.println("********* DIR " + file.getAbsolutePath());
            File[] files = file.listFiles();
            for (File f : files) {
                printFile(f);
            }
        } else {
            System.out.println("+++++++ FILE " + file.getAbsolutePath());
            System.out.println(new String(FileUtils.readFile(file), Constants.UTF_8));
        }
    }

    private static class FileUtils {

        private static File writeFile(File file, byte[] data) throws IOException {

            System.out.println("WRITE " + file.getName());

            BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(file));
            try {
                bos.write(data);
            } finally {
                bos.close();
            }

            return file;
        }

        private static byte[] readFile(File file) throws IOException {

            BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file));

            byte[] data = new byte[(int) file.length()];

            try {
                int available;
                int offset = 0;
                while ((available = bis.available()) > 0) {
                    offset += bis.read(data, offset, available);
                }
            } finally {
                bis.close();
            }

            System.out.println("READ " + file.getName());

            return data;
        }

        private static boolean deleteFile(File file) {
            return file.delete();
        }

    }

}
