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
import java.security.InvalidParameterException;

/**
 * Created by esaulpaugh on 4/29/16.
 */
public class EncryptedFileUtils {

    private final EncryptionManager encryptionManager;

    public EncryptedFileUtils(EncryptionManager encryptionManager) {
        this.encryptionManager = encryptionManager;
    }

    public File mkdir(String dir, String newName) {

        String newFilepath = encryptFilepath(dir, newName);

        File newFile = new File(newFilepath);

        if(newFile.mkdir()) {
            return newFile;
        }
        return null;
    }

    private String encryptFilepath(String dir, String filename) {
        return dir + '/' + encryptEncode(filename);
    }

    public File replaceFile(String oldFilepath, String dir, String newName, byte[] data) throws IOException {
        System.out.println("EncryptedFileUtils overwriting " + new String(data, Constants.UTF_8));

        String newFilepath = encryptFilepath(dir, newName);

        File newFile = new File(newFilepath);


        boolean renamed = new File(oldFilepath).renameTo(newFile);

        System.out.println("RENAMED " + oldFilepath + " to " + newFile.getAbsolutePath() + ", success=" + renamed);

        return FileUtils.writeFile(newFile, encryptData(data));
    }

    public File writeFile(String dir, String name, byte[] data) throws IOException {

        String filepath = dir + '/' + encryptEncode(name);

        return FileUtils.writeFile(new File(filepath), encryptData(data));
    }

    public byte[] readFile(String dir, String filename) throws IOException, InvalidParameterException {

        String filepath = dir + '/' + filename;

        return decryptData(FileUtils.readFile(new File(filepath)));
    }

    private String encryptEncode(String path) {
        return Utils.encode(encryptionManager.encrypt(path.getBytes(Constants.UTF_8)).getBytes());
    }

    private byte[] encryptData(byte[] data) {
        return encryptionManager.encrypt(data).getBytes();
    }

    private byte[] decryptData(byte[] encryptedData) throws InvalidParameterException {
        return encryptionManager.decrypt(new EncryptionManager.EncryptedMessage(encryptedData));
    }

    public synchronized boolean deleteFile(File file) throws IOException, IllegalArgumentException {

        boolean overwritten;

        if (file.isDirectory()) {

            if(file.list().length != 0) {
                throw new InvalidParameterException("folder must be empty to be deleted");
            }

            File renamedFile = new File(file.getParent(), Utils.secureRandomString(file.getName().length()));
            overwritten = file.renameTo(renamedFile);
            file = renamedFile;
        } else {
            file = FileUtils.writeFile(file, Utils.secureRandomBytes(encryptionManager.getIVLength()));
            overwritten = true;
        }

        return overwritten && FileUtils.deleteFile(file);

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
