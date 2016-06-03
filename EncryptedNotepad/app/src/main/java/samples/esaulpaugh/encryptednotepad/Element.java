package samples.esaulpaugh.encryptednotepad;

import android.support.annotation.NonNull;

import org.json.JSONException;
import org.json.JSONObject;

import java.security.SecureRandom;
import java.util.Random;

/**
 * Created by esaulpaugh on 3/21/16.
 */
public abstract class Element implements Comparable<Element> {

    private static class IdCreator {

        private final Random random1;
        private final Random random2;

        public IdCreator() {

            SecureRandom secureRandom = new SecureRandom();

            random1 = new Random();
            random2 = new Random();

            random1.setSeed(secureRandom.nextLong()); // set 48-bit seed in random1
            random2.setSeed(secureRandom.nextLong()); // set 48-bit seed in random2
        }

        public long nextId() {
            return random1.nextLong() ^ random2.nextLong();
        }

    }

    private static final ThreadLocal<IdCreator> ID_CREATOR_THREAD_LOCAL = new ThreadLocal<IdCreator>() {

        @Override
        public IdCreator initialValue() {
            return new IdCreator();
        }

    };

    private final long id;

    protected String dir;
    protected String filename;
    private boolean exists;
    private String name;

    public Element(String dir, String filename, boolean exists, String name) {

//        byte[] encryptedFilenameBytes = Utils.decode(file.getName());
//        byte[] decryptedFilenameBytes = encryptionManager.decrypt(new EncryptionManager.EncryptedMessage(encryptedFilenameBytes));

        this.id = ID_CREATOR_THREAD_LOCAL.get().nextId();

        this.dir = dir;
        this.filename = filename;
        this.exists = exists;
        this.name = name;
    }

    public Element(String json) throws JSONException {
        JSONObject jsonObject = new JSONObject(json);
        this.id = (Long) jsonObject.get("id");
        this.dir = (String) jsonObject.get("dir");
        this.filename = (String) jsonObject.opt("filename");
        this.exists = (Boolean) jsonObject.get("exists");
        this.name = (String) jsonObject.get("name");
    }

    public long getId() {
        return id;
    }

    public String getDir() {
        return dir;
    }

    public String getFilename() {
        return filename;
    }

    public boolean exists() {
        return exists;
    }

    public String getName() {
        return name;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }

    public void setExists(boolean exists) {
        this.exists = exists;
    }

    @Override
    public String toString() {
        JSONObject jsonObject = new JSONObject();
        try {
            jsonObject.put("id", id);
            jsonObject.put("dir", dir);
            jsonObject.put("filename", filename);
            jsonObject.put("exists", exists);
            jsonObject.put("name", name);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return jsonObject.toString();
    }

    @Override
    public int compareTo(@NonNull Element other) {

        if(this instanceof Folder) {
            if(other instanceof Note) {
                return -1;
            }
        } else {
            if(other instanceof Folder) {
                return 1;
            }
        }

        return this.name.compareTo(other.name);
    }
}
