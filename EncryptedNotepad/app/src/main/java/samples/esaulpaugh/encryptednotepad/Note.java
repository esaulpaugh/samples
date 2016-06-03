package samples.esaulpaugh.encryptednotepad;

import org.json.JSONException;

/**
 * Created by esaulpaugh on 3/21/16.
 */
public class Note extends Element {

//    private String filename;

    public Note(String dir, String filename, String name) {
        this(dir, filename, true, name);
    }

    public Note(String dir, String filename, boolean exists, String name) {
        super(dir, filename, exists, name);
//        this.filename = filename;
//        this.exists = exists;
//        this.name = name;
    }

    public Note(String elementJson) throws JSONException {
        super(elementJson);
//        JSONObject jsonObject = new JSONObject(elementJson);
////        this.filename = (String) jsonObject.get("filename");
//        this.exists = (Boolean) jsonObject.get("exists");
//        this.name = (String) jsonObject.get("name");
    }

//    public String getDir() {
//        return dir;
//    }
//
////    public String getFilename() {
////        return filename;
////    }
//
//    public boolean exists() {
//        return exists;
//    }
//
//    public String getName() {
//        return name;
//    }

//    @Override
//    public String toString() {
//        JSONObject jsonObject = new JSONObject();
//        try {
//            jsonObject.put("dir", dir);
//            jsonObject.put("filename", filename);
//            jsonObject.put("exists", exists);
//            jsonObject.put("name", name);
//        } catch (JSONException e) {
//            e.printStackTrace();
//        }
//        return jsonObject.toString();
//    }

}
