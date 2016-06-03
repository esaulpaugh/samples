package samples.esaulpaugh.encryptednotepad;

import org.json.JSONArray;
import org.json.JSONException;

import java.util.ArrayList;
import java.util.Collection;

/**
 * Created by esaulpaugh on 3/21/16.
 */
public class ManifestUtils {

    public static String toJson(ArrayList<String> arrayList) {
        return new JSONArray(arrayList).toString();
    }

    public static ArrayList<String> fromJson(String json) throws JSONException {
        JSONArray jsonArray = new JSONArray(json);
        final int len = jsonArray.length();
        ArrayList<String> list = new ArrayList<>(len);
        for(int i = 0; i < len; i++) {
            list.add((String) jsonArray.get(i));
        }
        return list;
    }

}
