package samples.esaulpaugh.encryptednotepad;

import android.app.Activity;
import android.content.Context;
import android.widget.Toast;

/**
 * Created by esaulpaugh on 5/13/16.
 */
public class UIUtils {

    public static void toast(Context context, String message) {
        toast(context, message, Toast.LENGTH_SHORT);
    }

    public static void toastLong(Context context, String message) {
        toast(context, message, Toast.LENGTH_LONG);
    }

    public static void toastOnUiThread(Activity activity, String message) {
        toastOnUiThread(activity, message, Toast.LENGTH_SHORT);
    }

    public static void toastOnUiThread(final Activity activity, final String message, final int duration) {
        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                toast(activity, message, duration);
            }
        });
    }

    private static void toast(Context context, String message, int duration) {
        Toast.makeText(context, message, duration).show();
    }

}
