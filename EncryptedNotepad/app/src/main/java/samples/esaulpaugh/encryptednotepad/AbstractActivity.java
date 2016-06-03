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

import android.app.Activity;
import android.content.Intent;
import android.content.res.Configuration;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.v7.app.AppCompatActivity;
import android.widget.Toast;

import javax.security.auth.DestroyFailedException;

/**
 * Created by esaulpaugh on 5/13/16.
 */
public abstract class AbstractActivity extends AppCompatActivity {

    private transient EncryptionManager encryptionManager;

    private boolean forward = false;
    private boolean back = false;
    private boolean root;

    public EncryptionManager getEncryptionManager() {
        return encryptionManager;
    }

    public void setForward(boolean forward) {
        this.forward = forward;
    }

    protected void toast(String message) {
        UIUtils.toast(AbstractActivity.this, message);
    }

    protected void toastLong(String message) {
        UIUtils.toastLong(AbstractActivity.this, message);
    }

    protected void toastOnUiThread(String message) {
        UIUtils.toastOnUiThread(AbstractActivity.this, message);
    }

    protected void toastLongOnUiThread(String message) {
        UIUtils.toastOnUiThread(AbstractActivity.this, message, Toast.LENGTH_LONG);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        this.root = getIntent().getBooleanExtra(Constants.ROOT, false);

        encryptionManager = ((CustomApplication) getApplication()).getEncryptionManager();

        if (!(this instanceof EnterPasswordActivity)
                && (encryptionManager == null || encryptionManager.isDestroyed())) {
            finish();
        }
    }

    @Override
    public void onBackPressed() {

        back = true;

        super.onBackPressed();
    }

    @Override
    public void onResume() {

        this.forward = false;
        this.back = false;

        if (!(this instanceof EnterPasswordActivity) && (encryptionManager == null || encryptionManager.isDestroyed())) {
            finish();
        }

        super.onResume();
    }

    @Override
    public void onPause() {

        System.out.println("onPause()");

        System.out.println("forward = " + forward);
        System.out.println("back = " + back);
        System.out.println("root = " + root);

        if((root && back) || (!back && !forward)) {
            destroyEncryptionManager();
        }

        super.onPause();
    }

    @Override
    public void startActivity(Intent intent) {
        forward = true;
        super.startActivity(intent);
    }

    @Override
    public void startActivities(Intent[] intents) {
        forward = true;
        super.startActivities(intents);
    }

    @Override
    public void startActivity(Intent intent, Bundle options) {
        forward = true;
        super.startActivity(intent, options);
    }

    @Override
    public void startActivityFromChild(@NonNull Activity child, Intent intent, int requestCode) {
        forward = true;
        super.startActivityFromChild(child, intent, requestCode);
    }

    @Override
    public void startActivityForResult(Intent intent, int requestCode) {
        forward = true;
        super.startActivityForResult(intent, requestCode);
    }

    @Override
    public void startActivityForResult(Intent intent, int requestCode, Bundle options) {
        forward = true;
        super.startActivityForResult(intent, requestCode, options);
    }

    private void destroyEncryptionManager() {

        System.out.println("+++++++++++++ DESTROY EncryptionManager +++++++++++++");

        EncryptionManager em = ((CustomApplication) getApplication()).getEncryptionManager();

        if (em != null && !em.isDestroyed()) {
            try {
                em.destroy();
            } catch (DestroyFailedException e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);

        System.out.println("yee onConfigurationChanged()");

    }

}
