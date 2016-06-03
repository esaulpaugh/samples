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

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.KeyEvent;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.TextView;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import static samples.esaulpaugh.encryptednotepad.Constants.DIR;
import static samples.esaulpaugh.encryptednotepad.Constants.ROOT;

public class EnterPasswordActivity extends AbstractActivity {

    private transient EditText enterPassword;

    private transient EditText confirmPassword;

    private transient EncryptionManager encryptionManager;

    private transient final AtomicBoolean settingUp = new AtomicBoolean(false);

//    /**
//     * ATTENTION: This was auto-generated to implement the App Indexing API.
//     * See https://g.co/AppIndexing/AndroidStudio for more information.
//     */
//    private GoogleApiClient client;

    private void setUp(String password) throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, UnrecoverableEntryException,
            InvalidAlgorithmParameterException, NoSuchPaddingException, KeyStoreException, NoSuchProviderException, IllegalBlockSizeException {


        if (settingUp.compareAndSet(false, true)) {

            Log.i("YAYA", "Setting up...");

            try {

                AuthEncryptionKey keys = KeyUtils.createKey(EnterPasswordActivity.this, password);

                CustomApplication application = (CustomApplication) getApplication();

                try {

                    EnterPasswordActivity.this.encryptionManager = new EncryptionManager(keys);
                    application.setEncryptionManager(EnterPasswordActivity.this.encryptionManager);

                } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException e) {
                    e.printStackTrace();
                }

            } catch (IOException | GeneralSecurityException e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_enter_password);

        String architecture = System.getProperty("os.arch");

        ListSupportedAlgorithms();

        System.out.println(architecture);
//        Toast.makeText(this, architecture, Toast.LENGTH_LONG).show();

        if (architecture.startsWith("arm")) {
            System.clearProperty("com.lambdaworks.jni.loader");
        } else {
            System.setProperty("com.lambdaworks.jni.loader", "nil");
        }

        try {
            TestUtils.printFile(getFilesDir());
//            TestUtils.printFile(getCacheDir());
//            TestUtils.printFile(getExternalCacheDir());
//            if(Build.VERSION.SDK_INT >= 11) {
//                TestUtils.printFile(getObbDir());
//            }
//            if(Build.VERSION.SDK_INT >= 19) {
//                for (File f : getObbDirs()) {
//                    TestUtils.printFile(f);
//                }
//                for (File f : getExternalCacheDirs()) {
//                    TestUtils.printFile(f);
//                }
//            }
//            if(Build.VERSION.SDK_INT >= 21) {
//                TestUtils.printFile(getCodeCacheDir());
//                TestUtils.printFile(getNoBackupFilesDir());
//                for (File f : getExternalMediaDirs()) {
//                    TestUtils.printFile(f);
//                }
//            }
        } catch (IOException io) {
            io.printStackTrace();
        }

//        try {
//            Provider providers[] = Security.getProviders();
//            for (Provider p : providers) {
//                System.out.println(p);
//                for (Enumeration e = p.keys(); e.hasMoreElements(); )
//                    System.out.println("        " + e.nextElement());
//            }
//        } catch (Exception e) {
//            e.printStackTrace();
//        }

//        ArrayList<String> hmacdFilenames = new ArrayList<>();
//
//        hmacdFilenames.add(Utils.encode(new byte[]{74, -111, 71, 9, 9, 60, 120}));
//        hmacdFilenames.add(Utils.encode(new byte[]{-111, -99, 0, 7, 67, -44}));
//
//        String json = ManifestUtils.toJson(hmacdFilenames);
//
//        System.out.println(json);
//
//        try {
//            ArrayList<String> strings = ManifestUtils.fromJson(json);
//
//            for (String s : strings) {
//                System.out.println("s = " + s);
//            }
//
//        } catch (JSONException e) {
//            e.printStackTrace();
//        }

        enterPassword = (EditText) findViewById(R.id.enter_password);
        confirmPassword = (EditText) findViewById(R.id.confirm_password);

////        client = new GoogleApiClient.Builder(this).addApi(AppIndex.API).build();
//        // ATTENTION: This was auto-generated to implement the App Indexing API.
//        // See https://g.co/AppIndexing/AndroidStudio for more information.
//        client = new GoogleApiClient.Builder(this).addApi(AppIndex.API).build();
    }

//    @Override
//    public void onStop() {
//        super.onStop();
//
//        // ATTENTION: This was auto-generated to implement the App Indexing API.
//        // See https://g.co/AppIndexing/AndroidStudio for more information.
//        Action viewAction = Action.newAction(
//                Action.TYPE_VIEW, // TODO: choose an action type.
//                "EnterPassword Page", // TODO: Define a title for the content shown.
//                // TODO: If you have web page content that matches this app activity's content,
//                // make sure this auto-generated web page URL is correct.
//                // Otherwise, set the URL to null.
//                Uri.parse("http://host/path"),
//                // TODO: Make sure this auto-generated app deep link URI is correct.
//                Uri.parse("android-app://samples.esaulpaugh.encryptednotepad/http/host/path")
//        );
//        AppIndex.AppIndexApi.end(client, viewAction);
//        client.disconnect();
//    }

    private class PasscodeListener implements TextView.OnEditorActionListener {

        private final boolean setup;

        public PasscodeListener(boolean setup) {
            this.setup = setup;
        }

        @Override
        public boolean onEditorAction(final TextView textView, int actionId, KeyEvent keyEvent) {
            if ((keyEvent == null && actionId == EditorInfo.IME_ACTION_DONE)
                    || (keyEvent != null && keyEvent.getAction() == KeyEvent.ACTION_DOWN && actionId == EditorInfo.IME_NULL)) {

                EnterPasswordActivity.this.runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        InputMethodManager imm = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
                        imm.hideSoftInputFromWindow(textView.getWindowToken(), 0);
                    }
                });

                if (setup) {

                    final String entered = enterPassword.getText().toString();
                    final String confirmed = confirmPassword.getText().toString();

                    if (confirmed.equals(entered)) {

                        enterPassword.setText("");
                        confirmPassword.setText("");

//                        Toast.makeText(EnterPasswordActivity.this, "Setting up...", Toast.LENGTH_LONG).show();

                        new Thread() {
                            @Override
                            public void run() {
                                try {
                                    setUp(confirmed);
                                    gogo();
                                } catch (IOException
                                        | CertificateException
                                        | InvalidKeyException
                                        | NoSuchAlgorithmException
                                        | UnrecoverableEntryException
                                        | NoSuchPaddingException
                                        | InvalidAlgorithmParameterException
                                        | KeyStoreException
                                        | IllegalBlockSizeException
                                        | NoSuchProviderException e) {
                                    e.printStackTrace();
                                }
//                                catch (final IllegalStateException ise) {
//                                    ise.printStackTrace();
//                                    runOnUiThread(new Runnable() {
//                                        @Override
//                                        public void run() {
//                                            Toast.makeText(EnterPasswordActivity.this, ise.getMessage(), Toast.LENGTH_LONG).show();
//                                        }
//                                    });
//                                }
                            }
                        }.start();
                    }

                } else {

                    final String entered = enterPassword.getText().toString();
                    enterPassword.setText("");

//                    Toast.makeText(EnterPasswordActivity.this, "Opening...", Toast.LENGTH_LONG).show();

                    new Thread() {
                        @Override
                        public void run() {
                            Log.i("YAYA", "Opening keys...");

                            CustomApplication application = (CustomApplication) getApplication();

                            try {

                                AuthEncryptionKey keys = KeyUtils.openKey(EnterPasswordActivity.this, entered);

                                EnterPasswordActivity.this.encryptionManager = new EncryptionManager(keys);
                                application.setEncryptionManager(EnterPasswordActivity.this.encryptionManager);

                            } catch (final UnsupportedOperationException | NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | CertificateException | KeyStoreException | UnrecoverableEntryException | IOException ex) {
                                ex.printStackTrace();
                                toastOnUiThread(ex.getMessage());
                                return;
                            } catch (InvalidParameterException ipe) {
                                ipe.printStackTrace();
                                EnterPasswordActivity.this.runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {

                                        InputMethodManager imm = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
                                        imm.showSoftInput(enterPassword, 0);

                                        toast("invalid password");
                                    }
                                });
                                return;
                            } catch (GeneralSecurityException e) {
                                e.printStackTrace();
                            }

                            try {
                                gogo();
                            } catch (IOException e) {
                                toast(e.getMessage());
                            }
                        }
                    }.start();
                }

                return true;

            } else if (keyEvent != null && keyEvent.getAction() == KeyEvent.ACTION_UP &&
                    actionId == EditorInfo.IME_NULL) {
                return true;
            }

            return false;
        }
    }

    private void gogo() throws IOException {
        Log.i("YAYA", "gogo()");

        Intent intent = new Intent(EnterPasswordActivity.this, ListActivity.class);

        Bundle extras = new Bundle();
        extras.putBoolean(ROOT, true);

        synchronized (EnterPasswordActivity.this) {
            File root = new File(EnterPasswordActivity.this.getFilesDir().getAbsolutePath() + "/root");
            if(!root.exists()) {
                if(!root.mkdir()) {
                    throw new IOException("unable to create root directory");
                }
            }
            extras.putString(DIR, root.getAbsolutePath());
        }

        intent.putExtras(extras);

        startActivity(intent);

//        finish();
    }

    @Override
    public void onStart() {
        super.onStart();
        // ATTENTION: This was auto-generated to implement the App Indexing API.
        // See https://g.co/AppIndexing/AndroidStudio for more information.
//        client.connect();

        enterPassword.postDelayed(new Runnable() {
            @Override
            public void run() {
                InputMethodManager imm = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
                imm.showSoftInput(enterPassword, 0);
            }
        }, 90);
    }

    @Override
    public void onResume() {
        super.onResume();

        if (KeyUtils.getScryptParams(EnterPasswordActivity.this) == null) {

            confirmPassword.setVisibility(View.VISIBLE);

            confirmPassword.setImeActionLabel("Go", EditorInfo.IME_ACTION_DONE);
            confirmPassword.setOnEditorActionListener(new PasscodeListener(true));

        } else {

            confirmPassword.setVisibility(View.GONE);

            enterPassword.setImeActionLabel("Unlock", EditorInfo.IME_ACTION_DONE);
            enterPassword.setOnEditorActionListener(new PasscodeListener(false));
        }
    }


////        InputMethodManager inputMethodManager = (InputMethodManager)getSystemService(Context.INPUT_METHOD_SERVICE);
////        inputMethodManager.toggleSoftInputFromWindow(enterPassword.getApplicationWindowToken(), InputMethodManager.SHOW_FORCED, 0);
//
////        InputMethodManager imm = (InputMethodManager)getSystemService(Context.INPUT_METHOD_SERVICE);
////        imm.showSoftInput(enterPassword.getRootView(), 0);
//
//
////        client.connect();
//
////        EncryptionManager.EncryptedMessage m = encryptionManager.encrypt(new byte[]{0, 5, 7});
////        byte[] plaintext = encryptionManager.decrypt(m);
////        TestUtils.print(plaintext);
//
//
////        // ATTENTION: This was auto-generated to implement the App Indexing API.
////        // See https://g.co/AppIndexing/AndroidStudio for more information.
////        Action viewAction = Action.newAction(
////                Action.TYPE_VIEW, // TODO: choose an action type.
////                "Main Page", // TODO: Define a title for the content shown.
////                // TODO: If you have web page content that matches this app activity's content,
////                // make sure this auto-generated web page URL is correct.
////                // Otherwise, set the URL to null.
////                Uri.parse("http://host/path"),
////                // TODO: Make sure this auto-generated app deep link URI is correct.
////                Uri.parse("android-app://samples.esaulpaugh.encryptednotepad/http/host/path")
////        );
////        AppIndex.AppIndexApi.start(client, viewAction);
//
//        // ATTENTION: This was auto-generated to implement the App Indexing API.
//        // See https://g.co/AppIndexing/AndroidStudio for more information.
//        Action viewAction = Action.newAction(
//                Action.TYPE_VIEW, // TODO: choose an action type.
//                "EnterPassword Page", // TODO: Define a title for the content shown.
//                // TODO: If you have web page content that matches this app activity's content,
//                // make sure this auto-generated web page URL is correct.
//                // Otherwise, set the URL to null.
//                Uri.parse("http://host/path"),
//                // TODO: Make sure this auto-generated app deep link URI is correct.
//                Uri.parse("android-app://samples.esaulpaugh.encryptednotepad/http/host/path")
//        );
//        AppIndex.AppIndexApi.start(client, viewAction);
//    }

//    @Override
//    public void onStop() {
//        super.onStop();
//
//        // ATTENTION: This was auto-generated to implement the App Indexing API.
//        // See https://g.co/AppIndexing/AndroidStudio for more information.
//        Action viewAction = Action.newAction(
//                Action.TYPE_VIEW, // TODO: choose an action type.
//                "Main Page", // TODO: Define a title for the content shown.
//                // TODO: If you have web page content that matches this app activity's content,
//                // make sure this auto-generated web page URL is correct.
//                // Otherwise, set the URL to null.
//                Uri.parse("http://host/path"),
//                // TODO: Make sure this auto-generated app deep link URI is correct.
//                Uri.parse("android-app://samples.esaulpaugh.encryptednotepad/http/host/path")
//        );
//        AppIndex.AppIndexApi.end(client, viewAction);
//        client.disconnect();
//    }

    public void ListSupportedAlgorithms() {
        String result = "";

        // get all the providers
        Provider[] providers = Security.getProviders();

        for (int p = 0; p < providers.length; p++) {
            // get all service types for a specific provider
            Set<Object> ks = providers[p].keySet();
            Set<String> servicetypes = new TreeSet<String>();
            for (Iterator<Object> it = ks.iterator(); it.hasNext(); ) {
                String k = it.next().toString();
                k = k.split(" ")[0];
                if (k.startsWith("Alg.Alias."))
                    k = k.substring(10);

                servicetypes.add(k.substring(0, k.indexOf('.')));
            }

            // get all algorithms for a specific service type
            int s = 1;
            for (Iterator<String> its = servicetypes.iterator(); its.hasNext(); ) {
                String stype = its.next();
                Set<String> algorithms = new TreeSet<String>();
                for (Iterator<Object> it = ks.iterator(); it.hasNext(); ) {
                    String k = it.next().toString();
                    k = k.split(" ")[0];
                    if (k.startsWith(stype + "."))
                        algorithms.add(k.substring(stype.length() + 1));
                    else if (k.startsWith("Alg.Alias." + stype + "."))
                        algorithms.add(k.substring(stype.length() + 11));
                }

                int a = 1;
                for (Iterator<String> ita = algorithms.iterator(); ita.hasNext(); ) {
                    result += ("[P#" + (p + 1) + ":" + providers[p].getName() + "]" +
                            "[S#" + s + ":" + stype + "]" +
                            "[A#" + a + ":" + ita.next() + "]\n");
                    a++;
                }

                s++;
            }
        }

        System.out.println(result);
    }

}
