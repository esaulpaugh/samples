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
import android.os.Build;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import org.json.JSONException;

import java.io.File;
import java.io.IOException;
import java.security.DigestException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.ShortBufferException;

import static samples.esaulpaugh.encryptednotepad.Constants.UTF_8;

public class NoteActivity extends AbstractActivity {

//    public static final String PARAM_DIR = "dir";
    public static final String PARAM_NOTE = "note";
    public static final String PARAM_NEW_NOTE = "new_note";

    public static final int REQUEST_CODE_EDIT_NOTE = 7;

//    private static final int HASH_LENGTH_BYTES = 20;
    private static final int HASH_LENGTH_BYTES = 16;

    private static final ThreadLocal<MessageDigest> MD5_THREAD_LOCAL = new ThreadLocal<MessageDigest>() {
        @Override
        public MessageDigest initialValue() {
            try {
                return MessageDigest.getInstance("MD5");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
                return null;
            }
        }
    };

//    private transient final Key HMAC_MD5_KEY = new SecretKeySpec(KeyUtils.secureRandomBytes(16), "HmacMd5");

    private transient EncryptedFileUtils encryptedFileUtils;

    private transient Note note;

    private transient final AtomicBoolean modified = new AtomicBoolean(false);

    private transient final AtomicBoolean saveInProgress = new AtomicBoolean(false);

    private transient boolean newNote;

    private transient volatile int lastSavedLength = -1;
    private final transient byte[] lastSavedHash = new byte[HASH_LENGTH_BYTES];

    private TextView save;
    private EditText editText;

    private Intent result;


    private void hash(byte[] output, byte[] data) throws NoSuchAlgorithmException, ShortBufferException, InvalidKeyException, DigestException {
//        Mac hmacMd5 = Mac.getInstance("HmacMd5");
//        hmacMd5.init(HMAC_MD5_KEY);
        MessageDigest md5 = MD5_THREAD_LOCAL.get();
        md5.update(data);
        md5.digest(output, 0, HASH_LENGTH_BYTES);
    }

    private void updateLastSavedHash(byte[] data, int utfStringLen) {
        try {
            hash(lastSavedHash, data);
            lastSavedLength = utfStringLen;
        } catch (NoSuchAlgorithmException | ShortBufferException | InvalidKeyException | DigestException e) {
            e.printStackTrace();
        }
    }

    private void setModified(boolean expected, boolean update) {
        if (modified.compareAndSet(expected, update)) {
            setSaveEnabled(update);
        }
    }

    private void setModified(boolean newValue) {
        modified.set(newValue);
        setSaveEnabled(newValue);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_note);

        Bundle extras = getIntent().getExtras();
        try {
            this.note = new Note(extras.getString(PARAM_NOTE));
        } catch (JSONException e) {
            e.printStackTrace();
        }

        this.save = (TextView) findViewById(R.id.save);

        this.editText = (EditText) findViewById(R.id.edit_text);

        this.encryptedFileUtils = new EncryptedFileUtils(((CustomApplication) getApplication()).getEncryptionManager());

        if(note.exists()) {
            newNote = false;
            try {
                final byte[] data = encryptedFileUtils.readFile(note.getDir(), note.getFilename());

                this.editText.setText(new String(data, UTF_8));

                final int textLen = this.editText.length();

                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        updateLastSavedHash(data, textLen);
                    }
                }).start();

                this.editText.setSelection(textLen);

//                Toast.makeText(NoteActivity.this, "read", Toast.LENGTH_LONG).show();
            } catch (Exception e) {
                e.printStackTrace();
                toastLong( "error: " + e.getMessage());
                finish();
                return;
            }
        } else {
            newNote = true;
        }

        result = new Intent();

        result.putExtra(PARAM_NEW_NOTE, newNote);

        this.save.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                save();
            }
        });

        if(note.exists()) {
            setModified(false);
        } else {
            setModified(true);
        }

        this.editText.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override
            public void afterTextChanged(final Editable s) {

                if(s.length() == lastSavedLength) {

                    new Thread(new Runnable() {
                        @Override
                        public void run() {
                            synchronized (lastSavedHash) {
                                try {
                                    final byte[] hash = new byte[HASH_LENGTH_BYTES];
                                    hash(hash, s.toString().getBytes(UTF_8));
                                    runOnUiThread(new Runnable() {
                                        @Override
                                        public void run() {
                                            if (Arrays.equals(hash, lastSavedHash)) {
                                                setModified(true, false);
                                            } else {
                                                setModified(false, true);
                                            }
                                        }
                                    });
                                } catch (NoSuchAlgorithmException | ShortBufferException | InvalidKeyException | DigestException e) {
                                    e.printStackTrace();
                                }
                            }
                        }
                    }).start();
                } else {
                    setModified(false, true);
                }
            }
        });

    }

    @Override
    public void onStart() {
        super.onStart();
    }

    private void save() {

        if (saveInProgress.compareAndSet(false, true)) {

            setModified(false);

            final String text = editText.getText().toString();
            final byte[] input = text.getBytes(UTF_8);

            new Thread() {

                @Override
                public void run() {

                    boolean success = false;

                    if(note.exists()) {
                        try {

                            System.out.println("old filename = " + note.getFilename());

                            File file = encryptedFileUtils.replaceFile(note.getDir() + '/' + note.getFilename(), note.getDir(), note.getName(), input);

                            System.out.println("new filename = " + file.getName());

                            NoteActivity.this.note.setFilename(file.getName());

//                            NoteActivity.this.note = new Note(note.getDir(), file.getName(), true, note.getName());

                            success = true;
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    } else {

                        try {
                            File file = encryptedFileUtils.writeFile(note.getDir(), note.getName(), input);

                            NoteActivity.this.note = new Note(NoteActivity.this.note.getDir(), file.getName(), true, NoteActivity.this.note.getName());

//                        boolean deleted = new File(note.getAbsolutePath()).delete(); // ************** TODO stop thrashing the disk by changing filenames *********

                            success = true;
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }

                    System.out.println("toString = " + note.toString());

                    result.putExtra(PARAM_NOTE, NoteActivity.this.note.toString());

                    setResult(Activity.RESULT_OK, result);

                    final boolean finalSuccess = success;

                    if(finalSuccess) {
                        lastSavedLength = text.length();
                        try {
                             hash(lastSavedHash, text.getBytes(UTF_8));
                        } catch (NoSuchAlgorithmException | ShortBufferException | InvalidKeyException | DigestException e) {
                            e.printStackTrace();
                            lastSavedLength = -1;
                        }
                    }

                    NoteActivity.this.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {

                            setSaveEnabled(false);

                            saveInProgress.set(false);

                            if(finalSuccess) {
                                toast("saved");
                            } else {
                                toastLong("save failed");
                            }
                        }
                    });
                }

            }.start();
        }

    }

    private void setSaveEnabled(boolean enabled) {
        save.setEnabled(enabled);
        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.HONEYCOMB) {
            save.setAlpha(enabled ? 1.0f : 0.6f);
        } else {
            save.setText(enabled ? "save" : "(no changes)");
        }
    }
}
