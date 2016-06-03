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
import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.res.Configuration;
import android.os.Bundle;
import android.util.Log;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.Window;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;

import org.json.JSONException;

import java.io.File;
import java.io.IOException;
import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import javax.security.auth.DestroyFailedException;

import static samples.esaulpaugh.encryptednotepad.Constants.DIR;
import static samples.esaulpaugh.encryptednotepad.Constants.UTF_8;

public class ListActivity extends AbstractActivity {


//  TODo  https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-00#page-11


    public static final int REQUEST_OPEN_FOLDER = 2;

    private static final int INITIAL_LIST_CAPACITY_PADDING = 3;

//    private volatile boolean gogo;
//    private volatile boolean backPressed;

//    private boolean root;
    private String dir;


    private transient EncryptedFileUtils encryptedFileUtils;

    private ArrayList<Element> elements;
    private CustomArrayAdapter adapter;

    private final HashMap<Long, Integer> idToIndexMap = new HashMap<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_list);

        this.dir = getIntent().getStringExtra(DIR);

        System.out.println("dir = " + dir);

        TextView newNoteButton = (TextView) findViewById(R.id.new_note);
//        this.newFolderButton = (TextView) findViewById(R.id.new_folder);
        ListView listView = (ListView) findViewById(R.id.list_view);

//            ((CustomApplication) getApplication()).setEncryptionManager(null);

        EncryptionManager em = getEncryptionManager();

        if(em == null) {
            System.out.println("em == null... finishing activity");
            finish();
            return;
        }

        this.encryptedFileUtils = new EncryptedFileUtils(em);

        elements = getElements(new File(dir).listFiles(), em);

        adapter = new CustomArrayAdapter(ListActivity.this, elements);

        listView.setAdapter(adapter);

//        listView.setOnItemClickListener(new AdapterView.OnItemClickListener() {
//            @Override
//            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
//                Element e = (Element) parent.getItemAtPosition(position);
//
//                Intent intent;
//                if(e instanceof Folder) {
//                    intent = new Intent(ListActivity.this, ListActivity.class);
//                    intent.putExtra(DIR, e.getDir());
//
//                    startActivity(intent);
//
//                } else {
//
//                    intent = new Intent(ListActivity.this, NoteActivity.class);
//                    intent.putExtra(NoteActivity.PARAM_NOTE, e.toString());
//
//                    startActivityForResult(intent, NoteActivity.REQUEST_CODE_EDIT_NOTE);
//
//                }
//
//
//            }
//        });

        assert newNoteButton != null;

        newNoteButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                View enterNameView = getLayoutInflater().inflate(R.layout.alert_enter_note_name, null);

                final EditText enterElementName = (EditText) enterNameView.findViewById(R.id.enter_element_name);
//                final View create = enterNameView.findViewById(R.id.create);

                final Dialog dialog = new Dialog(ListActivity.this);
                dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
                dialog.setContentView(enterNameView);

                enterElementName.setImeActionLabel("create", EditorInfo.IME_ACTION_DONE);

                enterElementName.setOnEditorActionListener(new PasscodeListener(new Runnable() {
                    @Override
                    public void run() {
                        final String name = enterElementName.getText().toString();

                        Note newNote = new Note(dir, null, false, name);

                        openNote(newNote);

                        dialog.dismiss();
                    }
                }));


//                create.setOnClickListener(new View.OnClickListener() {
//                    @Override
//                    public void onClick(View v) {
//                        final String name = enterElementName.getText().toString();
//
//                        Note newNote = new Note(dir, null, false, name);
//
//                        openNote(newNote);
//
//                        dialog.dismiss();
//                    }
//                });

                dialog.show();

                dialog.getWindow().setLayout(512, LinearLayout.LayoutParams.WRAP_CONTENT);

                enterElementName.postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        final InputMethodManager imm = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
                        imm.showSoftInput(enterElementName, 0);
                    }
                }, 40);


            }
        });

//        this.newFolderButton.setOnClickListener(new View.OnClickListener() {
//            @Override
//            public void onClick(View v) {
//
//            }
//        });


    }

    private ArrayList<Element> getElements(File[] fileArray, EncryptionManager encryptionManager) {

        List<File> files = Arrays.asList(fileArray);
        Collections.sort(files);

        final int numFiles = files.size();

        final ArrayList<Element> elements = new ArrayList<>(numFiles + INITIAL_LIST_CAPACITY_PADDING);

        Log.i("YAYA", "found " + numFiles + " files");


        for (int i = 0; i < numFiles; i++) {
            File file = files.get(i);
            String path = file.getAbsolutePath();

//            System.out.println("FILE " + file.getAbsolutePath());

            if (path.endsWith("instant-run")) {
                continue;
            }
            String dir = path.substring(0, path.lastIndexOf('/'));
            try {
                String name = new String(encryptionManager.decrypt(new EncryptionManager.EncryptedMessage(Utils.decode(file.getName()))), UTF_8);

                Element e = file.isDirectory()
                        ? new Folder(dir, file.getName(), true, name)
                        : new Note(dir, file.getName(), true, name);

                elements.add(e);

//                idToIndexMap.put(e.getId(), i);

            } catch (InvalidParameterException ipe) {
                ipe.printStackTrace();
            } catch (IllegalStateException ise) {
                ise.printStackTrace();
                finish();
            }
        }

        Collections.sort(elements);

        final int numElements = elements.size();
        for (int i = 0; i < numElements; i++) {
            idToIndexMap.put(elements.get(i).getId(), i);
        }

        return elements;
    }

    private void openNote(Note note) {
        Intent intent = new Intent(ListActivity.this, NoteActivity.class);

//        intent.putExtra(NoteActivity.PARAM_DIR, dir);
        intent.putExtra(NoteActivity.PARAM_NOTE, note.toString());

        startActivityForResult(intent, NoteActivity.REQUEST_CODE_EDIT_NOTE);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {

        if (requestCode == NoteActivity.REQUEST_CODE_EDIT_NOTE) {
            if (resultCode == Activity.RESULT_OK) {
                try {

                    Note note = new Note(data.getStringExtra(NoteActivity.PARAM_NOTE));

                    boolean newNote = data.getBooleanExtra(NoteActivity.PARAM_NEW_NOTE, false);

                    if (newNote) {


                        if (elements.add(note)) {
                            idToIndexMap.put(note.getId(), elements.size() - 1);
                        }

                    } else {

                        long id = note.getId();
                        Integer index = idToIndexMap.get(id);
//                        System.out.println(id + " --> " + index);
//
//                        for(Map.Entry<Long, Integer> e : idToIndexMap.entrySet()) {
//                            System.out.println(e.getKey() + ", " + e.getValue());
//                        }

                        elements.set(index, note);

                    }

                    adapter.notifyDataSetChanged();

                    // TODO fix filename changes on every save

                } catch (JSONException e) {
                    e.printStackTrace();
                }
            }
        } else if (requestCode == REQUEST_OPEN_FOLDER) {
            if (resultCode == -2) {
                setResult(resultCode);
                finish();
            }
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_options, menu);
        return true;
    }

    private class PasscodeListener implements TextView.OnEditorActionListener {

        private Runnable runnable;

        public PasscodeListener(Runnable runnable) {
            this.runnable = runnable;
        }

        @Override
        public boolean onEditorAction(final TextView textView, int actionId, KeyEvent keyEvent) {
            if ((keyEvent == null && actionId == EditorInfo.IME_ACTION_DONE)
                    || (keyEvent != null && keyEvent.getAction() == KeyEvent.ACTION_DOWN && actionId == EditorInfo.IME_NULL)) {

                runnable.run();

                return true;

            }

            return false;
        }
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {

        final InputMethodManager imm = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);

        switch (item.getItemId()) {
            case R.id.menu_create_folder:

                View enterNameView = getLayoutInflater().inflate(R.layout.alert_enter_note_name, null);

                final EditText enterElementName = (EditText) enterNameView.findViewById(R.id.enter_element_name);
//                final View create = enterNameView.findViewById(R.id.create);

                final Dialog dialog = new Dialog(ListActivity.this);
                dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
                dialog.setContentView(enterNameView);

                enterElementName.setImeActionLabel("create", EditorInfo.IME_ACTION_DONE);

                enterElementName.setOnEditorActionListener(new PasscodeListener(new Runnable() {
                    @Override
                    public void run() {
                        final String name = enterElementName.getText().toString();

                        File file;
                        if ((file = encryptedFileUtils.mkdir(dir, name)) != null) {
                            Folder folder = new Folder(dir, file.getName(), true, name);

                            boolean success;
                            if (success = elements.add(folder)) {
                                idToIndexMap.put(folder.getId(), elements.size() - 1);
                                adapter.notifyDataSetChanged();
                            }

                            imm.hideSoftInputFromWindow(enterElementName.getWindowToken(), 0);

                            dialog.dismiss();

                            toast(success ? "folder created" : "creation failed");
                        }
                    }
                }));

//                create.setOnClickListener(new View.OnClickListener() {
//                    @Override
//                    public void onClick(View v) {
//                        final String name = enterElementName.getText().toString();
//
//                        File file;
//                        if ((file = encryptedFileUtils.mkdir(dir, name)) != null) {
//                            Folder folder = new Folder(dir, file.getName(), true, name);
//                            if (elements.add(folder)) {
//                                idToIndexMap.put(folder.getId(), elements.size() - 1);
//                                adapter.notifyDataSetChanged();
//                            }
//
//                            imm.hideSoftInputFromWindow(enterElementName.getWindowToken(), 0);
//
//                            dialog.dismiss();
//                        }
//                    }
//                });

                dialog.show();

                dialog.getWindow().setLayout(512, LinearLayout.LayoutParams.WRAP_CONTENT);

                enterElementName.postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        imm.showSoftInput(enterElementName, 0);
                    }
                }, 40);

                return true;
            case R.id.menu_change_password:

                View v = getLayoutInflater().inflate(R.layout.alert_change_password, null);

                final EditText enterOldPassword = (EditText) v.findViewById(R.id.enter_old_password);
                final EditText enterNewPassword = (EditText) v.findViewById(R.id.enter_new_password);
                final EditText confirmNewPassword = (EditText) v.findViewById(R.id.confirm_new_password);

                final Activity activity = ListActivity.this;

                new AlertDialog.Builder(activity)
                        .setTitle("Change password")
                        .setView(v)
                        .setPositiveButton("Change password", new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialog, int which) {
                                final String oldPass = enterOldPassword.getText().toString();
                                final String newpass = enterNewPassword.getText().toString();
                                final String confirmedNewPass = confirmNewPassword.getText().toString();

                                if (!confirmedNewPass.equals(newpass) || !KeyUtils.changePassword(activity, oldPass, newpass)) {
                                    toast("error");
                                } else {
                                    toast("success");
                                    System.out.println("changePassword success");
                                }
                            }
                        })
                        .setNegativeButton("Cancel", null)
                        .show();

                enterOldPassword.postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        imm.showSoftInput(enterOldPassword, 0);
                    }
                }, 40);

                return true;

            case R.id.menu_about:
                startActivity(new Intent(ListActivity.this, AboutActivity.class));
                return true;
            case R.id.menu_exit:

                // TODO close the app

                EncryptionManager em = ((CustomApplication) getApplication()).getEncryptionManager();

                if (em != null && !em.isDestroyed()) {
                    try {
                        em.destroy();
                        System.out.println("EncryptionManager destroyed");
                    } catch (DestroyFailedException e) {
                        e.printStackTrace();
                    }
                }

//                Intent intent = new Intent(ListActivity.this, RootActivity.class);
//                intent.putExtra("exit", true);
//                intent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
//                startActivity(intent);

                setResult(-2);

                finish();

                return true;
            default:
                return super.onOptionsItemSelected(item);
        }
    }

    // TODO fix delete
    public void deleteElement(Element e) throws IOException, IllegalArgumentException {

        if (encryptedFileUtils.deleteFile(new File(e.getDir() + '/' + e.getFilename()))) {

            int index = idToIndexMap.remove(e.getId());
            elements.remove(index);
            adapter.notifyDataSetChanged();

            final int size = elements.size();
            for (int i = index; i < size; i++) {
                idToIndexMap.put(elements.get(i).getId(), i);
            }

        }
    }

//    @Override
//    public void onBackPressed() {
//
//        System.out.println("onBackPressed");
//
//        backPressed = true;
//
//        super.onBackPressed();
//    }

//    @Override
//    public void onResume() {
//
//        this.gogo = false;
//
//        if (encryptionManager == null || encryptionManager.isDestroyed()) {
//            finish();
//        }
//
//        super.onResume();
//    }

//    @Override
//    public void onPause() {
//
//        System.out.println("onPause()");
//
//        System.out.println("gogo = " + gogo);
//        System.out.println("backPressed = " + backPressed);
//        System.out.println("root = " + root);
//
//        if((!backPressed && !gogo) || (root && backPressed)) {
//            destroyEncryptionManager();
//        }
//
//        super.onPause();
//    }

//    @Override
//    public void onDestroy() {
//
//
//
//       System.out.println("onDestroy()");
//
//        System.out.println("backPressed = " + backPressed);
//        System.out.println("root = " + root);
//
//
//
////        destroyEncryptionManager();
//
//        super.onDestroy();
//    }

}
