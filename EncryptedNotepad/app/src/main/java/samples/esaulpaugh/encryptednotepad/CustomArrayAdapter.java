package samples.esaulpaugh.encryptednotepad;

import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.Color;
import android.os.Build;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.util.ArrayList;

import static samples.esaulpaugh.encryptednotepad.Constants.DIR;

/**
 * Created by esaulpaugh on 3/21/16.
 */
public class CustomArrayAdapter extends ArrayAdapter<Element> {

    private static final boolean HONEYCOMB_OR_LATER = Build.VERSION.SDK_INT >= Build.VERSION_CODES.HONEYCOMB;

    // TODO add attribution to opoloo https://creativecommons.org/licenses/by-sa/4.0/

    private static final int LAYOUT_RESOURCE_ID = R.layout.element;

        private final ListActivity activity;
//        private final Element[] elements;

        public CustomArrayAdapter(ListActivity activity, ArrayList<Element> elements) {
            super(activity, -1, elements);
            this.activity = activity;
//            this.elements = elements;
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            final ViewHolder viewHolder;
            if(convertView == null) {
                LayoutInflater inflater = activity.getLayoutInflater();
                convertView = inflater.inflate(LAYOUT_RESOURCE_ID, parent, false);
                viewHolder = new ViewHolder();
                viewHolder.icon = (ImageView) convertView.findViewById(R.id.icon);
                viewHolder.name = (TextView) convertView.findViewById(R.id.text);
                convertView.setTag(viewHolder);
            } else{
                viewHolder = (ViewHolder) convertView.getTag();
            }

            final Element e = getItem(position);

            boolean folder = e instanceof Folder;

            viewHolder.icon.setImageResource(folder ? R.drawable.ic_action_folder_closed : R.drawable.ic_action_list);
            viewHolder.name.setText(e.getName());

            int purp = Color.parseColor("#FF5A4BC7"); // FFCCCCCC
            int pink = Color.parseColor("#FF0BFF"); // FFDDDD00

            convertView.setBackgroundColor(folder ? purp : pink);
            if(HONEYCOMB_OR_LATER) {
                convertView.setAlpha(0.82f);
            }

            viewHolder.name.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    Intent intent;

                    activity.setForward(true);

                    if(e instanceof Folder) {

                        intent = new Intent(activity, ListActivity.class);
                        intent.putExtra(DIR, e.getDir() + '/' + e.getFilename());

                        activity.startActivityForResult(intent, ListActivity.REQUEST_OPEN_FOLDER);

                    } else {

                        intent = new Intent(activity, NoteActivity.class);
                        intent.putExtra(NoteActivity.PARAM_NOTE, e.toString());

                        activity.startActivityForResult(intent, NoteActivity.REQUEST_CODE_EDIT_NOTE);

                    }
                }
            });

            viewHolder.name.setOnLongClickListener(new View.OnLongClickListener() {
                @Override
                public boolean onLongClick(View v) {

                    new AlertDialog.Builder(activity)
                            .setTitle("Delete?")
                            .setPositiveButton("Delete", new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface dialog, int which) {
                                    try {
                                        activity.deleteElement(e);
                                    } catch (IOException e1) {
                                        e1.printStackTrace();
                                    } catch (IllegalArgumentException iae) {
                                        Toast.makeText(activity, iae.getMessage(), Toast.LENGTH_SHORT).show();
                                    }
                                }
                            })
                            .setNegativeButton("Cancel", null)
                            .show();


                    return false;
                }
            });

            return convertView;
        }

    private static class ViewHolder {
        private ImageView icon;
        private TextView name;
    }


}
