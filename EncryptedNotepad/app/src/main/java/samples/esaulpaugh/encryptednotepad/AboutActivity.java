package samples.esaulpaugh.encryptednotepad;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.text.Html;
import android.text.SpannableStringBuilder;
import android.text.method.LinkMovementMethod;
import android.text.style.ClickableSpan;
import android.text.style.URLSpan;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

/**
 * Created by esaulpaugh on 5/11/16.
 */
public class AboutActivity extends AbstractActivity {

    private static final String HTML = "Attributions:" +
            "<br>" +
            "<br>" +
            "<br>Opoloo" +
            "<br><a href=\"http://www.androidicons.com/\">Android Developer Icons</a>" +
            "<br><a href=\"https://creativecommons.org/licenses/by-sa/4.0/legalcode\">Creative Commons Attribution-ShareAlike 4.0 International Public License</a>" +
            "<br>" +
            "<br>" +
            "<br>Scrypt implementation" +
            "<br>Colin Percival, <a href=\"http://www.tarsnap.com/scrypt.html\">Tarsnap</a>, <a href=\"https://github.com/wg/scrypt\">Will Glozer</a>, lambdaworks" +
            "<br>";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_about);

        TextView tv = (TextView) findViewById(R.id.attributions);

        setTextViewHTML(tv, HTML);

//        Spanned spanned = Html.fromHtml();

//        tv.setText(spanned);

        // TODO attribution for scrypt and icons -- Tarsnap, Will Glozer (lambdaworks), opoloo

        Toast.makeText(this, "TODO attribution for scrypt and icons -- Tarsnap, Will Glozer (lambdaworks), opoloo", Toast.LENGTH_LONG).show();
    }

    protected void makeLinkClickable(SpannableStringBuilder strBuilder, final URLSpan span)
    {
        int start = strBuilder.getSpanStart(span);
        int end = strBuilder.getSpanEnd(span);
        int flags = strBuilder.getSpanFlags(span);
        ClickableSpan clickable = new ClickableSpan() {
            public void onClick(View view) {
                // Do something with span.getURL() to handle the link click...

                System.out.println(span.getURL());

                Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(span.getURL()));
                startActivity(browserIntent);

            }
        };
        strBuilder.setSpan(clickable, start, end, flags);
        strBuilder.removeSpan(span);
    }

    protected void setTextViewHTML(TextView text, String html)
    {
        CharSequence sequence = Html.fromHtml(html);
        SpannableStringBuilder strBuilder = new SpannableStringBuilder(sequence);
        URLSpan[] urls = strBuilder.getSpans(0, sequence.length(), URLSpan.class);
        for(URLSpan span : urls) {
            makeLinkClickable(strBuilder, span);
        }
        text.setText(strBuilder);
        text.setMovementMethod(LinkMovementMethod.getInstance());
    }

}
