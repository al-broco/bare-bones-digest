package com.albroco.androidhttpdigest;

import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import java.net.HttpURLConnection;
import java.net.URL;

public class MainActivity extends AppCompatActivity {
    private static final String LOG_TAG = MainActivity.class.getSimpleName();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        new MakeRequestAsyncTask().execute();
    }

    private static class MakeRequestAsyncTask extends AsyncTask<Void, Void, Void>  {
        private static final String TEST_URL = "http://httpbin.org/basic-auth/user/passwd";

        @Override
        protected Void doInBackground(Void... params) {
            try {
                HttpURLConnection connection = (HttpURLConnection) new URL(TEST_URL).openConnection();
                int statusCode = connection.getResponseCode();
                Log.i(LOG_TAG, "Request response code: " + statusCode);
            } catch (Exception e) {
                Log.e(LOG_TAG, "Request failed", e);
            }

            return null;
        }
    }
}
