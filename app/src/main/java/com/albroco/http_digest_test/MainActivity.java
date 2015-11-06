package com.albroco.http_digest_test;

import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import com.albroco.androidhttpdigest.HttpDigestState;

import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.HttpURLConnection;
import java.net.PasswordAuthentication;
import java.net.URL;

public class MainActivity extends AppCompatActivity {
    private static final String LOG_TAG = MainActivity.class.getSimpleName();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        CookieHandler.setDefault(new CookieManager());

        new MakeRequestAsyncTask().execute();
    }

    private static class MakeRequestAsyncTask extends AsyncTask<Void, Void, Void>  {
        private static final String TEST_URL = "http://httpbin.org/digest-auth/auth/user/passwd";

        @Override
        protected Void doInBackground(Void... params) {
            try {
                PasswordAuthentication auth = new PasswordAuthentication("user", "passwd".toCharArray());
                HttpDigestState httpDigestState = new HttpDigestState(auth);
                HttpURLConnection connection;

                connection = (HttpURLConnection) new URL(TEST_URL).openConnection();
                httpDigestState.processRequest(connection);
                Log.i(LOG_TAG, "First request response code: " + connection.getResponseCode());

                if (httpDigestState.requestNeedsResend()) {
                    connection = (HttpURLConnection) new URL(TEST_URL).openConnection();
                    httpDigestState.processRequest(connection);
                    Log.i(LOG_TAG, "Second request response code: " + connection.getResponseCode());
                }
            } catch (Exception e) {
                Log.e(LOG_TAG, "Request failed", e);
            }

            return null;
        }
    }
}
