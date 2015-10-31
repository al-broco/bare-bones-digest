package com.albroco.androidhttpdigest.lib;

import java.net.HttpURLConnection;

public class HttpDigestState {
    public void processRequest(HttpURLConnection connection) {
    }

    public boolean requestNeedsResend() {
        return false;
    }
}
