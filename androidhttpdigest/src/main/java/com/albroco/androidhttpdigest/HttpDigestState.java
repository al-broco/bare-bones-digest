package com.albroco.androidhttpdigest;

import android.util.Log;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HttpDigestState {
    private static final String LOG_TAG = HttpDigestState.class.getSimpleName();

    private static final String WWW_AUTHENTICATE_HTTP_HEADER_NAME = "WWW-Authenticate";
    private static final String AUTHORIZATION_HTTP_HEADER_NAME = "Authorization";
    public static final String HTTP_DIGEST_CHALLENGE_PREFIX = "Digest ";

    private final MessageDigest md5;
    private boolean needsResend = false;
    private String userName;
    private String password;
    private int nonceCount;
    private String realm;
    private String nonce;
    private String clientNonce;
    private String opaqueQuoted;
    private String algorithm;

    public HttpDigestState(String userName, String password) {
        this.userName = userName;
        this.password = password;
        try {
            this.md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            // TODO find out if this can happen
            throw new RuntimeException(e);
        }
    }

    public void processRequest(HttpURLConnection connection) throws IOException {
        updateRequestBeforeSending(connection);

        boolean challengeReceived = responseHasHttpDigestChallenge(connection);
        if (challengeReceived) {
            updateStateFromHttpDigestChallenge(connection);
            nonceCount = 1;
        }

        needsResend = challengeReceived;
    }

    public boolean requestNeedsResend() {
        return needsResend;
    }

    private void updateRequestBeforeSending(HttpURLConnection connection) {
        if (nonce == null) {
            return;
        }

        connection.setRequestProperty(AUTHORIZATION_HTTP_HEADER_NAME, createAuthorizationHeader(connection));
    }

    private String createAuthorizationHeader(HttpURLConnection connection) {
        generateClientNonce();

        String response = calculateResponse(connection);

        StringBuilder result = new StringBuilder();
        result.append("Digest ");

        result.append("username=");
        result.append(quoteString(userName));
        result.append(",");

        // TODO unsure what this is
        result.append("realm=");
        result.append(quoteString(realm));
        result.append(",");

        result.append("nonce=");
        result.append(quoteString(nonce));
        result.append(",");

        result.append("uri=");
        result.append(quoteString(connection.getURL().getPath()));
        result.append(",");

        result.append("response=");
        result.append(response);
        result.append(",");

        if (algorithm != null) {
            result.append("algorithm=");
            result.append(algorithm);
            result.append(",");
        }

        result.append("cnonce=");
        result.append(clientNonce);
        result.append(",");

        if (opaqueQuoted != null) {
            result.append("opaque=");
            result.append(opaqueQuoted);
            result.append(",");
        }

        // TODO handle other qop values
        result.append("qop=auth");
        result.append(",");

        // TODO: not sure about case
        result.append("nc=");
        result.append(String.format("%08x", nonceCount));

        // TODO other values

        Log.e(LOG_TAG, "Hdr: " + result);

        return result.toString();
    }

    private String calculateResponse(HttpURLConnection connection) {
        String a1 = calculateA1();
        String a2 = calculateA2(connection);

        String secret = calculateMd5(a1);
        String data = joinWithColon(nonce, String.format("%08x", nonceCount), clientNonce, "auth", calculateMd5(a2));

        return "\"" + calculateMd5(secret + ":" + data) + "\"";
    }

    private String calculateA1() {
        return joinWithColon(userName, realm, password);
    }

    private String calculateA2(HttpURLConnection connection) {
        return joinWithColon(connection.getRequestMethod(), connection.getURL().getPath());
    }

    private void generateClientNonce() {
        // TODO generate properly
        clientNonce = "0a4f113b";
    }

    private String joinWithColon(String... parts) {
        StringBuilder result = new StringBuilder();

        for (String part : parts) {
            if (result.length() > 0) {
                result.append(":");
            }
            result.append(part);
        }

        return result.toString();
    }

    private String calculateMd5(String string) {
        md5.reset();
        // TODO find out which encoding to use
        md5.update(string.getBytes());
        return encodeHexString(md5.digest());
    }

    private static String encodeHexString(byte[] bytes)
    {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for(int i = 0; i < bytes.length; i++){
            result.append(Integer.toHexString((bytes[i] & 0xf0) >> 4));
            result.append(Integer.toHexString((bytes[i] & 0x0f)));
        }
        return result.toString();
    }


    private static boolean responseHasHttpDigestChallenge(HttpURLConnection connection) throws IOException {
        // RFC 2617, Section 3.2.1:
        // If a server receives a request for an access-protected object, and an
        // acceptable Authorization header is not sent, the server responds with
        // a "401 Unauthorized" status code, and a WWW-Authenticate header as
        // per the framework defined above
        int statusCode = connection.getResponseCode();
        if (statusCode != 401) {
            return false;
        }

        // TODO: Handle multiple challenges
        String authenticateHeader = connection.getHeaderField(WWW_AUTHENTICATE_HTTP_HEADER_NAME);
        return authenticateHeader != null && authenticateHeader.startsWith(HTTP_DIGEST_CHALLENGE_PREFIX);
    }

    private void updateStateFromHttpDigestChallenge(HttpURLConnection connection) {
        String authenticateHeader = connection.getHeaderField(WWW_AUTHENTICATE_HTTP_HEADER_NAME);

        if (!authenticateHeader.startsWith(HTTP_DIGEST_CHALLENGE_PREFIX)) {
            return;
        }

        realm = null;
        nonce = null;
        opaqueQuoted = null;
        algorithm = null;

        // TODO: Current parsing is broken and only works for simple cases
        String digestChallenge = authenticateHeader.substring(HTTP_DIGEST_CHALLENGE_PREFIX.length());
        String challengeParts[] = digestChallenge.split(",");
        for (String challengePart : challengeParts) {
            int equalsIndex = challengePart.indexOf('=');
            if (equalsIndex != -1) {
                String key = challengePart.substring(0, equalsIndex).trim();
                String value = challengePart.substring(equalsIndex + 1).trim();

                if (key.equals("realm")) {
                    realm = unquoteString(value);
                } else if (key.equals("nonce")) {
                    nonce = unquoteString(value);
                } else if (key.equals("opaque")) {
                    opaqueQuoted = value;
                } else if (key.equals("algorithm")) {
                    algorithm = value;
                }
            }
        }
    }

    private String quoteString(String str) {
        // TODO: implement properly
        return "\"" + str + "\"";
    }

    private String unquoteString(String str) {
        // TODO: implement properly
        if (str.startsWith("\"") && str.endsWith("\"")) {
            return str.substring(1, str.length() - 1);
        }
        return str;
    }
}
