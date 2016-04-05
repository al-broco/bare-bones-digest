package com.albroco.androidhttpdigest;

import android.util.Log;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.PasswordAuthentication;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;

public class HttpDigestState {
  private static final String LOG_TAG = HttpDigestState.class.getSimpleName();

  private static final String WWW_AUTHENTICATE_HTTP_HEADER_NAME = "WWW-Authenticate";
  private static final String AUTHORIZATION_HTTP_HEADER_NAME = "Authorization";
  public static final String HTTP_DIGEST_CHALLENGE_PREFIX = "Digest ";

  private final MessageDigest md5;
  private boolean resendNeeded = false;
  private int nonceCount;
  private String realm;
  private String nonce;
  private String clientNonce;
  private String opaqueQuoted;
  private String algorithm;
  private PasswordAuthentication authentication;

  public HttpDigestState(PasswordAuthentication authentication) {
    this.authentication = authentication;

    try {
      this.md5 = MessageDigest.getInstance("MD5");
    } catch (NoSuchAlgorithmException e) {
      // TODO find out if this can happen
      throw new RuntimeException(e);
    }
  }

  public void updateStateFromResponse(int statusCode, Map<String, List<String>> responseHeaders) {
    resendNeeded = false;
    
    if (responseContainsChallenge(statusCode, responseHeaders)) {
      updateStateFromChallenge(responseHeaders);
    }

    // TODO: Support Authentication-Info header with changing nonce values
  }

  public void updateStateFromResponse(HttpURLConnection connection) throws IOException {
    updateStateFromResponse(connection.getResponseCode(), connection.getHeaderFields());
  }

  public static boolean responseContainsChallenge(int statusCode,
      Map<String, List<String>> responseHeaders) {
    // RFC 2617, Section 3.2.1:
    // If a server receives a request for an access-protected object, and an
    // acceptable Authorization header is not sent, the server responds with
    // a "401 Unauthorized" status code, and a WWW-Authenticate header as
    // per the framework defined above
    if (statusCode != 401) {
      return false;
    }

    List<String> wwwAuthenticateHeaders = responseHeaders.get(WWW_AUTHENTICATE_HTTP_HEADER_NAME);
    for (String wwwAuthenticateHeader : wwwAuthenticateHeaders) {
      if (wwwAuthenticateHeader.startsWith(HTTP_DIGEST_CHALLENGE_PREFIX)) {
        return true;
      }
    }

    return false;
  }

  public static boolean responseContainsChallenge(HttpURLConnection connection) throws IOException {
    return responseContainsChallenge(connection.getResponseCode(), connection.getHeaderFields());
  }

  public void updateStateFromChallenge(Map<String, List<String>> responseHeaders) {
    List<String> wwwAuthenticateResponseHeaders =
        responseHeaders.get(WWW_AUTHENTICATE_HTTP_HEADER_NAME);
    if (wwwAuthenticateResponseHeaders == null) {
      return;
    }

    for (String wwwAuthenticateResponseHeader : wwwAuthenticateResponseHeaders) {
      updateStateFromChallenge(wwwAuthenticateResponseHeader);
    }
  }

  public void updateStateFromChallenge(String wwwAuthenticateResponseHeader) {
    WwwAuthenticateHeader header = WwwAuthenticateHeader.parse(wwwAuthenticateResponseHeader);

    if (header != null) {
      realm = header.getRealm();
      setNonce(header.getNonce());
      opaqueQuoted = header.getOpaqueQuoted();
      algorithm = header.getAlgorithm();
      resendNeeded = true;
    }
  }

  public String getAuthorizationHeaderForRequest(String requestMethod, String path) {
    if (nonce == null) {
      return null;
    }

    return createAuthorizationHeader(requestMethod, path);
  }

  public String getAuthorizationHeaderForRequest(HttpURLConnection connection) {
    String requestMethod = connection.getRequestMethod();
    String path = connection.getURL().getPath();
    return getAuthorizationHeaderForRequest(requestMethod, path);
  }

  public void setHeadersOnRequest(HttpURLConnection connection) {
    String requestMethod = connection.getRequestMethod();
    String path = connection.getURL().getPath();
    String authorizationHeader = getAuthorizationHeaderForRequest(requestMethod, path);

    if (authorizationHeader != null) {
      connection.setRequestProperty(AUTHORIZATION_HTTP_HEADER_NAME, authorizationHeader);
    }
  }

  public boolean isResendNeeded() {
    return resendNeeded;
  }

  // TODO: this is useless for requests that POST a body or where the request must be manipulated
  // after headers are set
  public void processRequest(HttpURLConnection connection) throws IOException {
    setHeadersOnRequest(connection);

    updateStateFromResponse(connection);
  }

  private void setNonce(String nonce) {
    if (!nonce.equals(this.nonce)) {
      // When nonce changes, reset the nonce count.
      // RFC 2617 Section 3.2.2:
      // [...] The nc-value is the hexadecimal count of the number of requests (including the
      // current request) that the client has sent with the nonce value in this request.
      this.nonce = nonce;
      resetNonceCount();
    }
  }

  private void resetNonceCount() {
    this.nonceCount = 1;
  }

  private void incrementNonceCount() {
    this.nonceCount++;
  }

  private String createAuthorizationHeader(String requestMethod, String path) {
    generateClientNonce();

    String response = calculateResponse(requestMethod, path);

    StringBuilder result = new StringBuilder();
    result.append("Digest ");

    // Username is defined in Section 3.2.2 of RFC 2617
    // username         = "username" "=" username-value
    // username-value   = quoted-string
    result.append("username=");
    result.append(quoteString(authentication.getUserName()));
    result.append(",");

    // Realm is defined in RFC 2617, Section 1.2
    // realm       = "realm" "=" realm-value
    // realm-value = quoted-string
    // TODO: Keep different states per realm, see Section 1.2 of RFC 2617
    // TODO: Unnecessary to quote and then unquote string value
    result.append("realm=");
    result.append(quoteString(realm));
    result.append(",");

    // nonce             = "nonce" "=" nonce-value
    // nonce-value       = quoted-string
    // TODO: Unnecessary to quote and then unquote string value
    result.append("nonce=");
    result.append(quoteString(nonce));
    result.append(",");

    // digest-uri       = "uri" "=" digest-uri-value
    // digest-uri-value = request-uri   ; As specified by HTTP/1.1
    result.append("uri=");
    result.append(quoteString(path));
    result.append(",");

    // Response is defined in RFC 2617, Section 3.2.2 and 3.2.2.1
    // response         = "response" "=" request-digest
    result.append("response=");
    result.append(response);
    result.append(",");

    // Cnonce is defined in RFC 2617, Section 3.2.2
    // cnonce           = "cnonce" "=" cnonce-value
    // cnonce-value     = nonce-value
    // Must be present if qop is specified, must not if qop is unspecified
    // TODO: don't include if qop is unspecified
    result.append("cnonce=");
    result.append(clientNonce);
    result.append(",");

    // Opaque and algorithm are explained in Section 3.2.2 of RFC 2617:
    // "The values of the opaque and algorithm fields must be those supplied
    // in the WWW-Authenticate response header for the entity being
    // requested."

    if (opaqueQuoted != null) {
      result.append("opaque=");
      result.append(opaqueQuoted);
      result.append(",");
    }

    if (algorithm != null) {
      result.append("algorithm=");
      result.append(algorithm);
      result.append(",");
    }

    // TODO Verify that server supports auth
    // TODO Also support auth-int
    result.append("qop=auth");
    result.append(",");

    // Nonce count is defined in RFC 2617, Section 3.2.2
    // nonce-count      = "nc" "=" nc-value
    // nc-value         = 8LHEX (lower case hex)
    // Must be present if qop is specified, must not if qop is unspecified
    result.append("nc=");
    result.append(String.format("%08x", nonceCount));

    incrementNonceCount();

    Log.e(LOG_TAG, "Hdr: " + result);

    return result.toString();
  }

  private String calculateResponse(String requestMethod, String path) {
    // TODO: Below calculation is for the case where qop is present, if not qop is calculated
    // differently
    String a1 = calculateA1();
    String a2 = calculateA2(requestMethod, path);

    String secret = calculateMd5(a1);
    String data = joinWithColon(nonce,
        String.format("%08x", nonceCount),
        clientNonce,
        "auth",
        calculateMd5(a2));

    return "\"" + calculateMd5(secret + ":" + data) + "\"";
  }

  private String calculateA1() {
    // TODO: Below calculation is for if algorithm is MD5 or unspecified
    // TODO: Support MD5-sess algorithm
    return joinWithColon(authentication.getUserName(),
        realm,
        new String(authentication.getPassword()));
  }

  private String calculateA2(String requestMethod, String path) {
    // TODO: Below calculation if if qop is auth or unspecified
    // TODO: Support auth-int qop
    return joinWithColon(requestMethod, path);
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

  private static String encodeHexString(byte[] bytes) {
    StringBuilder result = new StringBuilder(bytes.length * 2);
    for (int i = 0; i < bytes.length; i++) {
      result.append(Integer.toHexString((bytes[i] & 0xf0) >> 4));
      result.append(Integer.toHexString((bytes[i] & 0x0f)));
    }
    return result.toString();
  }

  private void updateStateFromChallenge(HttpURLConnection connection) {
    updateStateFromChallenge(connection.getHeaderField(WWW_AUTHENTICATE_HTTP_HEADER_NAME));
  }

  private String quoteString(String str) {
    // TODO: implement properly
    return "\"" + str + "\"";
  }
}
