package com.albroco.androidhttpdigest;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.PasswordAuthentication;
import java.util.List;
import java.util.Map;

public class HttpDigestState {
  public static final String HTTP_DIGEST_CHALLENGE_PREFIX = "Digest ";

  private AuthorizationRequestHeader authorizationRequestHeader;

  private boolean resendNeeded = false;

  public HttpDigestState(PasswordAuthentication authentication) {
    this.authorizationRequestHeader = new AuthorizationRequestHeader();
    authorizationRequestHeader.setAuthentication(authentication);
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

    List<String> wwwAuthenticateHeaders = responseHeaders.get(WwwAuthenticateHeader.HEADER_NAME);
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
    List<String> wwwAuthenticateResponseHeaders = responseHeaders.get(WwwAuthenticateHeader.HEADER_NAME);
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
      authorizationRequestHeader.setRealm(header.getRealm());
      setNonce(header.getNonce());
      authorizationRequestHeader.setOpaqueQuoted(header.getOpaqueQuoted());
      authorizationRequestHeader.setAlgorithm(header.getAlgorithm());

      resendNeeded = true;
    }
  }

  public String getAuthorizationHeaderForRequest(String requestMethod, String path) {
    if (authorizationRequestHeader.getNonce() == null) {
      return null;
    }

    // TODO: Generate rnadom client nonce
    authorizationRequestHeader.setClientNonce("0a4f113b");
    authorizationRequestHeader.setPath(path);
    authorizationRequestHeader.setRequestMethod(requestMethod);

    String headerValue = authorizationRequestHeader.getHeaderValue();

    authorizationRequestHeader.incrementNonceCount();

    return headerValue;
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

    connection.setRequestProperty(AuthorizationRequestHeader.HEADER_NAME, authorizationHeader);
  }

  public boolean isResendNeeded() {
    return resendNeeded;
  }

  private void setNonce(String nonce) {
    if (!nonce.equals(authorizationRequestHeader.getNonce())) {
      // When nonce changes, reset the nonce count.
      // RFC 2617 Section 3.2.2:
      // [...] The nc-value is the hexadecimal count of the number of requests (including the
      // current request) that the client has sent with the nonce value in this request.
      authorizationRequestHeader.setNonce(nonce);
      authorizationRequestHeader.resetNonceCount();
    }
  }
}
