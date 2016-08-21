package org.barebonesdigest;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.PasswordAuthentication;
import java.util.List;
import java.util.Map;

/**
 * Describes an HTTP Digest Authentication session.
 * <p>
 * An authentication session starts when the server challenges the client for authentication. During
 * the session, the client can authenticate using the values received in the challenge that started
 * the session. Authentication sessions are explained in detail in
 * <a href="https://tools.ietf.org/html/rfc2617#section-3.3">Section 3.3 of RFC 2617</a>.
 * <p>
 * TODO: add some examples here since this is the main entry point of the API
 *
 * @see <a href="https://tools.ietf.org/html/rfc2617#section-3.3">RFC 2617, "HTTP Digest Access
 * Authentication", Section 3.3, "Digest Operation"</a>
 */
public class HttpDigestState {
  private static final String HTTP_DIGEST_CHALLENGE_PREFIX = "Digest ";

  private AuthenticationSession authenticationSession = null;
  private PasswordAuthentication authentication;
  // Reuse to minimize object creation
  private AuthorizationRequestHeader authorizationRequestHeader = new AuthorizationRequestHeader();
  private boolean resendNeeded = false;

  public HttpDigestState(PasswordAuthentication authentication) {
    this.authentication = authentication;
  }

  public void updateWithResponse(int statusCode, Map<String, List<String>> responseHeaders) {
    resendNeeded = false;

    if (responseContainsChallenge(statusCode, responseHeaders)) {
      updateWithChallenge(responseHeaders);
    }

    // TODO: Support Authentication-Info header with changing nonce values
  }

  public void updateWithResponse(HttpURLConnection connection) throws IOException {
    updateWithResponse(connection.getResponseCode(), connection.getHeaderFields());
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

  public void updateWithChallenge(Map<String, List<String>> responseHeaders) {
    List<String> wwwAuthenticateResponseHeaders =
        responseHeaders.get(WwwAuthenticateHeader.HEADER_NAME);
    if (wwwAuthenticateResponseHeaders == null) {
      return;
    }

    for (String wwwAuthenticateResponseHeader : wwwAuthenticateResponseHeaders) {
      updateWithChallenge(wwwAuthenticateResponseHeader);
    }
  }

  public void updateWithChallenge(String wwwAuthenticateResponseHeader) {
    WwwAuthenticateHeader header = WwwAuthenticateHeader.parse(wwwAuthenticateResponseHeader);

    if (header != null) {
      authenticationSession = new AuthenticationSession(authentication,
          header.getNonce(),
          header.getOpaqueQuoted(),
          header.getRealm(),
          header.getAlgorithm());

      resendNeeded = true;
    }
  }

  public String getAuthorizationHeaderForRequest(String requestMethod, String path) {
    if (authenticationSession == null) {
      return null;
    }

    authorizationRequestHeader.setAuthentication(authenticationSession.getAuthentication());
    authorizationRequestHeader.setNonce(authenticationSession.getNonce());
    authorizationRequestHeader.setNonceCount(authenticationSession.getNonceCount());
    authorizationRequestHeader.setOpaqueQuoted(authenticationSession.getOpaqueQuoted());
    authorizationRequestHeader.setRealm(authenticationSession.getRealm());
    authorizationRequestHeader.setAlgorithm(authenticationSession.getAlgorithm());
    // TODO: Generate random client nonce
    authorizationRequestHeader.setClientNonce("0a4f113b");
    authorizationRequestHeader.setPath(path);
    authorizationRequestHeader.setRequestMethod(requestMethod);

    String headerValue = authorizationRequestHeader.getHeaderValue();

    authenticationSession.incrementNonceCount();

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
}
