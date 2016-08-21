package org.barebonesdigest;

import java.net.PasswordAuthentication;

/**
 * Describes an HTTP Digest Authentication session.
 * <p>
 * An authentication session starts when the server challenges the client for authentication. During
 * the session, the client can authenticate using the values received in the challenge that started
 * the session. Authentication sessions are explained in detail in
 * <a href="https://tools.ietf.org/html/rfc2617#section-3.3">Section 3.3 of RFC 2617</a>.
 *
 * @see <a href="https://tools.ietf.org/html/rfc2617#section-3.3">RFC 2617, "HTTP Digest Access
 * Authentication", Section 3.3, "Digest Operation"</a>
 */
public class AuthenticationSession {
  private final String nonce;
  private int nonceCount;
  private final String opaqueQuoted;
  private final PasswordAuthentication authentication;
  private final String realm;
  private final String algorithm;

  public AuthenticationSession(PasswordAuthentication authentication,
      String nonce,
      String opaqueQuoted,
      String realm,
      String algorithm) {
    this.nonce = nonce;
    this.opaqueQuoted = opaqueQuoted;
    this.authentication = authentication;
    this.realm = realm;
    this.algorithm = algorithm;
  }

  public String getNonce() {
    return nonce;
  }

  public int getNonceCount() {
    return nonceCount;
  }

  public void incrementNonceCount() {
    nonceCount++;
  }

  public String getOpaqueQuoted() {
    return opaqueQuoted;
  }

  public PasswordAuthentication getAuthentication() {
    return authentication;
  }

  public String getRealm() {
    return realm;
  }

  public String getAlgorithm() {
    return algorithm;
  }
}
