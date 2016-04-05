package com.albroco.androidhttpdigest;

import java.net.PasswordAuthentication;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Describes an <code>Authorization</code> HTTP request header. Once the client has received a
 * HTTP Digest challenge from the server this header should be included in all subsequent requests
 * to authorize the client.
 *
 * @see <a href="https://tools.ietf.org/html/rfc2617#section-3.2.2">RFC 2617, "HTTP Digest Access
 * Authentication", Section 3.2.2, "The Authorization Request Header"</a>
 */
public class AuthorizationRequestHeader {
  /**
   * The name of the HTTP request header ({@value #HEADER_NAME}).
   */
  public static final String HEADER_NAME = "Authorization";

  private final MessageDigest md5;

  private String algorithm;
  private PasswordAuthentication authentication;
  private String clientNonce;
  private String nonce;
  private int nonceCount;
  private String opaqueQuoted;
  private String path;
  private String realm;
  private String requestMethod;

  public AuthorizationRequestHeader() {
    try {
      this.md5 = MessageDigest.getInstance("MD5");
    } catch (NoSuchAlgorithmException e) {
      // TODO find out if this can happen
      throw new RuntimeException(e);
    }
  }

  public String getAlgorithm() {
    return algorithm;
  }

  public void setAlgorithm(String algorithm) {
    this.algorithm = algorithm;
  }

  public PasswordAuthentication getAuthentication() {
    return authentication;
  }

  public void setAuthentication(PasswordAuthentication authentication) {
    this.authentication = authentication;
  }

  public String getClientNonce() {
    return clientNonce;
  }

  public void setClientNonce(String clientNonce) {
    this.clientNonce = clientNonce;
  }

  public String getNonce() {
    return nonce;
  }

  public void setNonce(String nonce) {
    this.nonce = nonce;
  }

  public int getNonceCount() {
    return nonceCount;
  }

  public void setNonceCount(int nonceCount) {
    this.nonceCount = nonceCount;
  }

  public void resetNonceCount() {
    setNonceCount(1);
  }

  public void incrementNonceCount() {
    setNonceCount(nonceCount + 1);
  }

  public String getOpaqueQuoted() {
    return opaqueQuoted;
  }

  public void setOpaqueQuoted(String opaqueQuoted) {
    this.opaqueQuoted = opaqueQuoted;
  }

  public String getPath() {
    return path;
  }

  public void setPath(String path) {
    this.path = path;
  }

  public String getRealm() {
    return realm;
  }

  public void setRealm(String realm) {
    this.realm = realm;
  }

  public String getRequestMethod() {
    return requestMethod;
  }

  public void setRequestMethod(String requestMethod) {
    this.requestMethod = requestMethod;
  }

  public String getHeaderValue() {
    // TODO: verify that all values are set

    String response = calculateResponse();

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

    return result.toString();
  }

  private String calculateResponse() {
    // TODO: Below calculation is for the case where qop is present, if not qop is calculated
    // differently
    String a1 = calculateA1();
    String a2 = calculateA2();

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

  private String calculateA2() {
    // TODO: Below calculation if if qop is auth or unspecified
    // TODO: Support auth-int qop
    return joinWithColon(requestMethod, path);
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

  private String quoteString(String str) {
    // TODO: implement properly
    return "\"" + str + "\"";
  }
}
