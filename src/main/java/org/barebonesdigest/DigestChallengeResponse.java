package org.barebonesdigest;

import android.annotation.SuppressLint;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Describes the contents of an {@code Authorization} HTTP request header. Once the client has
 * received a HTTP Digest challenge from the server this header should be included in all subsequent
 * requests to authorize the client.
 * <p>
 * Instances of this class is normally created as a response to an incoming challenge using
 * {@link #responseTo(DigestChallenge)}. To generate the {@code Authorization} header, som
 * additional values must be set:
 * <ul>
 * <li>The {@link #username(String) username} and {@link #password(String) password} for
 * authentication.</li>
 * <li>The {@link #digestUri(String) digestUri} used in the HTTP request.</li>
 * <li>The {@link #requestMethod(String) request method} of the request, such as "GET" or "POST".
 * </li>
 * </ul>
 * <p>
 *
 * Here is an example of how to create a response:
 * <pre>
 * {@code
 * DigestChallengeResponse response = DigestChallengeResponse.responseTo(challenge)
 *                                                           .username("user")
 *                                                           .password("passwd")
 *                                                           .digestUri("/example")
 *                                                           .requestMethod("GET");
 * }
 * </pre>
 *
 * <h2>Challenge response reuse</h2>
 *
 * A challenge response from an earlier challenge can be reused in subsequent requests. If the
 * server accepts the reused challenge this will cut down on unnecessary traffic.
 * <p>
 * Each time the challenge response is reused the nonce count must be increased by one, see
 * {@link #incrementNonceCount()}.
 *
 * <h2>Limitations</h2>
 *
 * <ul>
 * <li>Only the {@code MD5} {@code algorithm} is supported, not {@code MD5-sess}.</li>
 * <li>{@code qop} is always set to {@code auth}. The value from the challenge is not used.
 * {@code auth-int} {@code qop} is not supported.</li>
 * </ul>
 *
 * @see <a href="https://tools.ietf.org/html/rfc2617#section-3.2.2">RFC 2617, "HTTP Digest Access
 * Authentication", Section 3.2.2, "The Authorization Request Header"</a>
 */
public class DigestChallengeResponse {
  /**
   * The name of the HTTP request header ({@value #HTTP_HEADER_AUTHORIZATION}).
   */
  public static final String HTTP_HEADER_AUTHORIZATION = "Authorization";

  private static final int CLIENT_NONCE_BYTE_COUNT = 8;
  @SuppressLint("TrulyRandom")
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final byte[] clientNonceByteBuffer = new byte[CLIENT_NONCE_BYTE_COUNT];

  private final MessageDigest md5;

  private String algorithm;
  private String username;
  private String password;
  private String clientNonce;
  private String quotedNonce;
  private int nonceCount;
  private String quotedOpaque;
  private String digestUri;
  private String quotedRealm;
  private String requestMethod;

  /**
   * Creates an empty challenge response.
   */
  public DigestChallengeResponse() {
    try {
      this.md5 = MessageDigest.getInstance("MD5");
    } catch (NoSuchAlgorithmException e) {
      // TODO find out if this can happen
      throw new RuntimeException(e);
    }

    this.nonceCount(1);
    this.clientNonce(generateRandomNonce());
  }

  /**
   * Creates a digest challenge response, setting the values of the {@code realm}, {@code nonce},
   * {@code opaque}, and {@code algorithm} directives based on a challenge.
   *
   * @param challenge the challenge
   * @return a response to the challenge.
   */
  public static DigestChallengeResponse responseTo(DigestChallenge challenge) {
    return new DigestChallengeResponse().challenge(challenge);
  }

  /**
   * Sets the {@code algorithm} directive, which must be the same as the {@code algorithm} directive
   * of the challenge. The only value currently supported is "MD5".
   *
   * @param algorithm the value of the {@code algorithm} directive
   * @return this object so that setters can be chained
   * @see #getAlgorithm()
   * @see <a href="https://tools.ietf.org/html/rfc2617#section-3.2.2">Section 3.2.2 of RFC 2617</a>
   */
  public DigestChallengeResponse algorithm(String algorithm) {
    if (algorithm != null && !"MD5".equals(algorithm)) {
      throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
    }

    this.algorithm = algorithm;
    return this;
  }

  /**
   * Returns the value of the {@code algorithm} directive.
   *
   * @return the value of the {@code algorithm} directive
   * @see #algorithm(String)
   */
  public String getAlgorithm() {
    return algorithm;
  }

  /**
   * Sets the username to use for authentication.
   *
   * @param username the username
   * @return this object so that setters can be chained
   * @see #getUsername()
   * @see <a href="https://tools.ietf.org/html/rfc2617#section-3.2.2">Section 3.2.2 of RFC 2617</a>
   */
  public DigestChallengeResponse username(String username) {
    this.username = username;
    return this;
  }

  /**
   * Returns the username to use for authentication.
   *
   * @return the username
   * @see #username(String)
   */
  public String getUsername() {
    return username;
  }

  /**
   * Sets the password to use for authentication.
   *
   * @param password the password
   * @return this object so that setters can be chained
   * @see #getPassword()
   */
  public DigestChallengeResponse password(String password) {
    this.password = password;
    return this;
  }

  /**
   * Returns the password to use for authentication.
   *
   * @return the password
   * @see #password(String)
   */
  public String getPassword() {
    return password;
  }

  /**
   * Sets the {@code cnonce} directive, which is a random string generated by the client that will
   * be included in the challenge response hash.
   * <p>
   * There is normally no need to manually set the client nonce since it will have a default value
   * of a randomly generated string.
   *
   * @param clientNonce The unquoted value of the {@code cnonce} directive.
   * @return this object so that setters can be chained
   * @see #getClientNonce()
   * @see <a href="https://tools.ietf.org/html/rfc2617#section-3.2.2">Section 3.2.2 of RFC 2617</a>
   */
  public DigestChallengeResponse clientNonce(String clientNonce) {
    this.clientNonce = clientNonce;
    return this;
  }

  /**
   * Returns the value of the {@code cnonce} directive.
   * <p>
   * Unless overridden by calling {@link #clientNonce(String)}, the {@code cnonce} directive is
   * set to a randomly generated string.
   *
   * @return the {@code cnonce} directive
   * @see #clientNonce(String)
   */
  public String getClientNonce() {
    return clientNonce;
  }

  /**
   * Sets the {@code nonce} directive, which must be the same as the nonce directive of the
   * challenge.
   * <p>
   * Setting the {@code nonce} directive resets the nonce count to one.
   *
   * @param quotedNonce the quoted value of the {@code nonce} directive
   * @return this object so that setters can be chained
   * @see #getQuotedNonce()
   * @see #nonce(String)
   * @see #getNonce()
   * @see <a href="https://tools.ietf.org/html/rfc2617#section-3.2.2">Section 3.2.2 of RFC 2617</a>
   */
  public DigestChallengeResponse quotedNonce(String quotedNonce) {
    this.quotedNonce = quotedNonce;
    resetNonceCount();
    return this;
  }

  /**
   * Returns the quoted value of the {@code nonce} directive.
   *
   * @return the quoted value of the {@code nonce} directive
   * @see #quotedNonce(String)
   * @see #nonce(String)
   * @see #getNonce()
   */
  public String getQuotedNonce() {
    return quotedNonce;
  }

  /**
   * Sets the {@code nonce} directive, which must be the same as the {@code nonce} directive of the
   * challenge.
   * <p>
   * Setting the nonce directive resets the nonce count to one.
   *
   * @param unquotedNonce the unquoted value of the {@code nonce} directive
   * @return this object so that setters can be chained
   * @see #getNonce()
   * @see #quotedNonce(String)
   * @see #getQuotedNonce()
   * @see <a href="https://tools.ietf.org/html/rfc2617#section-3.2.2">Section 3.2.2 of RFC 2617</a>
   */
  public DigestChallengeResponse nonce(String unquotedNonce) {
    if (unquotedNonce == null) {
      return quotedNonce(null);
    }
    return quotedNonce(Rfc2616AbnfParser.quote(unquotedNonce));
  }

  /**
   * Returns the unquoted value of the {@code nonce} directive
   *
   * @return the unquoted value of the {@code nonce} directive
   * @see #nonce(String)
   * @see #quotedNonce(String)
   * @see #getQuotedNonce()
   */
  public String getNonce() {
    // TODO: Cache since value is used each time a header is written
    if (quotedNonce == null) {
      return null;
    }

    return Rfc2616AbnfParser.unquote(quotedNonce);
  }

  /**
   * Sets the integer representation of the {@code nonce-count} directive, which indicates how many
   * times this a challenge response with this nonce has been used.
   * <p>
   * This is useful when using a challenge response from a previous challenge when sending a
   * request. For each time a challenge response is used, the nonce count should be increased by
   * one.
   *
   * @param nonceCount integer representation of the {@code nonce-count} directive
   * @return this object so that setters can be chained
   * @see #getNonceCount()
   * @see #resetNonceCount()
   * @see #incrementNonceCount()
   * @see <a href="https://tools.ietf.org/html/rfc2617#section-3.2.2">Section 3.2.2 of RFC 2617</a>
   */
  public DigestChallengeResponse nonceCount(int nonceCount) {
    this.nonceCount = nonceCount;
    return this;
  }

  /**
   * Increments the value of the {@code nonce-count} by one.
   *
   * @return this object so that setters can be chained
   * @see #nonceCount(int)
   * @see #getNonceCount()
   * @see #resetNonceCount()
   */
  public DigestChallengeResponse incrementNonceCount() {
    nonceCount(nonceCount + 1);
    return this;
  }

  /**
   * Sets the value of the {@code nonce-count} to one.
   *
   * @return this object so that setters can be chained
   * @see #nonceCount(int)
   * @see #getNonceCount()
   * @see #incrementNonceCount()
   */
  public DigestChallengeResponse resetNonceCount() {
    nonceCount(1);
    return this;
  }

  /**
   * Returns the integer representation of the {@code nonce-count} directive.
   *
   * @return the integer representation of the {@code nonce-count} directive
   * @see #nonceCount(int)
   * @see #resetNonceCount()
   * @see #incrementNonceCount()
   */
  public int getNonceCount() {
    return nonceCount;
  }


  /**
   * Sets the {@code opaque} directive, which must be the same as the {@code opaque} directive of
   * the challenge.
   *
   * @param quotedOpaque the quoted value of the {@code opaque} directive, or {@code null} if no
   *                     opaque directive should be included in the challenge response
   * @return this object so that setters can be chained
   * @see #getQuotedOpaque()
   * @see #opaque(String)
   * @see #getOpaque()
   * @see <a href="https://tools.ietf.org/html/rfc2617#section-3.2.2">Section 3.2.2 of RFC 2617</a>
   */
  public DigestChallengeResponse quotedOpaque(String quotedOpaque) {
    this.quotedOpaque = quotedOpaque;
    return this;
  }

  /**
   * Returns the the quoted value of the {@code opaque} directive, or {@code null}.
   *
   * @return the the quoted value of the {@code opaque} directive, or {@code null} if the {@code
   * opaque} is not set
   * @see #quotedOpaque(String)
   * @see #opaque(String)
   * @see #getOpaque()
   */
  public String getQuotedOpaque() {
    return quotedOpaque;
  }

  /**
   * Sets the {@code opaque} directive, which must be the same as the {@code opaque} directive of
   * the challenge.
   * <p>
   * Note: Since the value of the {@code opaque} directive is always received from a challenge
   * quoted it is normally better to use the {@link #quotedOpaque(String)} method to avoid
   * unnecessary quoting/unquoting.
   *
   * @param unquotedOpaque the unquoted value of the {@code opaque} directive, or {@code null} if no
   *                       {@code opaque} directive should be included in the challenge response
   * @return this object so that setters can be chained
   * @see #getOpaque()
   * @see #quotedOpaque(String)
   * @see #getQuotedOpaque()
   * @see <a href="https://tools.ietf.org/html/rfc2617#section-3.2.2">Section 3.2.2 of RFC 2617</a>
   */
  public DigestChallengeResponse opaque(String unquotedOpaque) {
    if (unquotedOpaque == null) {
      return quotedOpaque(null);
    }
    return quotedOpaque(Rfc2616AbnfParser.quote(unquotedOpaque));
  }

  /**
   * Returns the the unquoted value of the {@code opaque} directive, or {@code null}.
   *
   * @return the the unquoted value of the {@code opaque} directive, or {@code null} if the {@code
   * opaque} is not set
   * @see #opaque(String)
   * @see #quotedOpaque(String)
   * @see #getQuotedOpaque()
   */
  public String getOpaque() {
    if (quotedOpaque == null) {
      return null;
    }
    return Rfc2616AbnfParser.unquote(quotedOpaque);
  }

  /**
   * Sets the {@code digest-uri} directive, which must be exactly the same as the
   * {@code Request-URI} of the {@code Request-Line} of the HTTP request.
   * <p>
   * The digest URI is explained in
   * <a href="https://tools.ietf.org/html/rfc2617#section-3.2.2">Section 3.2.2 of RFC 2617</a>,
   * and refers to the explanation of Request-URI found in
   * <a href="https://tools.ietf.org/html/rfc2616#section-5.1.2">Section 5.1.2 of RFC 2616</a>.
   * <p>
   * Examples: If the {@code Request-Line} is
   * <pre>
   * GET http://www.w3.org/pub/WWW/TheProject.html HTTP/1.1
   * </pre>
   * the {@code Request-URI} (and {@code digest-uri}) is "{@code
   * http://www.w3.org/pub/WWW/TheProject.html}". If {@code Request-Line} is
   * <pre>
   * GET /pub/WWW/TheProject.html HTTP/1.1
   * </pre>
   * the {@code Request-URI} is "{@code /pub/WWW/TheProject.html}".
   * <p>
   * This can be problematic since depending on the HTTP stack being used the {@code Request-Line}
   * and {@code Request-URI} values may not be accessible. If in doubt, a sensible guess is to set
   * the {@code digest-uri} to the path part of the URL being requested, for instance using
   * <a href="https://developer.android.com/reference/java/net/URL.html#getPath()">
   * <code>getPath()</code> in the <code>URL</code> class</a>.
   *
   * @param digestUri the value of the digest-uri directive
   * @return this object so that setters can be chained
   * @see #getDigestUri()
   */
  public DigestChallengeResponse digestUri(String digestUri) {
    this.digestUri = digestUri;
    return this;
  }

  /**
   * Returns the value of the {@code digest-uri} directive.
   *
   * @return the value of the {@code digest-uri} directive
   * @see #digestUri(String)
   */
  public String getDigestUri() {
    return digestUri;
  }

  /**
   * Sets the {@code realm} directive, which must be the same as the {@code realm} directive of
   * the challenge.
   *
   * @param quotedRealm the quoted value of the {@code realm} directive
   * @return this object so that setters can be chained
   * @see #getQuotedRealm()
   * @see #realm(String)
   * @see #getRealm()
   * @see <a href="https://tools.ietf.org/html/rfc2617#section-3.2.1">Section 3.2.1 of RFC 2617</a>
   * @see <a href="https://tools.ietf.org/html/rfc2617#section-3.2.2">Section 3.2.2 of RFC 2617</a>
   */
  public DigestChallengeResponse quotedRealm(String quotedRealm) {
    this.quotedRealm = quotedRealm;
    return this;
  }

  /**
   * Returns the quoted value of the {@code realm} directive.
   *
   * @return the quoted value of the {@code realm} directive
   * @see #quotedRealm(String)
   * @see #realm(String)
   * @see #getRealm()
   */
  public String getQuotedRealm() {
    return quotedRealm;
  }

  /**
   * Sets the {@code realm} directive, which must be the same as the {@code realm} directive of
   * the challenge.
   *
   * @param unquotedRealm the unquoted value of the {@code realm} directive
   * @return this object so that setters can be chained
   * @see #getRealm()
   * @see #quotedRealm(String)
   * @see #getQuotedRealm()
   * @see <a href="https://tools.ietf.org/html/rfc2617#section-3.2.1">Section 3.2.1 of RFC 2617</a>
   * @see <a href="https://tools.ietf.org/html/rfc2617#section-3.2.2">Section 3.2.2 of RFC 2617</a>
   */
  public DigestChallengeResponse realm(String unquotedRealm) {
    if (unquotedRealm == null) {
      return quotedRealm(null);
    }
    return quotedRealm(Rfc2616AbnfParser.quote(unquotedRealm));
  }

  /**
   * Returns the unquoted value of the {@code realm} directive.
   *
   * @return the unquoted value of the {@code realm} directive
   * @see #realm(String)
   * @see #quotedRealm(String)
   * @see #getQuotedRealm()
   */
  public String getRealm() {
    // TODO: Cache since value is used each time a header is written
    if (quotedRealm == null) {
      return null;
    }
    return Rfc2616AbnfParser.unquote(quotedRealm);
  }

  /**
   * Sets the HTTP method of the request (GET, POST, etc).
   *
   * @param requestMethod the request method
   * @return this object so that setters can be chained
   * @see #getRequestMethod()
   * @see <a href="https://tools.ietf.org/html/rfc2616#section-5.1.1">Section 5.1.1 of RFC 2616</a>
   */
  public DigestChallengeResponse requestMethod(String requestMethod) {
    this.requestMethod = requestMethod;
    return this;
  }

  /**
   * Returns the HTTP method of the request.
   *
   * @return the HTTP method
   * @see #requestMethod(String)
   */
  public String getRequestMethod() {
    return requestMethod;
  }

  /**
   * Sets the values of the {@code realm}, {@code nonce}, {@code opaque}, and {@code algorithm}
   * directives based on a challenge.
   *
   * @param challenge the challenge
   * @return this object so that setters can be chained
   */
  public DigestChallengeResponse challenge(DigestChallenge challenge) {
    return quotedNonce(challenge.getQuotedNonce()).quotedOpaque(challenge.getQuotedOpaque())
        .quotedRealm(challenge.getQuotedRealm())
        .algorithm(challenge.getAlgorithm());
  }

  /**
   * Returns the {@code credentials}, that is, the string to set in the {@code Authorization}
   * HTTP request header.
   * <p>
   * Before calling this method, the following values and directives must be set:
   * <ul>
   * <li>{@link #username(String) username}.</li>
   * <li>{@link #password(String) password}.</li>
   * <li>{@link #quotedRealm(String) realm}.</li>
   * <li>{@link #quotedNonce(String) nonce}.</li>
   * <li>{@link #digestUri(String) digest-uri}.</li>
   * <li>{@link #requestMethod(String) Method}.</li>
   * </ul>
   *
   * @return the string to set in the {@code Authorization} HTTP request header
   * @throws IllegalStateException if any of the mandatory directives and values listed above has
   *                               not been set
   * @see <a href="https://tools.ietf.org/html/rfc2617#section-3.2.2">Section 3.2.2 of RFC 2617</a>
   */
  public String getHeaderValue() {
    // TODO Get qop from challenge
    // TODO Also support auth-int, no qop
    String qop = "auth";

    if (username == null) {
      throw new IllegalStateException("Mandatory username not set");
    }
    if (password == null) {
      throw new IllegalStateException("Mandatory password not set");
    }
    if (quotedRealm == null) {
      throw new IllegalStateException("Mandatory realm not set");
    }
    if (quotedNonce == null) {
      throw new IllegalStateException("Mandatory nonce not set");
    }
    if (digestUri == null) {
      throw new IllegalStateException("Mandatory digest-uri not set");
    }
    if (requestMethod == null) {
      throw new IllegalStateException("Mandatory Method not set");
    }
    if (clientNonce == null && qop != null) {
      throw new IllegalStateException("Client nonce must be set when qop is set");
    }

    String response = calculateResponse();

    StringBuilder result = new StringBuilder();
    result.append("Digest ");

    // Username is defined in Section 3.2.2 of RFC 2617
    // username         = "username" "=" username-value
    // username-value   = quoted-string
    result.append("username=");
    result.append(Rfc2616AbnfParser.quote(username));
    result.append(",");

    // Realm is defined in RFC 2617, Section 1.2
    // realm       = "realm" "=" realm-value
    // realm-value = quoted-string
    result.append("realm=");
    result.append(quotedRealm);
    result.append(",");

    // nonce             = "nonce" "=" nonce-value
    // nonce-value       = quoted-string
    result.append("nonce=");
    result.append(quotedNonce);
    result.append(",");

    // digest-uri       = "uri" "=" digest-uri-value
    // digest-uri-value = request-uri   ; As specified by HTTP/1.1
    result.append("uri=");
    result.append(Rfc2616AbnfParser.quote(digestUri));
    result.append(",");

    // Response is defined in RFC 2617, Section 3.2.2 and 3.2.2.1
    // response         = "response" "=" request-digest
    result.append("response=");
    result.append(response);
    result.append(",");

    // cnonce is defined in RFC 2617, Section 3.2.2
    // cnonce           = "cnonce" "=" cnonce-value
    // cnonce-value     = nonce-value
    // Must be present if qop is specified, must not if qop is unspecified
    if (qop != null) {
      result.append("cnonce=");
      result.append(Rfc2616AbnfParser.quote(getClientNonce()));
      result.append(",");
    }

    // Opaque and algorithm are explained in Section 3.2.2 of RFC 2617:
    // "The values of the opaque and algorithm fields must be those supplied
    // in the WWW-Authenticate response header for the entity being
    // requested."

    if (quotedOpaque != null) {
      result.append("opaque=");
      result.append(quotedOpaque);
      result.append(",");
    }

    if (algorithm != null) {
      result.append("algorithm=");
      result.append(algorithm);
      result.append(",");
    }

    if (qop != null) {
      result.append("qop=");
      result.append(qop);
      result.append(",");
    }

    // Nonce count is defined in RFC 2617, Section 3.2.2
    // nonce-count      = "nc" "=" nc-value
    // nc-value         = 8LHEX (lower case hex)
    // Must be present if qop is specified, must not if qop is unspecified
    if (qop != null) {
      result.append("nc=");
      result.append(String.format("%08x", nonceCount));
    }

    return result.toString();
  }

  private String calculateResponse() {
    // TODO: Below calculation is for the case where qop is present, if not qop is calculated
    // differently
    String a1 = calculateA1();
    String a2 = calculateA2();

    String secret = calculateMd5(a1);
    String data = joinWithColon(getNonce(),
        String.format("%08x", nonceCount),
        getClientNonce(),
        "auth",
        calculateMd5(a2));

    return "\"" + calculateMd5(secret + ":" + data) + "\"";
  }

  private String calculateA1() {
    // TODO: Below calculation is for if algorithm is MD5 or unspecified
    // TODO: Support MD5-sess algorithm
    return joinWithColon(username, getRealm(), password);
  }

  private String calculateA2() {
    // TODO: Below calculation if if qop is auth or unspecified
    // TODO: Support auth-int qop
    return joinWithColon(requestMethod, digestUri);
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
    for (byte b : bytes) {
      result.append(Integer.toHexString((b & 0xf0) >> 4));
      result.append(Integer.toHexString((b & 0x0f)));
    }
    return result.toString();
  }

  private static synchronized String generateRandomNonce() {
    RANDOM.nextBytes(clientNonceByteBuffer);
    return encodeHexString(clientNonceByteBuffer);
  }
}
