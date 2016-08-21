package org.barebonesdigest;

public class WwwAuthenticateHeader {
  public static final String HEADER_NAME = "WWW-Authenticate";

  private static final String HTTP_DIGEST_CHALLENGE_PREFIX = "digest";

  private final String realm;
  private final String nonce;
  private final String opaqueQuoted;
  private final String algorithm;
  private final boolean stale;

  private WwwAuthenticateHeader(String realm,
      String nonce,
      String opaqueQuoted,
      String algorithm,
      boolean stale) {
    this.realm = realm;
    this.nonce = nonce;
    this.opaqueQuoted = opaqueQuoted;
    this.algorithm = algorithm;
    this.stale = stale;
  }

  public static WwwAuthenticateHeader parse(String authenticateHeader) {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser(authenticateHeader);
    try {
      parser.consumeLiteral(HTTP_DIGEST_CHALLENGE_PREFIX);
      parser.consumeWhitespace();

      String realm = null;
      String nonce = null;
      String opaqueQuoted = null;
      String algorithm = null;
      boolean stale = false;

      while (parser.containsMoreData()) {
        String token = parser.consumeToken().get();
        parser.consumeWhitespace().consumeLiteral("=").consumeWhitespace();

        if (token.equals("realm")) {
          // Realm definition from RFC 2617, Section 1.2:
          // realm       = "realm" "=" realm-value
          // realm-value = quoted-string
          realm = parser.unquote(parser.consumeQuotedString().get());
        } else if (token.equals("nonce")) {
          // Nonce definition from RFC 2617, Section 3.2.1:
          // nonce             = "nonce" "=" nonce-value
          // nonce-value       = quoted-string
          nonce = parser.unquote(parser.consumeQuotedString().get());
        } else if (token.equals("opaque")) {
          // Opaque definition from RFC 2617, Section 3.2.1:
          // opaque            = "opaque" "=" quoted-string
          opaqueQuoted = parser.consumeQuotedString().get();
        } else if (token.equals("algorithm")) {
          // Algorithm definition from RFC 2617, Section 3.2.1:
          // algorithm         = "algorithm" "=" ( "MD5" | "MD5-sess" |
          //                     token )
          // TODO: deal with malformed/unsupported algorithm
          algorithm = parser.consumeToken().get();
        } else if (token.equals("qop")) {
          // Qop definition from RFC 2617, Section 3.2.1:
          // qop-options       = "qop" "=" <"> 1#qop-value <">
          // qop-value         = "auth" | "auth-int" | token
          // TODO: deal with malformed/unsupported qop
          // TODO: Not really a quoted string
          // TODO store qop
          // TODO test site returns non-quoted qop, consider allowing it
          parser.consumeQuotedString();
        } else if (token.equals("domain")) {
          // Domain definition from RFC 2617, Section 3.2.1:
          // domain            = "domain" "=" <"> URI ( 1*SP URI ) <">
          // TODO store domain
          parser.consumeQuotedString().get();
        } else if (token.equals("stale")) {
          // Stale definition from RFC 2617, Section 3.2.1:
          // stale             = "stale" "=" ( "true" | "false" )
          String staleToken = parser.consumeToken().get();
          // TRUE (case-insensitive) means stale, any other value (or stale
          // directive not present) means false. From RFC 2617, Section 3.2.1:
          // [...] If stale is TRUE (case-insensitive), the client may wish to simply retry the
          // request with a new encrypted response [...] If stale is FALSE, or anything other
          // than TRUE, or the stale directive is not present, the username and/or password are
          // invalid [...]
          stale = staleToken.equalsIgnoreCase("true");
        } else {
          // Any other directive can be included (and MUST be ignored).
          // Definition of auth-param from RFC 2617, Section 1.2;
          // auth-param     = token "=" ( token | quoted-string )
          // TODO parse auth-params
          // TODO store (or ignore) auth-params
          throw new Rfc2616AbnfParser.ParseException("Unrecognized auth-param: " + token, parser);
        }

        parser.consumeWhitespace();
        if (parser.containsMoreData()) {
          parser.consumeLiteral(",").consumeWhitespace();
        }
      }

      if (realm == null) {
        throw new Rfc2616AbnfParser.ParseException("Missing directive: realm");
      }
      if (nonce == null) {
        throw new Rfc2616AbnfParser.ParseException("Missing directive: nonce");
      }

      return new WwwAuthenticateHeader(realm, nonce, opaqueQuoted, algorithm, stale);
    } catch (Rfc2616AbnfParser.ParseException e) {
      return null;
    }
  }

  /**
   * Returns the value of the mandatory <em>realm</em> directive.
   *
   * The realm directive is described in Section 3.2.1 of
   * <a href="https://tools.ietf.org/html/rfc2617">RFC 2617</a>:
   *
   * <dl>
   * <dt>realm</dt>
   * <dd>A string to be displayed to users so they know which
   * username and password to use.  This string should contain
   * at least the name of the host performing the
   * authentication and might additionally indicate the
   * collection of users who might have access. An example
   * might be "registered_users@gotham.news.com".</dd>
   * </dl>
   *
   * @return The value of the realm directive
   */
  public String getRealm() {
    return realm;
  }

  /**
   * Returns the value of the <em>algorithm</em> directive, if present.
   *
   * The algorithm directive is described in Section 3.2.1 of
   * <a href="https://tools.ietf.org/html/rfc2617">RFC 2617</a>:
   *
   * <dl>
   * <dt>algorithm</dt>
   *
   * <dd>A string indicating a pair of algorithms used to produce
   * the digest and a checksum. If this is not present it is
   * assumed to be "MD5".  If the algorithm is not understood,
   * the challenge should be ignored (and a different one
   * used, if there is more than one). [&hellip;]</dd>
   * </dl>
   *
   * @return The value of the algorithm directive or {@code null} if the
   * algorithm directive is not present in the header
   */
  public String getAlgorithm() {
    return algorithm;
  }

  /**
   * Returns the value of the mandatory <em>nonce</em> directive.
   *
   * The nonce directive is described in Section 3.2.1 of
   * <a href="https://tools.ietf.org/html/rfc2617">RFC 2617</a>:
   *
   * <dl>
   * <dt>nonce</dt>
   *
   * <dd>A server-specified data string which should be uniquely generated
   * each time a 401 response is made. It is recommended that this
   * string be base64 or hexadecimal data. Specifically, since the
   * string is passed in the header lines as a quoted string, the
   * double-quote character is not allowed.
   * <p>
   * The contents of the nonce are implementation dependent. The quality
   * of the implementation depends on a good choice. [&hellip;]
   * <p>
   * The nonce is opaque to the client.</dd>
   * </dl>
   *
   * @return the nonce as a string
   */
  public String getNonce() {
    return nonce;
  }

  /**
   * Returns the {@code quoted-string} version of the <em>opaque</em>
   * directive, if present in the header.
   *
   * The nonce directive is described in Section 3.2.1 of
   * <a href="https://tools.ietf.org/html/rfc2617">RFC 2617</a>:
   *
   * <dl>
   * <dt>opaque</dt>
   * <dd>A string of data, specified by the server, which should
   * be returned by the client unchanged in the Authorization
   * header of subsequent requests with URIs in the same
   * protection space. It is recommended that this string be
   * base64 or hexadecimal data.</dd>
   * </dl>
   *
   * @return the value of the opaque directive or {@code null} if the
   * opaque directive is not present in the header
   */
  public String getOpaqueQuoted() {
    return opaqueQuoted;
  }

  /**
   * Returns a boolean representation of the <em>stale</em> directive.
   *
   * This method returns {@code true} if the header has a stale
   * directive that is equal to "true" (case-insensitive). If there is
   * no stale directive or it has any other value, {@code false} is
   * returned.
   *
   * The stale directive is described in Section 3.2.1 of
   * <a href="https://tools.ietf.org/html/rfc2617">RFC 2617</a>:
   *
   * <dl>
   * <dt>stale</dt>
   * <dd>A flag, indicating that the previous request from the
   * client was rejected because the nonce value was stale. If
   * stale is TRUE (case-insensitive), the client may wish to
   * simply retry the request with a new encrypted response,
   * without reprompting the user for a new username and
   * password. The server should only set stale to TRUE if it
   * receives a request for which the nonce is invalid but
   * with a valid digest for that nonce (indicating that the
   * client knows the correct username/password). If stale is
   * FALSE, or anything other than TRUE, or the stale
   * directive is not present, the username and/or password
   * are invalid, and new values must be obtained.</dd>
   * </dl>
   *
   * @return {@code true} if a stale directive is present in the
   * header and equal to "true" (case-insensitive), {@code
   * false} otherwise.
   */
  public boolean isStale() {
    return stale;
  }
}
