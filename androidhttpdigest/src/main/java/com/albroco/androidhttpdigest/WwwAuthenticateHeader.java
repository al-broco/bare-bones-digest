package com.albroco.androidhttpdigest;

public class WwwAuthenticateHeader {
  // TOOD: create table and do lookup
  // Defined in RFC 2616, Section 2.2
  private static final String EBNF_SEPARATOR_CHARACTERS = "()<>@,;:\\\"([]?={} \t";

  private static final String HTTP_DIGEST_CHALLENGE_PREFIX = "digest";
  private final String realm;
  private final String nonce;
  private final String opaqueQuoted;
  private final String algorithm;

  private WwwAuthenticateHeader(String realm, String nonce, String opaqueQuoted, String algorithm) {
    this.realm = realm;
    this.nonce = nonce;
    this.opaqueQuoted = opaqueQuoted;
    this.algorithm = algorithm;
  }

  public static WwwAuthenticateHeader parse(String authenticateHeader) {
    // TODO: Current parsing is broken and only works for simple cases

    Parser parser = new Parser(authenticateHeader);
    try {
      parser.consumeLiteral(HTTP_DIGEST_CHALLENGE_PREFIX);
      parser.consumeWhitespace();

      String realm = null;
      String nonce = null;
      String opaqueQuoted = null;
      String algorithm = null;

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
          parser.consumeQuotedString();

          // TODO parse domain
          // TODO parse stale
          // TODO parse domain
          // TODO parse auth-param
        } else {
          throw new ParseException("Unexpected token: " + token, parser);
        }

        parser.consumeWhitespace();
        if (parser.containsMoreData()) {
          parser.consumeLiteral(",").consumeWhitespace();
        }
      }

      return new WwwAuthenticateHeader(realm, nonce, opaqueQuoted, algorithm);
    } catch (ParseException e) {
      return null;
    }
  }

  public String getRealm() {
    return realm;
  }

  public String getAlgorithm() {
    return algorithm;
  }

  public String getNonce() {
    return nonce;
  }

  public String getOpaqueQuoted() {
    return opaqueQuoted;
  }

  private static String unquoteString(String str) {
    // TODO: implement properly
    if (str.startsWith("\"") && str.endsWith("\"")) {
      return str.substring(1, str.length() - 1);
    }
    return str;
  }

  private static final class Parser {
    private String input;
    private int eltStart;
    private int eltEnd;

    public Parser(String input) {
      this.input = input;
    }

    public String get() {
      return input.substring(eltStart, eltEnd);
    }

    public Parser consumeLiteral(String literal) throws ParseException {
      // Definition from RFC 2616, Section 2.1:
      // "literal"
      //    Quotation marks surround literal text. Unless stated otherwise,
      //    the text is case-insensitive.
      if (input.length() < eltEnd + literal.length()) {
        throw new ParseException("Expected literal " + literal, this);
      }

      String substring = input.substring(eltEnd, eltEnd + literal.length());
      if (!substring.equalsIgnoreCase(literal)) {
        throw new ParseException("Expected literal " + literal, this);
      }

      eltStart = eltEnd;
      eltEnd += literal.length();

      return this;
    }

    public Parser consumeWhitespace() throws ParseException {
      // Definition from RFC 2616, Section 2.2:
      // LWS            = [CRLF] 1*( SP | HT )
      // CRLF           = CR LF
      // CR             = <US-ASCII CR, carriage return (13)>
      // LF             = <US-ASCII LF, linefeed (10)>
      // SP             = <US-ASCII SP, space (32)>
      // HT             = <US-ASCII HT, horizontal-tab (9)>
      // TODO make more efficient
      eltStart = eltEnd;
      while (containsMoreData() && (input.charAt(eltEnd) == ' ' ||
          input.charAt(eltEnd) == '\t' ||
          input.charAt(eltEnd) == '\r' ||
          input.charAt(eltEnd) == '\n')) {
        ++eltEnd;
      }

      return this;
    }

    public Parser consumeToken() throws ParseException {
      // Definition from RFC 2616, Section 2.2:
      // token          = 1*<any CHAR except CTLs or separators>
      int tokenEnd = eltEnd;
      while (tokenEnd < input.length() && isValidTokenChar(input.charAt(tokenEnd))) {
        ++tokenEnd;
      }

      if (eltEnd == tokenEnd) {
        throw new ParseException("Expected token", this);
      }

      eltStart = eltEnd;
      eltEnd = tokenEnd;

      return this;
    }

    private boolean isValidTokenChar(char c) {
      // Definition from RFC 2616, Section 2.2:
      // token          = 1*<any CHAR except CTLs or separators>
      // CHAR           = <any US-ASCII character (octets 0 - 127)>
      // CTL            = <any US-ASCII control character
      //                  (octets 0 - 31) and DEL (127)>
      if (c <= 31 || c > 126) {
        return false;
      }

      return EBNF_SEPARATOR_CHARACTERS.indexOf(c) == -1;
    }

    public Parser consumeQuotedString() throws ParseException {
      // Definition from RFC 2616, Section 2.2:
      // A string of text is parsed as a single word if it is quoted using
      // double-quote marks.
      //     quoted-string  = ( <"> *(qdtext | quoted-pair ) <"> )
      //     qdtext         = <any TEXT except <">>
      // The backslash character ("\") MAY be used as a single-character
      // quoting mechanism only within quoted-string and comment constructs.
      //     quoted-pair    = "\" CHAR
      // TODO: Handle quoted characters
      int stringEnd = eltEnd;
      if (stringEnd >= input.length() || input.charAt(stringEnd) != '"') {
        throw new ParseException("Expected quoted string", this);
      }

      stringEnd++;
      while (stringEnd < input.length() && input.charAt(stringEnd) != '"') {
        stringEnd++;
      }
      stringEnd++;

      if (stringEnd > input.length()) {
        throw new ParseException("Expected quoted string", this);
      }

      eltStart = eltEnd;
      eltEnd = stringEnd;

      return this;
    }

    public String getRemainingInput() {
      return input.substring(eltEnd);
    }

    public boolean containsMoreData() {
      return eltEnd < input.length();
    }

    public int getPos() {
      return eltEnd;
    }

    public String unquote(String s) {
      return s.substring(1, s.length() - 1);
    }
  }

  private static final class ParseException extends Exception {
    ParseException(String message) {
      super(message);
    }

    ParseException(String message, Parser parser) {
      this(message + " at pos " + parser.getPos() + ", remaining input: " +
          parser.getRemainingInput());
    }
  }
}
