package org.barebonesdigest;

/**
 * Parses strings with a grammar defined using the augmented BNF described
 * in <a href="https://tools.ietf.org/html/rfc2616#section-2.1">Section 2.1
 * of RFC 2616.</a>
 *
 * The parser is created with a string to parse as parameter:
 * <p><blockquote><pre>
 * String content = "realm = \"testrealm@host.com\""
 * Rfc2616AbnfParser parser = new Rfc2616AbnfParser(content);
 * </blockquote></pre>
 *
 * <p>Internally, the parser has a cursor position that can be advanced using
 * the various <code>consume</code> methods. <code>consume</code> methods can
 * be chained:
 * <p><blockquote><pre>
 * parser.consumeToken(); // Advances the cursor past "realm"
 * parser.consumeWhitespace().consumeLiteral("=").consumeWhiteSpace();
 *                        // Advances the cursor up to the first quote
 * </blockquote></pre>
 *
 * <p>The string contents consumed by the latest call to a <code>consume</code>
 * method can be obtained using {@link #get()}:
 * <p><blockquote><pre>
 * String realm = parser.consumeQuotedString().get();
 * </blockquote></pre>
 */
public final class Rfc2616AbnfParser {
  // TOOD: create table and do lookup
  // Defined in RFC 2616, Section 2.2
  private static final String ABNF_SEPARATOR_CHARACTERS = "()<>@,;:\\\"([]?={} \t";

  private String input;
  private int eltStart;
  private int eltEnd;

  public Rfc2616AbnfParser(String input) {
    this.input = input;
  }

  public String get() {
    return input.substring(eltStart, eltEnd);
  }

  public Rfc2616AbnfParser consumeLiteral(String literal) throws ParseException {
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

  public Rfc2616AbnfParser consumeWhitespace() throws ParseException {
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

  public Rfc2616AbnfParser consumeToken() throws ParseException {
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

    return ABNF_SEPARATOR_CHARACTERS.indexOf(c) == -1;
  }

  public Rfc2616AbnfParser consumeQuotedString() throws ParseException {
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

  /**
   * Unqoutes a quoted string.
   *
   * Quoted strings are explained in
   * <a href="https://tools.ietf.org/html/rfc2616#section-2.2">Section 2.2 of
   * RFC 2616</a>:
   *
   * <dl>
   * <dt>quoted-string</dt>
   * <dd>A string of text is parsed as a single word if it is quoted using
   * double-quote marks.
   * <p><blockquote><pre>
   * quoted-string  = ( &lt;"&gt; *(qdtext | quoted-pair ) &lt;"&gt; )
   * qdtext         = &lt;any TEXT except &lt;"&gt;&gt;
   * </blockquote></pre>
   * The backslash character ("\") MAY be used as a single-character
   * quoting mechanism only within quoted-string and comment
   * constructs.
   * <p><blockquote><pre>
   * quoted-pair    = "\" CHAR
   * </blockquote></pre></dd>
   * </dl>
   *
   * @param str the string to unqoute
   * @return the unquoted string
   */
  public static String unquote(String str) {
    // TODO: Handle malformed strings (missing quotes, strings ending in \)
    if (str.indexOf('\\') == -1) {
      return str.substring(1, str.length() - 1);
    }

    StringBuffer result = new StringBuffer();

    int index = 1;
    while (index < str.length() - 1) {
      char c = str.charAt(index);
      if (c == '\\') {
        c = str.charAt(++index);
      }
      result.append(c);
    }

    return result.toString();
  }

  public static final class ParseException extends Exception {
    ParseException(String message) {
      super(message);
    }

    ParseException(String message, Rfc2616AbnfParser parser) {
      this(message + " at pos " + parser.getPos() + ", remaining input: " +
          parser.getRemainingInput());
    }
  }
}
