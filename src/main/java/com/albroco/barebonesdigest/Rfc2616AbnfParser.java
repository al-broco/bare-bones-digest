// Copyright (c) 2016 Petter Wintzell

package com.albroco.barebonesdigest;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
final class Rfc2616AbnfParser {
  private static final boolean[] VALID_TOKEN_CHARS = new boolean[127];
  private static final boolean[] VALID_TOKEN68_CHARS_EXCLUDING_EQUALS = new boolean[127];

  private static final Pattern QUOTE_PATTERN = Pattern.compile("[\"\\\\]");
  private static final Pattern UNQUOTE_PATTERN = Pattern.compile("\\\\(.)");

  private final String input;
  private int eltStart;
  private int eltEnd;

  static {
    // Definition from RFC 2616, Section 2.2:
    // token          = 1*<any CHAR except CTLs or separators>
    // CHAR           = <any US-ASCII character (octets 0 - 127)>
    // CTL            = <any US-ASCII control character
    //                  (octets 0 - 31) and DEL (127)>
    // separators     = "(" | ")" | "<" | ">" | "@"
    //                | "," | ";" | ":" | "\" | <">
    //                | "/" | "[" | "]" | "?" | "="
    //                | "{" | "}" | SP | HT

    String separators = "()<>@,;:\\\"/[]?={} \t";

    for (char c = 0; c < VALID_TOKEN_CHARS.length; ++c) {
      VALID_TOKEN_CHARS[c] = c >= 32 && c < 127 && separators.indexOf(c) == -1;
    }
  }

  static {
    // Definition from RFC 7235, Section 2.1:
    // token68        = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
    // Definitions from RFC 5234, Section B.1:
    // ALPHA          =  %x41-5A / %x61-7A   ; A-Z / a-z
    // DIGIT          =  %x30-39 ; 0-9

    String token68Chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~+/";

    for (char c = 0; c < VALID_TOKEN68_CHARS_EXCLUDING_EQUALS.length; ++c) {
      VALID_TOKEN68_CHARS_EXCLUDING_EQUALS[c] = token68Chars.indexOf(c) != -1;
    }
  }

  public Rfc2616AbnfParser(String input) {
    this.input = input;
  }

  public String get() {
    return input.substring(eltStart, eltEnd);
  }

  public String getInput() {
    return input;
  }

  public String getRemainingInput() {
    return input.substring(eltEnd);
  }

  public int getPos() {
    return eltEnd;
  }

  public void setPos(int pos) {
    this.eltStart = this.eltEnd = pos;
  }

  public boolean hasMoreData() {
    return eltEnd < input.length();
  }

  public boolean isLookingAtLiteral(String literal) {
    // Definition from RFC 2616, Section 2.1:
    // "literal"
    //    Quotation marks surround literal text. Unless stated otherwise,
    //    the text is case-insensitive.
    if (input.length() < eltEnd + literal.length()) {
      return false;
    }

    String substring = input.substring(eltEnd, eltEnd + literal.length());
    return substring.equalsIgnoreCase(literal);
  }

  public Rfc2616AbnfParser consumeLiteral(String literal) throws ParseException {
    if (!isLookingAtLiteral(literal)) {
      throw new ParseException("Expected literal '" + literal + "'", this);
    }

    eltStart = eltEnd;
    eltEnd += literal.length();

    return this;
  }

  public Rfc2616AbnfParser consumeOws() {
    // Optional white space, definition from RFC 7230, Section 3.2.3:
    // OWS            = *( SP / HTAB )
    //                ; optional whitespace
    // Note: Also include newline/carriage return also be able to parse the rule for LWS from
    // RFC 2616, Section 2.2:
    // LWS            = [CRLF] 1*( SP | HT )
    // TODO make more efficient
    eltStart = eltEnd;
    while (hasMoreData() && (input.charAt(eltEnd) == ' ' ||
        input.charAt(eltEnd) == '\t' ||
        input.charAt(eltEnd) == '\r' ||
        input.charAt(eltEnd) == '\n')) {
      ++eltEnd;
    }

    return this;
  }

  public Rfc2616AbnfParser consumeRws() throws ParseException {
    // Required white space, definition from RFC 7230, Section 3.2.3:
    // RWS            = 1*( SP / HTAB )
    //                ; required whitespace
    if (consumeOws().get().length() == 0) {
      throw new ParseException("Expected whitespace", this);
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
    return c < VALID_TOKEN_CHARS.length && VALID_TOKEN_CHARS[c];
  }

  public Rfc2616AbnfParser consumeToken68() throws ParseException {
    int tokenEnd = eltEnd;
    while (tokenEnd < input.length() && isValidToken68CharExcludingEquals(input.charAt(tokenEnd))) {
      ++tokenEnd;
    }
    while (tokenEnd < input.length() && input.charAt(tokenEnd) == '=') {
      ++tokenEnd;
    }

    if (eltEnd == tokenEnd) {
      throw new ParseException("Expected token68", this);
    }

    eltStart = eltEnd;
    eltEnd = tokenEnd;

    return this;
  }

  private boolean isValidToken68CharExcludingEquals(char c) {
    return c < VALID_TOKEN68_CHARS_EXCLUDING_EQUALS.length &&
        VALID_TOKEN68_CHARS_EXCLUDING_EQUALS[c];
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
    int pos = eltEnd;
    if (pos >= input.length() || input.charAt(pos) != '"') {
      throw new ParseException("Expected quoted string", this);
    }

    pos++;

    boolean closingQuoteFound = false;
    while (!closingQuoteFound) {
      int nextQuote = input.indexOf("\"", pos);

      if (nextQuote == -1) {
        throw new ParseException("Expected quoted string", this);
      }

      int precedingBackslashes = 0;
      while (input.charAt(nextQuote - precedingBackslashes - 1) == '\\') {
        precedingBackslashes++;
      }

      if (precedingBackslashes % 2 == 0) {
        closingQuoteFound = true;
      }

      pos = nextQuote + 1;
    }

    eltStart = eltEnd;
    eltEnd = pos;
    return this;
  }

  public Rfc2616AbnfParser consumeQuotedStringOrToken() throws ParseException {
    if (eltEnd >= input.length()) {
      throw new ParseException("Expected token or quoted string", this);
    }

    if (input.charAt(eltEnd) == '\"') {
      return consumeQuotedString();
    }

    return consumeToken();
  }

  /**
   * Quotes a string.
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
   * @param str a string to quote
   * @return the quoted string
   */
  public static String quote(String str) {
    Matcher matcher = QUOTE_PATTERN.matcher(str);
    return "\"" + matcher.replaceAll("\\\\$0") + "\"";
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
   * @param str a quoted string to unquote - if the string is not a valid quoted an undefined
   *            non-null String is returned (no exception is thrown)
   * @return the unquoted string
   */
  public static String unquote(String str) {
    if (str.length() < 2) {
      return str;
    }
    Matcher matcher = UNQUOTE_PATTERN.matcher(str.substring(1, str.length() - 1));
    return matcher.replaceAll("$1");
  }

  /**
   * Given either a token or a quoted string (e.g. the result of
   * {@link #consumeQuotedStringOrToken()}), unquotes the string if it is quoted and returns the
   * result.
   *
   * @param str either a quoted string or a token
   * @return the string, unquoted if it was quoted
   */
  public static String unquoteIfQuoted(String str) {
    if (str.startsWith("\"")) {
      return unquote(str);
    }
    return str;
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

  @Override
  public String toString() {
    return "Rfc2616AbnfParser{" +
        "input='" + input + '\'' +
        ", pos=" + eltEnd +
        ", lastConsumed=" + get() +
        ", remainingInput='" + getRemainingInput() + "'" +
        '}';
  }
}
