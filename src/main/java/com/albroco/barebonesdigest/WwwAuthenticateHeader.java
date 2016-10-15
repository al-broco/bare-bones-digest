// Copyright (c) 2016 Petter Wintzell

package com.albroco.barebonesdigest;

import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Class for extracting challenges from <code>WWW-Authenticate</code> headers.
 * <p>
 * The <code>WWW-Authenticate</code> header is described in
 * <a href="https://tools.ietf.org/html/rfc7235#section-4.1">Section 4.1 of RFC 7235</a>. It can
 * contain one or more challenges and it can appear multiple times in each response.
 * <p>
 * Example: The following header:
 * <pre>
 * WWW-Authenticate: Newauth realm="apps", type=1, title="Login to \"apps\"", Basic realm="simple"
 * </pre>
 * contains two challenges, <code>Newauth realm="apps", type=1, title="Login to \"apps\""</code> and
 * <code>Basic realm="simple"</code>.
 * <p>
 * This class is not specific for digest authentication. It returns the challenges as strings and
 * can extract challenges of any type.
 */
public final class WwwAuthenticateHeader {
  /**
   * Name of the HTTP response header WWW-Authenticate.
   *
   * @see <a href="https://tools.ietf.org/html/rfc2616#section-14.47">RFC 7235, Section 14.47,
   * WWW-Authenticate</a>
   */
  public static final String HTTP_HEADER_WWW_AUTHENTICATE = "WWW-Authenticate";

  private WwwAuthenticateHeader() {
  }

  /**
   * Extracts challenges from an HTTP response.
   *
   * @param connection the connection the response will be read from
   * @return a list of challenges
   * @throws ChallengeParseException if the challenges are malformed and could not be
   *                                 parsed
   */
  public static List<String> extractChallenges(HttpURLConnection connection) throws
      ChallengeParseException {
    return extractChallenges(connection.getHeaderFields());
  }

  /**
   * Extracts challenges from a map of HTTP headers.
   * <p>
   * A note about the map representing the headers: header names are case insensitive in HTTP. This
   * means that the <code>WWW-Authenticate</code> header can be represented in multiple
   * ways (<code>WWW-Authenticate</code>, <code>www-authenticate</code>, etc), even in the same
   * HTTP response. This method makes no assumption about the case of the headers, but two keys
   * in the map must not be equal if case is disregarded, that is, all case variations of
   * <code>WWW-Authenticate</code> must be collected with the same key. Incidentally, this is
   * what is returned by {@code HttpURLConnection.getHeaderFields()}.
   *
   * @param headers the headers, as a map where the keys are header names and values are
   *                iterables where each element is a header value string
   * @return a list of challenges
   * @throws ChallengeParseException if the challenges are malformed and could not be
   *                                 parsed
   */
  public static <T extends Iterable<String>> List<String> extractChallenges(Map<String, T>
      headers) throws ChallengeParseException {
    if (headers.containsKey(HTTP_HEADER_WWW_AUTHENTICATE)) {
      return extractChallenges(headers.get(HTTP_HEADER_WWW_AUTHENTICATE));
    }

    for (String headerName : headers.keySet()) {
      if (HTTP_HEADER_WWW_AUTHENTICATE.equalsIgnoreCase(headerName)) {
        return extractChallenges(headers.get(headerName));
      }
    }

    return Collections.emptyList();
  }

  /**
   * Extracts challenges from a set of <code>WWW-Authenticate</code> HTTP headers.
   *
   * @param wwwAuthenticateHeaders the header values
   * @return a list of challenges
   * @throws ChallengeParseException if the challenges are malformed and could not be
   *                                 parsed
   */
  public static List<String> extractChallenges(Iterable<String> wwwAuthenticateHeaders) throws
      ChallengeParseException {
    List<String> result = new ArrayList<>();
    for (String header : wwwAuthenticateHeaders) {
      extractChallenges(header, result);
    }
    return result;
  }

  /**
   * Extracts challenges from a <code>WWW-Authenticate</code> header.
   *
   * @param wwwAuthenticateHeader the header value
   * @return a list of challenges
   * @throws ChallengeParseException if the challenges are malformed and could not be
   *                                 parsed
   */
  public static List<String> extractChallenges(String wwwAuthenticateHeader) throws
      ChallengeParseException {
    List<String> result = new ArrayList<>();
    extractChallenges(wwwAuthenticateHeader, result);
    return result;
  }

  private static void extractChallenges(String header,
      List<String> result) throws ChallengeParseException {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser(header);
    while (parser.hasMoreData()) {
      try {
        int startOfChallenge = parser.getPos();

        // Consume and store the challenge
        consumeChallenge(parser);
        result.add(parser.getInput().substring(startOfChallenge, parser.getPos()));

        // Consume (and discard) comma separating challenge from the next, or move on to string end
        parser.consumeOws();
        if (parser.hasMoreData()) {
          parser.consumeLiteral(",").consumeOws();
        }
      } catch (Rfc2616AbnfParser.ParseException e) {
        throw new ChallengeParseException(e);
      }
    }
  }

  private static void consumeChallenge(Rfc2616AbnfParser parser) throws Rfc2616AbnfParser
      .ParseException {
    parser.consumeToken(); // auth-scheme

    int savedPos = parser.getPos();
    try {
      consumeToEndOfEmptyOrAuthParamBasedChallenge(parser);
      return;
    } catch (Rfc2616AbnfParser.ParseException e) {
      // Failed to parse string as an auth-param based challenge
    }

    parser.setPos(savedPos);
    try {
      consumeToEndOfSchemeOnlyChallenge(parser);
      return;
    } catch (Rfc2616AbnfParser.ParseException e) {
      // Failed to parse string as scheme-only challenge
    }

    parser.setPos(savedPos);
    consumeToEndOfToken68BasedChallenge(parser);
  }

  private static void consumeToEndOfSchemeOnlyChallenge(Rfc2616AbnfParser parser) throws
      Rfc2616AbnfParser.ParseException {
    int pos = parser.getPos();
    try {
      parser.consumeOws();
      if (!isLookingAtCommaOrStringEnd(parser)) {
        // Unexpected content, the following will fail the parsing:
        parser.consumeLiteral(",");
      }
    } finally {
      parser.setPos(pos);
    }
  }

  private static void consumeToEndOfToken68BasedChallenge(Rfc2616AbnfParser parser) throws
      Rfc2616AbnfParser.ParseException {
    parser.consumeRws().consumeToken68(); // token68
    if (!isLookingAtCommaOrStringEnd(parser)) {
      // Unexpected content, the following will fail the parsing:
      parser.consumeLiteral(",");
    }
  }

  private static boolean isLookingAtCommaOrStringEnd(Rfc2616AbnfParser parser) {
    int pos = parser.getPos();
    try {
      parser.consumeOws();
      return !parser.hasMoreData() || parser.isLookingAtLiteral(",");
    } finally {
      parser.setPos(pos);
    }
  }

  private static void consumeToEndOfEmptyOrAuthParamBasedChallenge(Rfc2616AbnfParser parser)
      throws Rfc2616AbnfParser.ParseException {

    consumeAuthParam(parser);

    while (parser.hasMoreData()) {
      // This could be the end of the challenge, it depends on what follows
      int possibleEndOfChallenge = parser.getPos();

      parser.consumeOws();
      if (!parser.hasMoreData()) {
        // String end, challenge has ended
        parser.setPos(possibleEndOfChallenge);
        return;
      }

      // auth-param must be followed by comma, either separating it from the next auth-param or
      // the next challenge
      parser.consumeLiteral(",").consumeOws();
      if (!tryToConsumeAuthParam(parser)) {
        // Comma not followed by auth-param, this means a new challenge starts after the comma
        parser.setPos(possibleEndOfChallenge);
        return;
      }
    }
  }

  private static void consumeAuthParam(Rfc2616AbnfParser parser) throws Rfc2616AbnfParser
      .ParseException {
    parser.consumeOws()
        .consumeToken()
        .consumeOws()
        .consumeLiteral("=")
        .consumeOws()
        .consumeQuotedStringOrToken();
  }

  private static boolean tryToConsumeAuthParam(Rfc2616AbnfParser parser) {
    int originalPos = parser.getPos();
    try {
      consumeAuthParam(parser);
    } catch (Rfc2616AbnfParser.ParseException e) {
      parser.setPos(originalPos);
      return false;
    }
    return true;
  }
}
