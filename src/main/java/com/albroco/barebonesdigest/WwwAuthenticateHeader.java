package com.albroco.barebonesdigest;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * TODO document
 */
public class WwwAuthenticateHeader {
  /**
   * Name of the HTTP response header WWW-Authenticate.
   *
   * @see <a href="https://tools.ietf.org/html/rfc2616#section-14.47">RFC 7235, Section 14.47,
   * WWW-Authenticate</a>
   */
  public static final String HTTP_HEADER_WWW_AUTHENTICATE = "WWW-Authenticate";

  /**
   * TODO document
   */
  public static <T extends Collection<String>> List<String> extractChallenges(Map<String, T>
      headers) throws HttpDigestChallengeParseException {
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
   * TODO document
   */
  public static List<String> extractChallenges(Collection<String> wwwAuthenticateHeaders) throws
      HttpDigestChallengeParseException {
    List<String> result = new ArrayList<>();
    for (String header : wwwAuthenticateHeaders) {
      extractChallenges(header, result);
    }
    return result;
  }

  /**
   * TODO document
   */
  public static List<String> extractChallenges(String wwwAuthenticateHeader) throws
      HttpDigestChallengeParseException {
    List<String> result = new ArrayList<>();
    extractChallenges(wwwAuthenticateHeader, result);
    return result;
  }

  private static void extractChallenges(String header,
      List<String> result) throws HttpDigestChallengeParseException {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser(header);
    while (parser.hasMoreData()) {
      try {
        int startOfChallenge = parser.getPos();
        consumeChallenge(parser);
        result.add(parser.getInput().substring(startOfChallenge, parser.getPos()));
        parser.consumeWhitespace();
        if (parser.hasMoreData()) {
          parser.consumeLiteral(",").consumeWhitespace();
        }
      } catch (Rfc2616AbnfParser.ParseException e) {
        throw new HttpDigestChallengeParseException(e);
      }
    }
  }

  private static void consumeChallenge(Rfc2616AbnfParser parser) throws Rfc2616AbnfParser
      .ParseException {
    parser.consumeToken().consumeWhitespace(); // auth-scheme

    int savedPos = parser.getPos();
    try {
      consumeToEndOfEmptyOrAuthParamBasedChallenge(parser);
    } catch (Rfc2616AbnfParser.ParseException e) {
      parser.setPos(savedPos);
      consumeToEndOfToken68BasedChallenge(parser);
    }
  }

  private static void consumeToEndOfToken68BasedChallenge(Rfc2616AbnfParser parser) throws
      Rfc2616AbnfParser.ParseException {
    parser.consumeToken68().consumeWhitespace(); // token68
    if (parser.hasMoreData()) {
      int pos = parser.getPos();
      parser.consumeLiteral(",").setPos(pos);
    }
  }

  private static void consumeToEndOfEmptyOrAuthParamBasedChallenge(Rfc2616AbnfParser parser)
      throws Rfc2616AbnfParser.ParseException {
    boolean firstAuthParam = true;
    while (parser.hasMoreData()) {
      int possibleEndOfChallenge = parser.getPos();
      if (!firstAuthParam) {
        parser.consumeLiteral(",").consumeWhitespace();
      }
      firstAuthParam = false;
      parser.consumeToken().consumeWhitespace();
      if (parser.isLookingAtLiteral("=")) {
        parser.consumeLiteral("=")
            .consumeWhitespace()
            .consumeQuotedStringOrToken()
            .consumeWhitespace();
      } else {
        parser.setPos(possibleEndOfChallenge);
        return;
      }
    }
  }
}
