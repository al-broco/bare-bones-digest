package com.albroco.barebonesdigest;

import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class DigestAuthentication {
  private List<DigestChallenge> challenges;

  private DigestAuthentication(List<DigestChallenge> challenges) {
    this.challenges = challenges;
  }

  public DigestAuthentication fromHttpUrlConnection(HttpURLConnection connection) throws
      HttpDigestChallengeParseException {
    return fromResponseHeaders(connection.getHeaderFields());
  }

  public static <T extends Iterable<String>> DigestAuthentication fromResponseHeaders(Map<String,
      T> headers) throws HttpDigestChallengeParseException {
    return fromChallenges(WwwAuthenticateHeader.extractChallenges(headers));
  }

  public static DigestAuthentication fromWwwAuthenticateHeader(String wwwAuthenticateHeader)
      throws HttpDigestChallengeParseException {
    return fromChallenges(WwwAuthenticateHeader.extractChallenges(wwwAuthenticateHeader));
  }

  public static DigestAuthentication fromWwwAuthenticateHeaders(Iterable<String>
      wwwAuthenticateHeaders) throws HttpDigestChallengeParseException {
    return fromChallenges(WwwAuthenticateHeader.extractChallenges(wwwAuthenticateHeaders));
  }

  public static DigestAuthentication fromChallenges(Iterable<String> challenges) throws
      HttpDigestChallengeParseException {
    List<DigestChallenge> digestChallenges;
    if (challenges instanceof Collection) {
      digestChallenges = new ArrayList<>(((Collection) challenges).size());
    } else {
      digestChallenges = new ArrayList<>();
    }

    for (String challenge : challenges) {
      if (DigestChallenge.isDigestChallenge(challenge)) {
        digestChallenges.add(DigestChallenge.parse(challenge));
      }
    }
    return new DigestAuthentication(digestChallenges);
  }

  public static DigestAuthentication fromDigestChallenges(Collection<? extends
      DigestChallenge> challenges) {
    return new DigestAuthentication(new ArrayList<>(challenges));
  }

  public static DigestAuthentication fromDigestChallenge(DigestChallenge challenge) {
    return new DigestAuthentication(Collections.singletonList(challenge));
  }
}
