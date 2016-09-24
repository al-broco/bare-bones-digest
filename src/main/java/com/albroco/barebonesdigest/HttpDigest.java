package com.albroco.barebonesdigest;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class HttpDigest {
  public static <T extends Collection<String>> String getAuthenticationHeader(Map<String, T> headers,

      String requestMethod,
      String digestUri,
      String username,
      String password) throws HttpDigestChallengeParseException,
      UnsupportedHttpDigestAlgorithmException {
    // TODO response can be null
    return createResponseFromChallenges(WwwAuthenticateHeader.extractChallenges(headers)).username(
        username)
        .password(password)
        .digestUri(digestUri)
        .requestMethod(requestMethod)
        .getHeaderValue();
  }

  public static <T extends Collection<String>> DigestChallengeResponse createResponseFromResponseHeaders(
      Map<String, T> headers) throws HttpDigestChallengeParseException,
      UnsupportedHttpDigestAlgorithmException {
    return createResponseFromChallenges(WwwAuthenticateHeader.extractChallenges(headers));
  }

  public static DigestChallengeResponse createResponseFromWwwAuthenticateHeader(String
      wwwAuthenticateHeader) throws HttpDigestChallengeParseException,
      UnsupportedHttpDigestAlgorithmException {
    return createResponseFromChallenges(WwwAuthenticateHeader.extractChallenges(Collections
        .singletonList(
        wwwAuthenticateHeader)));
  }

  public static DigestChallengeResponse createResponseFromWwwAuthenticateHeaders(Collection<String>
      wwwAuthenticateHeaders) throws HttpDigestChallengeParseException,
      UnsupportedHttpDigestAlgorithmException {
    return createResponseFromChallenges(WwwAuthenticateHeader.extractChallenges(
        wwwAuthenticateHeaders));
  }

  public static DigestChallengeResponse createResponseFromChallenges(Collection<String> challenges)
      throws HttpDigestChallengeParseException, UnsupportedHttpDigestAlgorithmException {
    List<DigestChallenge> digestChallenges = new ArrayList<>(challenges.size());
    for (String challenge : challenges) {
      if (DigestChallenge.isDigestChallenge(challenge)) {
        digestChallenges.add(DigestChallenge.parse(challenge));
      }
    }
    return createResponseFromDigestChallenges(digestChallenges);
  }

  public static DigestChallengeResponse createResponseFromDigestChallenges(Collection<? extends
      DigestChallenge> challenges) throws UnsupportedHttpDigestAlgorithmException {
    // TODO: allow ordering of challenges
    UnsupportedHttpDigestAlgorithmException exception = null;

    for (DigestChallenge challenge : challenges) {
      try {
        return DigestChallengeResponse.responseTo(challenge);
      } catch (UnsupportedHttpDigestAlgorithmException e) {
        exception = e;
      }
    }

    if (exception != null) {
      throw exception;
    }

    // TODO: makes sense?
    return null;
  }
}
