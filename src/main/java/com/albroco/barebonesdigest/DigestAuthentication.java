package com.albroco.barebonesdigest;

import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class DigestAuthentication {
  private List<DigestChallenge> challenges;
  private DigestChallengeResponse response;
  private String username;
  private String password;
  private boolean firstResponse = true;

  /**
   * Default comparator used when comparing which challenge to use when there is more than one to
   * choose from.
   * <p>
   * Orders challenges from most preferred to least preferred. Unsupported challenges (that is,
   * challenges that do not meet the requirements of
   * {@link DigestChallengeResponse#isChallengeSupported(DigestChallenge)}) are sorted last.
   * Supported challenges are sorted in the following order:
   * <ol>
   * <li>Challenges where the server supports qop types <code>auth</code> and
   * <code>auth-int</code>.</li>
   * <li>Challenges where the server supports qop type <code>auth</code> but not
   * <code>auth-int</code>.</li>
   * <li>Challenges where the server supports the unnamed legacy qop type for RFC 2069
   * compatibility but not <code>auth</code>. This should rarely happen in practice.</li>
   * <li>Challenges where the server supports qop type <code>auth-int</code> and nothing else.
   * This is ranked last because <code>auth-int</code> is limited and cannot authenticate requests
   * without a body, such as HTTP GET.</li>
   * </ol>
   */
  public static final Comparator<DigestChallenge> DEFAULT_CHALLENGE_COMPARATOR =
      new Comparator<DigestChallenge>() {
        @Override
        public int compare(DigestChallenge lhs, DigestChallenge rhs) {
          return score(rhs) - score(lhs);
        }

        private int score(DigestChallenge challenge) {
          if (!DigestChallengeResponse.isChallengeSupported(challenge)) {
            return Integer.MIN_VALUE;
          }

          Set<DigestChallenge.QualityOfProtection> supportedQopTypes =
              challenge.getSupportedQopTypes();
          if (supportedQopTypes.contains(DigestChallenge.QualityOfProtection.AUTH_INT) &&
              supportedQopTypes.contains(DigestChallenge.QualityOfProtection.AUTH)) {
            return 0;
          }

          if (supportedQopTypes.contains(DigestChallenge.QualityOfProtection.AUTH)) {
            return -1;
          }

          if (supportedQopTypes.contains(DigestChallenge.QualityOfProtection
              .UNSPECIFIED_RFC2069_COMPATIBLE)) {
            return -2;
          }

          if (supportedQopTypes.contains(DigestChallenge.QualityOfProtection.AUTH_INT)) {
            return -3;
          }

          return Integer.MIN_VALUE;
        }
      };

  private DigestAuthentication(List<DigestChallenge> challenges) {
    this.challenges = challenges;
    Collections.sort(this.challenges, DEFAULT_CHALLENGE_COMPARATOR);
  }

  public static DigestAuthentication fromResponse(HttpURLConnection connection) throws
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

  public DigestAuthentication challengeOrdering(Comparator<? super DigestChallenge>
      orderingComparator) {
    Collections.sort(this.challenges, orderingComparator);
    return this;
  }

  /**
   * Sets the username to use for authentication.
   *
   * @param username the username
   * @return this object so that setters can be chained
   * @see #getUsername()
   * @see <a href="https://tools.ietf.org/html/rfc2617#section-3.2.2">Section 3.2.2 of RFC 2617</a>
   */
  public DigestAuthentication username(String username) {
    if (response != null) {
      response.username(username);
    } else {
      this.username = username;
    }
    return this;
  }

  /**
   * Returns the username to use for authentication.
   *
   * @return the username
   * @see #username(String)
   */
  public String getUsername() {
    if (response != null) {
      return response.getUsername();
    }
    return username;
  }

  /**
   * Sets the password to use for authentication.
   *
   * @param password the password
   * @return this object so that setters can be chained
   * @see #getPassword()
   */
  public DigestAuthentication password(String password) {
    if (response != null) {
      response.password(password);
    } else {
      this.password = password;
    }
    return this;
  }

  /**
   * Returns the password to use for authentication.
   *
   * @return the password
   * @see #password(String)
   */
  public String getPassword() {
    if (response != null) {
      return response.getPassword();
    }
    return password;
  }

  public DigestChallengeResponse getChallengeResponse() {
    if (response == null) {
      response = pickChallengeResponse().username(username).password(password);
      challenges = null;
      username = password = null;
    }

    return response;
  }

  public String getAuthorizationForRequest(String requestMethod, String digestUri) {
    if (!firstResponse) {
      getChallengeResponse().incrementNonceCount().randomizeClientNonce();
    }
    firstResponse = false;

    return getChallengeResponse().requestMethod(requestMethod)
        .digestUri(digestUri)
        .getHeaderValue();
  }

  private DigestChallengeResponse pickChallengeResponse() {
    for (DigestChallenge challenge : challenges) {
      if (DigestChallengeResponse.isChallengeSupported(challenge)) {
        return DigestChallengeResponse.responseTo(challenge);
      }
    }

    // TODO: throw exception that no compatible challenge was found
    return null;
  }
}
