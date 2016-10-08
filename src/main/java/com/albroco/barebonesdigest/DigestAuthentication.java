package com.albroco.barebonesdigest;

import com.android.internal.util.Predicate;

import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.albroco.barebonesdigest.DigestChallenge.QualityOfProtection;
import static com.albroco.barebonesdigest.DigestChallenge.QualityOfProtection.AUTH;
import static com.albroco.barebonesdigest.DigestChallenge.QualityOfProtection.AUTH_INT;
import static com.albroco.barebonesdigest.DigestChallenge.QualityOfProtection
    .UNSPECIFIED_RFC2069_COMPATIBLE;

/**
 * TODO doc
 * note: not thread safe
 */
public final class DigestAuthentication {
  private List<DigestChallenge> challenges;
  private DigestChallengeResponse response;
  private String username;
  private String password;
  private boolean firstResponse = true;

  /**
   * Predicate for filtering challenges baesd on what "quality of protection" types they support.
   * TODO test
   */
  public static final class QopFilter implements Predicate<DigestChallenge> {
    private final Set<QualityOfProtection> supportedQops;

    public static QopFilter allowingQops(QualityOfProtection supportedQop,
        QualityOfProtection... supportedQops) {
      return new QopFilter(EnumSet.of(supportedQop, supportedQops));
    }

    public static QopFilter disallowingQops(QualityOfProtection supportedQop,
        QualityOfProtection... supportedQops) {
      return new QopFilter(EnumSet.complementOf(EnumSet.of(supportedQop, supportedQops)));
    }

    private QopFilter(Set<QualityOfProtection> supportedQops) {
      this.supportedQops = supportedQops;
    }

    @Override
    public boolean apply(DigestChallenge digestChallenge) {
      for (QualityOfProtection qop : supportedQops) {
        if (digestChallenge.getSupportedQopTypes().contains(qop)) {
          return true;
        }
      }
      return false;
    }
  }

  /**
   * Predicate that can be used with {@link #filterChallenges(Predicate)} to prevent challenges that
   * only support the {@link QualityOfProtection#UNSPECIFIED_RFC2069_COMPATIBLE} from being used
   * when generating a response.
   */
  public static final Predicate<DigestChallenge> EXCLUDE_LEGACY_QOP_FILTER =
      QopFilter.disallowingQops(UNSPECIFIED_RFC2069_COMPATIBLE);

  /**
   * Predicate that can be used with {@link #filterChallenges(Predicate)} to prevent challenges that
   * only support the {@link QualityOfProtection#AUTH_INT} from being used when generating a
   * response.
   */
  public static final Predicate<DigestChallenge> EXCLUDE_AUTH_INT_FILTER =
      QopFilter.disallowingQops(AUTH_INT);

  /**
   * Default comparator used when comparing which challenge to use when there is more than one to
   * choose from.
   * <p>
   * Orders challenges from most preferred to least preferred:
   * <ol>
   * <li>Challenges where the server supports qop types <code>auth</code> and
   * <code>auth-int</code>.</li>
   * <li>Challenges where the server supports qop type <code>auth</code> but not
   * <code>auth-int</code>.</li>
   * <li>Challenges where the server supports the unnamed legacy qop type for RFC 2069
   * compatibility and nothing else. This should rarely happen in practice.</li>
   * <li>Challenges where the server supports qop type <code>auth-int</code> and nothing else.
   * This is ranked last among the supported challenges because <code>auth-int</code> is limited
   * and cannot authenticate requests without a body, such as HTTP GET.</li>
   * <li>Unsupported challenges.</li>
   * </ol>
   */
  public static final Comparator<DigestChallenge> DEFAULT_CHALLENGE_COMPARATOR =
      new Comparator<DigestChallenge>() {
        private final Collection<QualityOfProtection> AUTH_AUTH_INT_QOPS =
            EnumSet.of(AUTH, AUTH_INT);

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
          if (supportedQopTypes.containsAll(AUTH_AUTH_INT_QOPS)) {
            return 0;
          }

          if (supportedQopTypes.contains(AUTH)) {
            return -1;
          }

          if (supportedQopTypes.contains(UNSPECIFIED_RFC2069_COMPATIBLE)) {
            return -2;
          }

          if (supportedQopTypes.contains(AUTH_INT)) {
            return -3;
          }

          return Integer.MIN_VALUE;
        }
      };

  /**
   * Creates an authentication by reading response headers from an {@code HttpURLConnection} object.
   *
   * @param connection the connection
   * @return a new {@code DigestAuthentication} object
   * @throws HttpDigestChallengeParseException if challenges could not be parsed
   */
  public static DigestAuthentication fromResponse(HttpURLConnection connection) throws
      HttpDigestChallengeParseException {
    return fromResponseHeaders(connection.getHeaderFields());
  }

  /**
   * Creates an authentication from a map of HTTP response headers.
   * <p>
   * A note about the map representing the headers: header names are case insensitive in HTTP, but
   * keys in a {@code Map} are case-sensitive. This method uses
   * {@link WwwAuthenticateHeader#extractChallenges(Map)} and handles case in the same way.
   *
   * @param headers the headers, as a map where the keys are header names and values are
   *                iterables where each element is a header value string
   * @return a new {@code DigestAuthentication} object
   * @throws HttpDigestChallengeParseException if challenges could not be parsed
   */
  public static <T extends Iterable<String>> DigestAuthentication fromResponseHeaders(Map<String,
      T> headers) throws HttpDigestChallengeParseException {
    return fromChallenges(WwwAuthenticateHeader.extractChallenges(headers));
  }

  /**
   * Creates an authentication from a number of <code>WWW-Authenticate</code> headers.
   *
   * @param wwwAuthenticateHeaders the <code>WWW-Authenticate</code> headers
   * @return a new {@code DigestAuthentication} object
   * @throws HttpDigestChallengeParseException if challenges could not be parsed
   */
  public static DigestAuthentication fromWwwAuthenticateHeaders(Iterable<String>
      wwwAuthenticateHeaders) throws HttpDigestChallengeParseException {
    return fromChallenges(WwwAuthenticateHeader.extractChallenges(wwwAuthenticateHeaders));
  }

  /**
   * Creates an authentication from a single <code>WWW-Authenticate</code> header.
   *
   * @param wwwAuthenticateHeader the <code>WWW-Authenticate</code> header
   * @return a new {@code DigestAuthentication} object
   * @throws HttpDigestChallengeParseException if challenges could not be parsed
   */
  public static DigestAuthentication fromWwwAuthenticateHeader(String wwwAuthenticateHeader)
      throws HttpDigestChallengeParseException {
    return fromChallenges(WwwAuthenticateHeader.extractChallenges(wwwAuthenticateHeader));
  }

  /**
   * Creates an authentication from a number of challenges.
   * <p>
   * Challenges can be of any type, not just Digest challenges. See
   * <a href="https://tools.ietf.org/html/rfc7235#section-2.1">RFC 7235, Section 2.1</a> for a
   * definition of challenges. Some example of valid challenges:
   * <ul>
   * <li><code>Basic realm="simple"</code></li>
   * <li><code>Digest realm="testrealm@host.com", qop="auth,auth-int",
   * nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
   * opaque="5ccc069c403ebaf9f0171e9517f40e41"</code></li>
   * <li><code>Newauth realm="apps", type=1, title="Login to \"apps\""</code></li>
   * </ul>
   *
   * @param challenges the challenges
   * @return a new {@code DigestAuthentication} object
   * @throws HttpDigestChallengeParseException if challenges could not be parsed
   */
  public static DigestAuthentication fromChallenges(Iterable<String> challenges) throws
      HttpDigestChallengeParseException {
    List<DigestChallenge> supportedChallenges = createListOfMatchingSize(challenges);

    for (String challenge : challenges) {
      if (DigestChallenge.isDigestChallenge(challenge)) {
        DigestChallenge digestChallenge = DigestChallenge.parse(challenge);
        if (DigestChallengeResponse.isChallengeSupported(digestChallenge)) {
          supportedChallenges.add(digestChallenge);
        }
      }
    }

    return new DigestAuthentication(supportedChallenges);
  }

  /**
   * Creates an authentication from a number of parsed Digest challenges.
   *
   * @param challenges the digest challenges
   * @return a new {@code DigestAuthentication} object
   */
  public static DigestAuthentication fromDigestChallenges(Iterable<? extends
      DigestChallenge> challenges) {
    List<DigestChallenge> supportedChallenges = createListOfMatchingSize(challenges);
    for (DigestChallenge challenge : challenges) {
      if (DigestChallengeResponse.isChallengeSupported(challenge)) {
        supportedChallenges.add(challenge);
      }
    }
    return new DigestAuthentication(supportedChallenges);
  }

  /**
   * Creates an authentication from a parsed Digest challenge.
   *
   * @param challenge the digest challenge
   * @return a new {@code DigestAuthentication} object
   */
  public static DigestAuthentication fromDigestChallenge(DigestChallenge challenge) {
    return fromDigestChallenges(Collections.singleton(challenge));
  }

  /**
   * Internal constructor.
   *
   * @param challengesRepresentation the list of challenges, this list will not be copied but used
   *                                 in the object's internal representation
   */
  private DigestAuthentication(List<DigestChallenge> challengesRepresentation) {
    this.challenges = challengesRepresentation;
    Collections.sort(this.challenges, DEFAULT_CHALLENGE_COMPARATOR);
  }

  /**
   * Returns {@code true} if a response can be generated to any of the challenges.
   * <p>
   * If this method returns {@code false}, it could mean that:
   * <ol>
   * <li>The list of challenges is empty, or</li>
   * <li>none of the challenges are supported (see
   * {@link DigestChallengeResponse#isChallengeSupported(DigestChallenge)}).</li>
   * </ol>
   *
   * @return {@code true} if a response can be generated to any of the challenges
   */
  public boolean canRespond() {
    return response != null || !this.challenges.isEmpty();
  }

  /**
   * Filters challenges so that challenges for which the predicate returns {@code false} will
   * not be used when generating a response.
   * <p>
   * Note that if no challenges remain it will not be possible to generate a response, see
   * {@link #canRespond()}.
   * <p>
   * Calling this method multiple times will apply multiple filters. A new filter does not replace
   * an earlier filter.
   * <p>
   * This method must be called before a choice is made as to which challenge to use. Once a choice
   * has been made it cannot be changed. This means that his method cannot be called after methods
   * such as {@link #getChallengeResponse()} or {@link #getAuthorizationForRequest(String, String)}.
   *
   * @param filter a predicate to use for filtering
   * @return this object so that setters can be chained
   * @throws IllegalStateException if this method is called after a method that requires a choice
   *                               to be made regarding which of the available challenges to use:
   *                               {@link #isEntityBodyDigestRequired()},
   *                               {@link #getChallengeResponse()},
   *                               {@link #getAuthorizationForRequest(String, String)},
   *                               {@link #getAuthorizationForRequest(String, String, byte[])}.
   * @see #EXCLUDE_AUTH_INT_FILTER
   * @see #EXCLUDE_LEGACY_QOP_FILTER
   */
  public DigestAuthentication filterChallenges(Predicate<? super DigestChallenge> filter) {
    if (challenges == null) {
      throw new IllegalStateException("Cannot filter challenges after challenge has been chosen");
    }
    for (Iterator<DigestChallenge> i = challenges.iterator(); i.hasNext(); ) {
      if (!filter.apply(i.next())) {
        i.remove();
      }
    }
    return this;
  }

  /**
   * Sets the challenge ordering, which will determine which challenge that will be used if there
   * are several.
   * <p>
   * By default, challenges are sorted using {@link #DEFAULT_CHALLENGE_COMPARATOR}.
   * <p>
   * This method must be called before a choice is made as to which challenge to use. Once a choice
   * has been made it cannot be changed. This means that his method cannot be called after methods
   * such as {@link #getChallengeResponse()} or {@link #getAuthorizationForRequest(String, String)}.
   *
   * @param orderingComparator A comparator object that will be used to sort the challenges. The
   *                           challenge that will be used is the first supported challenge
   *                           according to the sort order defined by the comparator.
   * @return this object so that setters can be chained
   * @throws IllegalStateException if this method is called after a method that requires a choice
   *                               to be made regarding which of the available challenges to use:
   *                               {@link #isEntityBodyDigestRequired()},
   *                               {@link #getChallengeResponse()},
   *                               {@link #getAuthorizationForRequest(String, String)},
   *                               {@link #getAuthorizationForRequest(String, String, byte[])}.
   */
  public DigestAuthentication challengeOrdering(Comparator<? super DigestChallenge>
      orderingComparator) {
    if (challenges == null) {
      throw new IllegalStateException(
          "Cannot change challenge ordering after challenge has been chosen");
    }
    Collections.sort(this.challenges, orderingComparator);
    return this;
  }

  /**
   * Returns {@code true} if the digest of the {@code entity-body} is required to generate a
   * response to the preferred challenge.
   * <p>
   * For most challenges, setting the digest of the {@code entity-body} is optional. It is only
   * required if the only quality of protection the server accepts is {@code auth-int}.
   *
   * @return {@code true} if the digest of the {@code entity-body} must be set
   */
  public boolean isEntityBodyDigestRequired() {
    return getChallengeResponse().isEntityBodyDigestRequired();
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

  /**
   * Picks a challenge among the available challenges and generates a response to it.
   * <p>
   * The response returned references the internal representation of this instance, modifying it
   * will modify this instance. Example: Calling
   * {@link DigestChallengeResponse#username(String) username} on the response will change the value
   * returned by {@link #getUsername()}.
   *
   * @return a challenge response
   * @throws IllegalStateException if this method is called when
   *                               {@link #canRespond()} returns {@code false}, that is, none of
   *                               the available challenges are supported
   */
  public DigestChallengeResponse getChallengeResponse() {
    if (!canRespond()) {
      throw new IllegalStateException(
          "None of the provided challenges is supported, no response can be generated");
    }

    if (response == null) {
      response = DigestChallengeResponse.responseTo(challenges.iterator().next())
          .username(username)
          .password(password);
      challenges = null;
      username = password = null;
    }

    return response;
  }

  /**
   * Returns the value of <code>Authorization</code> header that can be used in a particular
   * request.
   * <p>
   * TODO document that each invocation will increase nonce count, etc
   *
   * @param requestMethod the HTTP request method, such as GET or POST.
   * @param digestUri     the {@code Request-URI} of the {@code Request-Line} of the HTTP request,
   *                      see {@link DigestChallengeResponse#digestUri(String)} for a discussion
   *                      of what to set here
   * @return an authorization string, to use in an <code>Authorization</code> header
   * @throws IllegalStateException            If this method is called when
   *                                          {@link #canRespond()} returns {@code false}, that
   *                                          is, none of the available challenges are supported
   * @throws InsufficientInformationException If this method is called when
   *                                          {@link #isEntityBodyDigestRequired()} returns
   *                                          {@code true}, that is, a response can not be generated
   *                                          without a digest of
   *                                          the request's body. See TODO
   * @throws InsufficientInformationException If username or password has not been set
   * @see DigestChallengeResponse#requestMethod(String)
   * @see DigestChallengeResponse#digestUri(String)
   * @see #getAuthorizationForRequest(String, String, byte[])
   */
  public String getAuthorizationForRequest(String requestMethod, String digestUri) {
    prepareForAuthorization();

    String result =
        getChallengeResponse().requestMethod(requestMethod).digestUri(digestUri).getHeaderValue();
    getChallengeResponse().requestMethod(null).digestUri(null).entityBody(null);
    // TODO test that ccalues above are cleared
    return result;
  }

  /**
   * Returns the value of <code>Authorization</code> header that can be used in a particular
   * request.
   * <p>
   * TODO document that each invocation will increase nonce count, etc
   * <p>
   * This method takes the request's <code>entity-body</code> as an argument. The entity body is the
   * message body after decoding any transfer encoding that might have been applied. Example:If
   * <code>Transfer-Encoding</code> is <code>gzip</code> the entity body is the unzipped message and
   * the message body is the gzipped message. Only some requests have entity bodies,
   * <code>GET</code> requests for example do not. See
   * {@link DigestChallengeResponse#entityBody(byte[])} for more details.
   * <p>
   * This method can be used for any request that has an entity body, but it is only used for
   * "quality of protection" <code>auth-int</code>. Quality of protection <code>auth-int</code>
   * requires a hash of the entity body of the message to be included in the challenge response.
   * <p>
   * TODO test
   *
   * @param requestMethod the HTTP request method, such as GET or POST.
   * @param digestUri     the {@code Request-URI} of the {@code Request-Line} of the HTTP request,
   *                      see {@link DigestChallengeResponse#digestUri(String)} for a discussion
   *                      of what to set here
   * @param entityBody    the <code>entity-body</code> of the request (see above), or {@code null}
   *                      if the request does not have an entity body
   * @return an authorization string, to use in an <code>Authorization</code> header
   * @throws IllegalStateException            If this method is called when
   *                                          {@link #canRespond()} returns {@code false}, that
   *                                          is, none of the available challenges are supported
   * @throws InsufficientInformationException If username or password has not been set
   * @see DigestChallengeResponse#requestMethod(String)
   * @see DigestChallengeResponse#digestUri(String)
   * @see DigestChallengeResponse#entityBody(byte[])
   * @see #getAuthorizationForRequest(String, String)
   * @see #isEntityBodyDigestRequired()
   */
  public String getAuthorizationForRequest(String requestMethod,
      String digestUri,
      byte[] entityBody) {
    prepareForAuthorization();

    String result = getChallengeResponse().requestMethod(requestMethod)
        .digestUri(digestUri)
        .entityBody(entityBody)
        .getHeaderValue();
    getChallengeResponse().requestMethod(null).digestUri(null).entityBody(null);
    return result;
  }

  private void prepareForAuthorization() {
    if (!firstResponse) {
      getChallengeResponse().incrementNonceCount().randomizeClientNonce();
    }
    firstResponse = false;
  }

  private static List<DigestChallenge> createListOfMatchingSize(Iterable<?> iterable) {
    List<DigestChallenge> digestChallenges;
    if (iterable instanceof Collection) {
      digestChallenges = new ArrayList<>(((Collection) iterable).size());
    } else {
      digestChallenges = new ArrayList<>();
    }
    return digestChallenges;
  }

  @Override
  public String toString() {
    return "DigestAuthentication{" +
        "challenges=" + challenges +
        ", response=" + response +
        ", username='" + getUsername() + '\'' +
        ", password=*" +
        ", firstResponse=" + firstResponse +
        '}';
  }
}
