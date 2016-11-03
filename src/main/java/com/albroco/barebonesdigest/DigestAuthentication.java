// Copyright (c) 2016 Petter Wintzell

package com.albroco.barebonesdigest;

import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.albroco.barebonesdigest.DigestChallenge.QualityOfProtection;
import static com.albroco.barebonesdigest.DigestChallenge.QualityOfProtection.AUTH;
import static com.albroco.barebonesdigest.DigestChallenge.QualityOfProtection.AUTH_INT;
import static com.albroco.barebonesdigest.DigestChallenge.QualityOfProtection
    .UNSPECIFIED_RFC2069_COMPATIBLE;

/**
 * Utility class with high-level methods for parsing challenges and generating responses.
 * <p>
 * Create an instance of this class once a digest challenge is received. Use the instance to respond
 * to the challenge and to authenticate future requests.
 *
 * <h1>Basic usage</h1>
 *
 * Here is a basic example of how to make a request using {@code HttpURLConnection} and, in case
 * of a challenge, respond to the challenge:
 *
 * <blockquote><pre>{@code
 * // Step 1. Create the connection
 * URL url = new URL("http://httpbin.org/digest-auth/auth/user/passwd");
 * HttpURLConnection connection = (HttpURLConnection) url.openConnection();
 *
 * // Step 2. Make the request and check to see if the response contains an authorization challenge
 * if (connection.getResponseCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
 *     // Step 3. Create a authentication object from the challenge...
 *     DigestAuthentication auth = DigestAuthentication.fromResponse(connection);
 *     // ...with correct credentials
 *     auth.username("user").password("passwd");
 *
 *     // Step 4 (Optional). Check if the challenge was a digest challenge of a supported type
 *     if (!auth.canRespond()) {
 *         // No digest challenge or a challenge of an unsupported type - do something else or fail
 *         return;
 *     }
 *
 *     // Step 5. Create a new connection, identical to the original one.
 *     connection = (HttpURLConnection) url.openConnection();
 *     // ...and set the Authorization header on the request, with the challenge response
 *     connection.setRequestProperty(DigestChallengeResponse.HTTP_HEADER_AUTHORIZATION,
 *         auth.getAuthorizationForRequest("GET", connection.getURL().getPath()));
 * }
 * }</pre></blockquote>
 *
 * <h1>Reuse challenges for future requests</h1>
 *
 * The {@code DigestAuthentication} object can be used to authenticate future requests. This removes
 * the need of making the request twice (once for the challenge and once for the actual request):
 *
 * <blockquote><pre>{@code
 * HttpURLConnection anotherConnection = (HttpURLConnection) url.openConnection();
 * anotherConnection.setRequestProperty(DigestChallengeResponse.HTTP_HEADER_AUTHORIZATION,
 *     auth.getAuthorizationForRequest("GET", initialConnection.getURL().getPath()));
 * }</pre></blockquote>
 *
 * <h1>Supporting other authentication schemes</h1>
 *
 * To support other authentication schemes than Digest, you can use {@link WwwAuthenticateHeader} to
 * parse <code>WWW-Authenticate</code> headers into individual challenges. Example:
 *
 * <blockquote><pre>{@code
 * if (connection.getResponseCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
 *     // Parse the headers and extract challenges, this will return challenges of all types
 *     List<String> challengeStrings =
 *         WwwAuthenticateHeader.extractChallenges(connection.getHeaderFields());
 *
 *     // Check the challenges and act on them...
 *
 *     // ...or pass them to DigestAuthentication to handle digest challenges:
 *     DigestAuthentication auth =
 *         DigestAuthentication.fromChallenges(challengeStrings).username("user").password
 *         ("passwd");
 * }
 * }</pre></blockquote>
 *
 * <h1>Overriding which challenge is used for the response</h1>
 *
 * If the HTTP response from the server contains more then one Digest challenge, one will be chosen
 * when generating the challenge response. Use {@link #challengeOrdering(Comparator)} to define
 * which challenge is preferred.
 *
 * <h1>Supporting <code>auth-int</code> quality of protection</h1>
 *
 * The <code>auth-int</code> quality of protection requires a digest of the entity body of the
 * request to be included in the challenge response. To be compatible with servers that require
 * <code>auth-int</code> quality of protection, use
 * {@link #getAuthorizationForRequest(String, String, byte[])} instead of
 * {@link #getAuthorizationForRequest(String, String)}.
 * <p>
 * <code>auth-int</code> is uncommon. It cannot be used with HTTP requests that does not include a
 * body, such as <code>GET</code>. Some server implementations accept <code>auth-int</code>
 * authentication for such requests as well, using a zero-length entity body.
 *
 * <h1>Concurrency</h1>
 *
 * This class is thread safe, read and write operations are synchronized.
 */
public final class DigestAuthentication {
  private List<DigestChallenge> challenges;
  private DigestChallengeResponse response;
  private String username;
  private String password;

  /**
   * Default comparator used when comparing which challenge to use when there is more than one to
   * choose from.
   * <p>
   * Challenges that are not supported are ordered last.
   * <p>
   * Challenges that use digest algorithms <code>SHA-256</code> or <code>SHA-256-sess</code> are
   * always preferred over challenges that use <code>MD5</code>, <code>MD5-sess</code>, or does
   * not specify an algorithm.
   * <p>
   * If the rules above are not enough challenges are ordered according to the following, from
   * most preferred to least preferred:
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
   * </ol>
   */
  public static final Comparator<DigestChallenge> DEFAULT_CHALLENGE_COMPARATOR =
      new Comparator<DigestChallenge>() {
        private final Collection<QualityOfProtection> AUTH_AUTH_INT_QOPS =
            EnumSet.of(AUTH, AUTH_INT);

        @Override
        public int compare(DigestChallenge lhs, DigestChallenge rhs) {
          int result = supportScore(rhs) - supportScore(lhs);
          if (result == 0) {
            result = algorithmScore(rhs) - algorithmScore(lhs);
          }
          if (result == 0) {
            result = miscScore(rhs) - miscScore(lhs);
          }

          return result;
        }

        private int supportScore(DigestChallenge challenge) {
          if (DigestChallengeResponse.isChallengeSupported(challenge)) {
            return 0;
          }

          return -1;
        }

        private int algorithmScore(DigestChallenge challenge) {
          if (challenge.getAlgorithm().equals("SHA-256") ||
              challenge.getAlgorithm().equals("SHA-256-sess")) {
            return 0;
          }

          return -1;
        }

        private int miscScore(DigestChallenge challenge) {
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

          return -4;
        }
      };

  /**
   * Creates an authentication by reading response headers from an {@code HttpURLConnection} object.
   *
   * @param connection the connection
   * @return a new {@code DigestAuthentication} object
   * @throws ChallengeParseException if challenges could not be parsed
   */
  public static DigestAuthentication fromResponse(HttpURLConnection connection) throws
      ChallengeParseException {
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
   * @throws ChallengeParseException if challenges could not be parsed
   */
  public static <T extends Iterable<String>> DigestAuthentication fromResponseHeaders(Map<String,
      T> headers) throws ChallengeParseException {
    return fromChallenges(WwwAuthenticateHeader.extractChallenges(headers));
  }

  /**
   * Creates an authentication from a number of <code>WWW-Authenticate</code> headers.
   *
   * @param wwwAuthenticateHeaders the <code>WWW-Authenticate</code> headers
   * @return a new {@code DigestAuthentication} object
   * @throws ChallengeParseException if challenges could not be parsed
   */
  public static DigestAuthentication fromWwwAuthenticateHeaders(Iterable<String>
      wwwAuthenticateHeaders) throws ChallengeParseException {
    return fromChallenges(WwwAuthenticateHeader.extractChallenges(wwwAuthenticateHeaders));
  }

  /**
   * Creates an authentication from a single <code>WWW-Authenticate</code> header.
   *
   * @param wwwAuthenticateHeader the <code>WWW-Authenticate</code> header
   * @return a new {@code DigestAuthentication} object
   * @throws ChallengeParseException if challenges could not be parsed
   */
  public static DigestAuthentication fromWwwAuthenticateHeader(String wwwAuthenticateHeader)
      throws ChallengeParseException {
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
   * @throws ChallengeParseException if challenges could not be parsed
   */
  public static DigestAuthentication fromChallenges(Iterable<String> challenges) throws
      ChallengeParseException {
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
   * @return this object
   * @throws IllegalStateException if this method is called after a method that requires a choice
   *                               to be made regarding which of the available challenges to use:
   *                               {@link #isEntityBodyDigestRequired()},
   *                               {@link #getChallengeResponse()},
   *                               {@link #getAuthorizationForRequest(String, String)},
   *                               {@link #getAuthorizationForRequest(String, String, byte[])}.
   */
  public synchronized DigestAuthentication challengeOrdering(Comparator<? super DigestChallenge>
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
  public synchronized boolean isEntityBodyDigestRequired() {
    return getChallengeResponse().isEntityBodyDigestRequired();
  }

  /**
   * Sets the username to use for authentication.
   *
   * @param username the username
   * @return this object
   * @see #getUsername()
   * @see <a href="https://tools.ietf.org/html/rfc2617#section-3.2.2">Section 3.2.2 of RFC 2617</a>
   */
  public synchronized DigestAuthentication username(String username) {
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
  public synchronized String getUsername() {
    if (response != null) {
      return response.getUsername();
    }
    return username;
  }

  /**
   * Sets the password to use for authentication.
   *
   * @param password the password
   * @return this object
   * @see #getPassword()
   */
  public synchronized DigestAuthentication password(String password) {
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
  public synchronized String getPassword() {
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
  public synchronized DigestChallengeResponse getChallengeResponse() {
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
   * The first time an <code>Authorization</code> header is generated nonce count will be set to 1.
   * Each subsequent call will increase the nonce count by one. The server expects the nonce count
   * to increase by exactly one for each request, so do not call this method unless you intend to
   * use the result in a request.
   * <p>
   * Calling this method has the same effect as calling
   * {@link #getAuthorizationForRequest(String, String, byte[])} with a zero-length byte array for
   * {@code entityBody}.
   *
   * @param requestMethod the HTTP request method, such as GET or POST.
   * @param digestUri     the {@code Request-URI} of the {@code Request-Line} of the HTTP request,
   *                      see {@link DigestChallengeResponse#digestUri(String)} for a discussion
   *                      of what to set here
   * @return an authorization string, to use in an <code>Authorization</code> header
   * @throws IllegalStateException            If this method is called when
   *                                          {@link #canRespond()} returns {@code false}, that
   *                                          is, none of the available challenges are supported
   * @throws InsufficientInformationException If username or password has not been set
   * @see DigestChallengeResponse#requestMethod(String)
   * @see DigestChallengeResponse#digestUri(String)
   * @see #getAuthorizationForRequest(String, String, byte[])
   */
  public synchronized String getAuthorizationForRequest(String requestMethod, String digestUri) {
    return getAuthorizationForRequest(requestMethod, digestUri, new byte[0]);
  }

  /**
   * Returns the value of <code>Authorization</code> header that can be used in a particular
   * request.
   * <p>
   * This method takes the request's <code>entity-body</code> as an argument. The entity body is the
   * message body after decoding any transfer encoding that might have been applied. Example: If
   * <code>Transfer-Encoding</code> is <code>gzip</code> the entity body is the unzipped message and
   * the message body is the gzipped message. Only some requests have entity bodies,
   * <code>GET</code> requests for example do not. See
   * {@link DigestChallengeResponse#entityBody(byte[])} for more details.
   * <p>
   * This method can be used for any request, but the entity-body is only used for "quality of
   * protection" <code>auth-int</code>. Quality of protection <code>auth-int</code> requires a
   * hash of the entity body of the message to be included in the challenge response.
   * <p>
   * Not all requests have an <code>entity-body</code>, for example, GET requests do not. Some
   * servers accept an <code>entity-body</code> of zero length for such requests (even though it is
   * strictly speaking not correct to do so).
   * <p>
   * The first time an <code>Authorization</code> header is generated nonce count will be set to 1.
   * Each subsequent call will increase the nonce count by one. The server expects the nonce count
   * to increase by exactly one for each request, so do not call this method unless you intend to
   * use the result in a request.
   *
   * @param requestMethod the HTTP request method, such as GET or POST.
   * @param digestUri     the {@code Request-URI} of the {@code Request-Line} of the HTTP request,
   *                      see {@link DigestChallengeResponse#digestUri(String)} for a discussion
   *                      of what to set here
   * @param entityBody    the <code>entity-body</code> of the request (see above)
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
  public synchronized String getAuthorizationForRequest(String requestMethod,
      String digestUri,
      byte[] entityBody) {
    String result = getChallengeResponse().requestMethod(requestMethod)
        .digestUri(digestUri)
        .entityBody(entityBody)
        .getHeaderValue();
    getChallengeResponse().requestMethod(null)
        .digestUri(null)
        .entityBody(new byte[0])
        .incrementNonceCount()
        .randomizeClientNonce();
    return result;
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
  public synchronized String toString() {
    return "DigestAuthentication{" +
        "challenges=" + challenges +
        ", response=" + response +
        ", username='" + getUsername() + '\'' +
        ", password=*" +
        '}';
  }
}
