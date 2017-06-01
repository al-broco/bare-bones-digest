/**
 * An implementation of the HTTP Digest authentication scheme for Android.
 *
 * With a small effort you can use it to get HTTP digest working with HttpURLConnection or any
 * other HTTP stack.
 * <p>
 * Here is an example of how to make a request and respond to a Digest challenge:
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
 *     // Step 5. Create a new connection, identical to the original one...
 *     connection = (HttpURLConnection) url.openConnection();
 *     // ...and set the Authorization header on the request, with the challenge response
 *     connection.setRequestProperty(DigestChallengeResponse.HTTP_HEADER_AUTHORIZATION,
 *     auth.getAuthorizationForRequest("GET", connection.getURL().getPath()));
 * }
 * }</pre></blockquote>
 *
 * {@link com.albroco.barebonesdigest.DigestAuthentication} is the main entry point of the API,
 * read the documentation for more examples. Some other useful classes include:
 * <ul>
 * <li>{@link com.albroco.barebonesdigest.WwwAuthenticateHeader} which can be used to parse
 * challenges from WWW-Authenticate headers, including challenges of other types than Digest.</li>
 * <li>{@link com.albroco.barebonesdigest.DigestChallenge} which provides functionality for
 * parsing digest challenges.</li>
 * <li>{@link com.albroco.barebonesdigest.DigestChallengeResponse} which provides functionality
 * for generating responses to digest challenges.</li>
 * </ul>
 */
package com.albroco.barebonesdigest;