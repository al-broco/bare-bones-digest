package com.albroco.barebonesdigest;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;

import static junit.framework.Assert.assertEquals;

public class UseCaseCodeExamplesTest {

  @Before
  public void setup() {
    CookieHandler.setDefault(new CookieManager());
  }

  @Test
  public void testGenerateResponseFromHeaders() throws Exception {
    // Step 1. Create the connection
    HttpURLConnection connection = createConnection();

    // Step 2. Make the request and check to see if the response contains an authorization challenge
    if (connection.getResponseCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {

      // Step 3. Create a authentication object from the challenge...
      DigestAuthentication auth = DigestAuthentication.fromResponse(connection);
      // ...with correct credentials
      auth.username("user").password("passwd");

      // Step 4. Create a new connection, identical to the original one
      connection = createConnection();

      // Step 5. Set the Authorization header on the request, with the challenge response
      connection.setRequestProperty(DigestChallengeResponse.HTTP_HEADER_AUTHORIZATION,
          auth.getAuthorizationForRequest("GET", connection.getURL().getPath()));
    }

    assertEquals(200, connection.getResponseCode());
  }

  @Test
  public void testReuseChallengeResponse() throws Exception {
    DigestAuthentication auth = null;

    HttpURLConnection connection = createConnection();

    if (connection.getResponseCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
      auth = DigestAuthentication.fromResponse(connection).username("user").password("passwd");
      connection = createConnection();
      connection.setRequestProperty(DigestChallengeResponse.HTTP_HEADER_AUTHORIZATION,
          auth.getAuthorizationForRequest("GET", connection.getURL().getPath()));
    }

    assertEquals(200, connection.getResponseCode());

    HttpURLConnection secondRequest = createConnection();
    String get = auth.getAuthorizationForRequest("GET", connection.getURL().getPath());
    secondRequest.setRequestProperty(DigestChallengeResponse.HTTP_HEADER_AUTHORIZATION, get);

    assertEquals(200, connection.getResponseCode());
  }

  @Test
  public void testRespondToOtherChallengeTypes() throws Exception {
    HttpURLConnection connection = createConnection();

    if (connection.getResponseCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
      List<String> challengeStrings =
          WwwAuthenticateHeader.extractChallenges(connection.getHeaderFields());

      // Check for other challenge types here

      DigestAuthentication auth =
          DigestAuthentication.fromChallenges(challengeStrings).username("user").password("passwd");

      connection = createConnection();
      connection.setRequestProperty(DigestChallengeResponse.HTTP_HEADER_AUTHORIZATION,
          auth.getAuthorizationForRequest("GET", connection.getURL().getPath()));
    }

    assertEquals(200, connection.getResponseCode());
  }

  private HttpURLConnection createConnection() throws IOException {
    return (HttpURLConnection) new URL("http://httpbin.org/digest-auth/auth/user/passwd")
        .openConnection();
  }
}
