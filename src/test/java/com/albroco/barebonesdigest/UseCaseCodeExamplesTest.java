// Copyright (c) 2016 Petter Wintzell

package com.albroco.barebonesdigest;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.io.IOException;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;

import static junit.framework.Assert.assertEquals;

/**
 * Tests that the code from the code examples work.
 * <p>
 * Note: These are not unit tests since they are dependent on an external resource. By default,
 * they are all disabled.
 */
@Ignore("Dependent on an external resource (remote server)")
public class UseCaseCodeExamplesTest {

  @Before
  public void setup() {
    CookieHandler.setDefault(new CookieManager());
  }

  @Test
  public void testGenerateResponseFromHeaders() throws Exception {
    // Step 1. Create the connection
    URL url = new URL("http://httpbin.org/digest-auth/auth/user/passwd");
    HttpURLConnection connection = (HttpURLConnection) url.openConnection();

    // Step 2. Make the request and check to see if the response contains an authorization challenge
    if (connection.getResponseCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
      // Step 3. Create a authentication object from the challenge...
      DigestAuthentication auth = DigestAuthentication.fromResponse(connection);
      // ...with correct credentials
      auth.username("user").password("passwd");

      // Step 4 (Optional). Check if the challenge was a digest challenge of a supported type
      if (!auth.canRespond()) {
        // No digest challenge or a challenge of an unsupported type! Do something else or fail
        return;
      }

      // Step 5. Create a new connection, identical to the original one.
      connection = (HttpURLConnection) url.openConnection();
      // ...and set the Authorization header on the request, with the challenge response
      connection.setRequestProperty(DigestChallengeResponse.HTTP_HEADER_AUTHORIZATION,
          auth.getAuthorizationForRequest("GET", connection.getURL().getPath()));
    }

    assertEquals(200, connection.getResponseCode());
  }

  @Test
  public void testReuseChallengeResponse() throws Exception {
    DigestAuthentication auth = null;

    URL url = new URL("http://httpbin.org/digest-auth/auth/user/passwd");
    HttpURLConnection initialConnection = (HttpURLConnection) url.openConnection();
    if (initialConnection.getResponseCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
      auth = DigestAuthentication.fromResponse(initialConnection);
      auth.username("user").password("passwd");
      initialConnection = (HttpURLConnection) url.openConnection();
      initialConnection.setRequestProperty(DigestChallengeResponse.HTTP_HEADER_AUTHORIZATION,
          auth.getAuthorizationForRequest("GET", initialConnection.getURL().getPath()));
    }

    assertEquals(200, initialConnection.getResponseCode());

    HttpURLConnection anotherConnection = (HttpURLConnection) url.openConnection();
    anotherConnection.setRequestProperty(DigestChallengeResponse.HTTP_HEADER_AUTHORIZATION,
        auth.getAuthorizationForRequest("GET", initialConnection.getURL().getPath()));

    assertEquals(200, anotherConnection.getResponseCode());
  }

  @Test
  public void testRespondToOtherChallengeTypes() throws Exception {
    HttpURLConnection connection = createConnection();

    if (connection.getResponseCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
      // Parse the headers and extract challenges, this will return challenges of all types
      List<String> challengeStrings =
          WwwAuthenticateHeader.extractChallenges(connection.getHeaderFields());

      // Check the challenges and act on them...

      // ...or pass them to DigestAuthentication to handle digest challenges:
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
