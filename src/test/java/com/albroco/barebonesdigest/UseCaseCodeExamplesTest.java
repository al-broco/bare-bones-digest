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
    // Step 1. Make the request
    HttpURLConnection request = createRequest();

    // Step 2. Check to see if the response contains an authorization challenge
    if (request.getResponseCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {

      // Step 3. Create a response to the challenge
      String authenticationHeader = HttpDigest.getAuthenticationHeader(request.getHeaderFields(),
          "GET",
          "/digest-auth/auth/user/passwd",
          "user",
          "passwd");

      // Step 4. Create a new request, identical to the original one
      request = createRequest();

      // Step 5. Set the Authorization header on the request, with the challenge response
      request.setRequestProperty(DigestChallengeResponse.HTTP_HEADER_AUTHORIZATION,
          authenticationHeader);
    }

    assertEquals(200, request.getResponseCode());
  }

  @Test
  public void testReuseChallengeResponse() throws Exception {
    HttpURLConnection request = createRequest();

    if (request.getResponseCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
      DigestChallengeResponse response =
          HttpDigest.createResponseFromResponseHeaders(request.getHeaderFields());
      response.requestMethod("GET")
          .digestUri("/digest-auth/auth/user/passwd")
          .username("user")
          .password("passwd");

      request = createRequest();
      request.setRequestProperty(DigestChallengeResponse.HTTP_HEADER_AUTHORIZATION,
          response.getHeaderValue());
    }

    assertEquals(200, request.getResponseCode());
  }

  @Test
  public void testRespondToOtherChallengeTypes() throws Exception {
    HttpURLConnection request = createRequest();

    if (request.getResponseCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
      List<String> challengeStrings =
          WwwAuthenticateHeader.extractChallenges(request.getHeaderFields());

      // Check for other challenge types here

      DigestChallengeResponse response =
          HttpDigest.createResponseFromChallenges(challengeStrings);
      response.requestMethod("GET")
          .digestUri("/digest-auth/auth/user/passwd")
          .username("user")
          .password("passwd");

      request = createRequest();
      request.setRequestProperty(DigestChallengeResponse.HTTP_HEADER_AUTHORIZATION,
          response.getHeaderValue());
    }

    assertEquals(200, request.getResponseCode());
  }

  private HttpURLConnection createRequest() throws IOException {
    return (HttpURLConnection) new URL("http://httpbin.org/digest-auth/auth/user/passwd")
        .openConnection();
  }
}
