// Copyright (c) 2016 Petter Wintzell

package com.albroco.barebonesdigest.compatibility;

import com.albroco.barebonesdigest.DigestAuthentication;
import com.albroco.barebonesdigest.DigestChallenge;
import com.albroco.barebonesdigest.DigestChallengeResponse;

import org.junit.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.albroco.barebonesdigest.DigestTestUtils.assertHeadersEqual;

/**
 * Tests that the digest algorithm is compatible with httpbin.
 * <p>
 * Note that qop auth-int is not tested since httpbin only allows GET and there is no entity-body
 * for GET requests so no valid auth-int request can be made as I understand it.
 *
 * @see <a href="https://github.com/Runscope/httpbin">https://github.com/Runscope/httpbin</a>
 * @see <a href="http://httpbin.org/">http://httpbin.org/</a>
 */
public class HttpBinCompatibilityTest {

  /**
   * Tests that the library is compatible with httpbin v0.5, link is
   * "/digest-auth/auth/user/passwd/MD5".
   *
   * @see <a href="https://github.com/Runscope/httpbin">https://github.com/Runscope/httpbin</a>
   */
  @Test
  public void testQopAuthAuthenticationMd5Algorithm() throws Exception {
    // Tests an actual challenge and compares it to a correct response
    Map<String, List<String>> responseHeaders = new HashMap<String, List<String>>() {{
      put("WWW-Authenticate", Arrays.asList("Digest nonce=\"fa670d6814c95916137b4a3282f9a4b3\", " +
          "opaque=\"7c835eb339cfcf0906ef3c9c9308d345\", realm=\"me@kennethreitz.com\", " +
          "qop=auth"));

    }};

    DigestAuthentication auth = DigestAuthentication.fromResponseHeaders(responseHeaders);

    String expected1stChallengeResp = "Digest username=\"user\",realm=\"me@kennethreitz.com\"," +
        "nonce=\"fa670d6814c95916137b4a3282f9a4b3\",uri=\"/digest-auth/auth/user/passwd\"," +
        "response=\"f1bd8482a9048d39e71a2261710d899e\",cnonce=\"5cfa3f5df37a1032\"," +
        "opaque=\"7c835eb339cfcf0906ef3c9c9308d345\",qop=auth,nc=00000001";

    auth.username("user")
        .password("passwd")
        .getChallengeResponse()
        .clientNonce("5cfa3f5df37a1032")
        .firstRequestClientNonce("5cfa3f5df37a1032");

    String actual1stChallengeResp =
        auth.getAuthorizationForRequest("GET", "/digest-auth/auth/user/passwd");

    assertHeadersEqual(expected1stChallengeResp, actual1stChallengeResp);

    String expected2ndChallengeResp = "Digest username=\"user\",realm=\"me@kennethreitz.com\"," +
        "nonce=\"fa670d6814c95916137b4a3282f9a4b3\",uri=\"/digest-auth/auth/user/passwd\"," +
        "response=\"7ab68f8d0f58dff1118b683e286dbab6\",cnonce=\"5f8b5f70805c6676\"," +
        "opaque=\"7c835eb339cfcf0906ef3c9c9308d345\",qop=auth,nc=00000002";

    auth.getChallengeResponse().clientNonce("5f8b5f70805c6676");

    String actual2ndChallengeResp =
        auth.getAuthorizationForRequest("GET", "/digest-auth/auth/user/passwd");

    assertHeadersEqual(expected2ndChallengeResp, actual2ndChallengeResp);
  }

  /**
   * Tests that the library is compatible with httpbin (version not known), link is
   * "/digest-auth/auth-int/user/passwd/MD5".
   *
   * @see <a href="https://github.com/Runscope/httpbin">https://github.com/Runscope/httpbin</a>
   */
  @Test
  public void testQopAuthIntAuthenticationMd5Algorithm() throws Exception {
    // Tests an actual challenge and compares it to a correct response
    Map<String, List<String>> responseHeaders = new HashMap<String, List<String>>() {{
      put("WWW-Authenticate", Arrays.asList("Digest nonce=\"5fa47e6f0ea32457ddd5bb8f2e216744\", " +
          "opaque=\"57114b3e58fe9e11e27c986a6ace567b\", realm=\"me@kennethreitz.com\", " +
          "qop=auth-int"));

    }};

    DigestAuthentication auth = DigestAuthentication.fromResponseHeaders(responseHeaders);

    String expected1stChallengeResp = "Digest username=\"user\",realm=\"me@kennethreitz.com\"," +
        "nonce=\"5fa47e6f0ea32457ddd5bb8f2e216744\"," +
        "uri=\"/digest-auth/auth-int/user/passwd\"," +
        "response=\"068ff0565c5fa972e74c80c0a6a2148f\",cnonce=\"87ffb3ed6c945edd\"," +
        "opaque=\"57114b3e58fe9e11e27c986a6ace567b\",qop=auth-int,nc=00000001";

    auth.username("user")
        .password("passwd")
        .getChallengeResponse()
        .clientNonce("87ffb3ed6c945edd")
        .firstRequestClientNonce("87ffb3ed6c945edd");

    String actual1stChallengeResp =
        auth.getAuthorizationForRequest("GET", "/digest-auth/auth-int/user/passwd");

    assertHeadersEqual(expected1stChallengeResp, actual1stChallengeResp);

    String expected2ndChallengeResp = "Digest username=\"user\",realm=\"me@kennethreitz.com\"," +
        "nonce=\"5fa47e6f0ea32457ddd5bb8f2e216744\"," +
        "uri=\"/digest-auth/auth-int/user/passwd\"," +
        "response=\"13ba2a7a7a545671a7223dc06189853f\",cnonce=\"cda594d5958d55a2\"," +
        "opaque=\"57114b3e58fe9e11e27c986a6ace567b\",qop=auth-int,nc=00000002";

    auth.getChallengeResponse().clientNonce("cda594d5958d55a2");

    String actual2ndChallengeResp =
        auth.getAuthorizationForRequest("GET", "/digest-auth/auth-int/user/passwd");

    assertHeadersEqual(expected2ndChallengeResp, actual2ndChallengeResp);
  }

  /**
   * Tests that the library is compatible with httpbin v0.5, link is
   * "/digest-auth/auth/user/passwd/SHA-256".
   *
   * @see <a href="https://github.com/Runscope/httpbin">https://github.com/Runscope/httpbin</a>
   */
  @Test
  public void testQopAuthAuthenticationSha256Algorithm() throws Exception {
    // Tests an actual challenge and compares it to a correct response
    DigestChallenge challenge = DigestChallenge.parse("Digest " +
        "nonce=\"ce63ed7e494c4331f2e48c4e17670804\", realm=\"me@kennethreitz.com\", " +
        "algorithm=SHA-256, opaque=\"0ecec678bb98e4f53a70fc90539e64e0\", qop=\"auth\"");

    String expectedResponse = "Digest username=\"user\",realm=\"me@kennethreitz.com\"," +
        "nonce=\"ce63ed7e494c4331f2e48c4e17670804\"," +
        "uri=\"/digest-auth/auth/user/passwd/SHA-256\"," +
        "response=\"91a21d53724b7aedafb7188eae59d5af01d23c7ded604f5186c23f674cc24f9c\"," +
        "cnonce=\"8b0d1fbc049d8c82\",opaque=\"0ecec678bb98e4f53a70fc90539e64e0\"," +
        "algorithm=SHA-256,qop=auth,nc=00000001";

    DigestChallengeResponse response = DigestChallengeResponse.responseTo(challenge)
        .clientNonce("8b0d1fbc049d8c82")
        .firstRequestClientNonce("8b0d1fbc049d8c82")
        .username("user")
        .password("passwd")
        .digestUri("/digest-auth/auth/user/passwd/SHA-256")
        .requestMethod("GET");

    assertHeadersEqual(expectedResponse, response.getHeaderValue());
  }

  /**
   * Tests that the library is compatible with httpbin at
   * <a href="http://httpbin.org/digest-auth/auth/user/passwd">
   * http://httpbin.org/digest-auth/auth/user/passwd</a>
   */
  @Test
  public void testLegacyVersionQopAuthAuthentication() throws Exception {
    // Tests an actual challenge and compares it to a correct response
    DigestChallenge challenge = DigestChallenge.parse("Digest " +
        "nonce=\"b1a3714cecf3dd591cbb4d8088007b1a\", opaque=\"69290c04602447fcbd7d5c1eee8c56fb\"," +
        " realm=\"me@kennethreitz.com\", qop=auth");

    String expectedResponse = "Digest username=\"user\",realm=\"me@kennethreitz.com\"," +
        "nonce=\"b1a3714cecf3dd591cbb4d8088007b1a\",uri=\"/digest-auth/auth/user/passwd\"," +
        "response=\"a2afb5482fc9a20d57d3c6c266ded420\",cnonce=\"f40f582c9763308e\"," +
        "opaque=\"69290c04602447fcbd7d5c1eee8c56fb\",qop=auth,nc=00000001";

    DigestChallengeResponse response = DigestChallengeResponse.responseTo(challenge)
        .clientNonce("f40f582c9763308e")
        .firstRequestClientNonce("f40f582c9763308e")
        .username("user")
        .password("passwd")
        .digestUri("/digest-auth/auth/user/passwd")
        .requestMethod("GET");

    assertHeadersEqual(expectedResponse, response.getHeaderValue());
  }
}
