package com.albroco.barebonesdigest;

import org.junit.Ignore;
import org.junit.Test;

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
    DigestChallenge challenge = DigestChallenge.parse("Digest " +
        "nonce=\"ad317569721cf76378c9e16549710c80\", realm=\"me@kennethreitz.com\", " +
        "algorithm=MD5, opaque=\"5ce4f90dc57064bce88fa755374de06a\", qop=\"auth\"");

    String expectedResponse = "Digest username=\"user\",realm=\"me@kennethreitz.com\"," +
        "nonce=\"ad317569721cf76378c9e16549710c80\",uri=\"/digest-auth/auth/user/passwd/MD5\"," +
        "response=\"2d0219f304214b3a7b82441820fde5b8\",cnonce=\"83365a929a0358e4\"," +
        "opaque=\"5ce4f90dc57064bce88fa755374de06a\",algorithm=MD5,qop=auth,nc=00000001";

    DigestChallengeResponse response = DigestChallengeResponse.responseTo(challenge)
        .clientNonce("83365a929a0358e4")
        .firstRequestClientNonce("83365a929a0358e4")
        .username("user")
        .password("passwd")
        .digestUri("/digest-auth/auth/user/passwd/MD5")
        .requestMethod("GET");

    assertHeadersEqual(expectedResponse, response.getHeaderValue());
  }

  /**
   * Tests that the library is compatible with httpbin v0.5, link is
   * "/digest-auth/auth/user/passwd/SHA-256".
   *
   * @see <a href="https://github.com/Runscope/httpbin">https://github.com/Runscope/httpbin</a>
   */
  @Ignore("SHA-256 not supported")
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
