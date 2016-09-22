package com.albroco.barebonesdigest.compatibility;

import com.albroco.barebonesdigest.DigestChallenge;
import com.albroco.barebonesdigest.DigestChallengeResponse;

import org.junit.Test;

import static com.albroco.barebonesdigest.DigestTestUtils.assertHeadersEqual;

/**
 * Tests that the digest algorithm is compatible with the module <code>mod_auth_digest</code> of
 * Apache HTTP server 2.4.
 * @see <a href="http://httpd.apache.org/docs/2.4/mod/mod_auth_digest.html">
 *   Apache Module mod_auth_digest</a>
 */
public class Apache2_4DigestModuleCompatibilityTest {

  /**
   * Tests that the library is compatible with Apache running the following configuration:
   * <pre>
   * AuthType Digest
   * AuthName "bare-bones-digest test"
   * AuthDigestAlgorithm MD5
   * AuthDigestQop none
   * Require valid-user
   * [...]
   * </pre>
   */
  @Test
  public void testRfc2069Authentication() throws Exception {
    // Tests an actual challenge and compares it to a correct response
    DigestChallenge challenge = DigestChallenge.parse("Digest realm=\"bare-bones-digest test\", " +
        "nonce=\"EqiV7xs9BQA=3390f0b69ef6af6fef61d201c182a5b9111494ed\", algorithm=MD5");

    String expectedResponse = "Digest username=\"albroco\",realm=\"bare-bones-digest test\"," +
        "nonce=\"EqiV7xs9BQA=3390f0b69ef6af6fef61d201c182a5b9111494ed\",uri=\"/index.html\"," +
        "response=\"1efd5f060aff70006d7b6ef13faa71b3\",algorithm=MD5";

    DigestChallengeResponse response = DigestChallengeResponse.responseTo(challenge)
        .username("albroco")
        .password("CircleOfLife")
        .digestUri("/index.html")
        .requestMethod("GET");

    assertHeadersEqual(expectedResponse, response.getHeaderValue());
  }

  /**
   * Tests that the library is compatible with Apache running the following configuration:
   * <pre>
   * AuthType Digest
   * AuthName "bare-bones-digest test"
   * AuthDigestAlgorithm MD5
   * AuthDigestQop auth
   * Require valid-user
   * [...]
   * </pre>
   */
  @Test
  public void testQopAuthAuthentication() throws Exception {
    // Tests an actual challenge and compares it to a correct response
    DigestChallenge challenge = DigestChallenge.parse("Digest realm=\"bare-bones-digest test\", " +
        "nonce=\"+KaaKhw9BQA=cbf7cb8e6d97628b423628326aabe17349cfe834\", algorithm=MD5, " +
        "qop=\"auth\"");

    String expectedResponse = "Digest username=\"albroco\",realm=\"bare-bones-digest test\"," +
        "nonce=\"+KaaKhw9BQA=cbf7cb8e6d97628b423628326aabe17349cfe834\",uri=\"/index.html\"," +
        "response=\"d679dfffa90470b87b32f946a67eb850\",cnonce=\"d0b163a6678da9dc\",algorithm=MD5," +
        "qop=auth,nc=00000001";

    DigestChallengeResponse response = DigestChallengeResponse.responseTo(challenge)
        .clientNonce("d0b163a6678da9dc")
        .firstRequestClientNonce("d0b163a6678da9dc")
        .username("albroco")
        .password("CircleOfLife")
        .digestUri("/index.html")
        .requestMethod("GET");

    assertHeadersEqual(expectedResponse, response.getHeaderValue());
  }
}
