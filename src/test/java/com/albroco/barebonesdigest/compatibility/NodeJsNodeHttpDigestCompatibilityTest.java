package com.albroco.barebonesdigest.compatibility;

import com.albroco.barebonesdigest.DigestChallenge;
import com.albroco.barebonesdigest.DigestChallengeResponse;

import org.junit.Test;

import static com.albroco.barebonesdigest.DigestTestUtils.assertHeadersEqual;

/**
 * Tests that the digest algorithm is compatible with the module <code>node-http-digest</code>
 * version 0.1.0.
 *
 * @see <a href="https://github.com/thedjinn/node-http-digest">node-http-digest</a>
 */
public class NodeJsNodeHttpDigestCompatibilityTest {

  /**
   * Tests that the library is compatible with a server implemented as:
   *
   * <pre>
   * {@code
   * var httpdigest = require('http-digest');
   *
   * // simple secured web server, unauthenticated requests are not allowed
   * httpdigest.createServer("theuser", "thepass", function(request, response) {
   * response.writeHead(200, {'Content-Type': 'text/html'});
   * response.end("<h1>Secure zone!</h1>");
   * }).listen(8000);
   * }</pre>
   */
  @Test
  public void testQopAuthAuthentication() throws Exception {
    // Tests an actual challenge and compares it to a correct response
    DigestChallenge challenge = DigestChallenge.parse("Digest realm=\"node-http-digest\", " +
        "qop=\"auth\", " +
        "nonce=\"f50dffb4d7abd8ef3d91bb20ff7fd3a3\", " +
        "opaque=\"666ec9a92102ba3d3add863392842bfa\"");

    String expectedResponse = "Digest username=\"theuser\"," +
        "realm=\"node-http-digest\"," +
        "nonce=\"f50dffb4d7abd8ef3d91bb20ff7fd3a3\"," +
        "uri=\"/index.html\"," +
        "response=\"cae25dac1d753c271b9e8d7e515357a8\"," +
        "cnonce=\"da90c03022411abb\"," +
        "opaque=\"666ec9a92102ba3d3add863392842bfa\"," +
        "qop=auth,nc=00000001";

    DigestChallengeResponse response = DigestChallengeResponse.responseTo(challenge)
        .clientNonce("da90c03022411abb")
        .firstRequestClientNonce("da90c03022411abb")
        .username("theuser")
        .password("thepass")
        .digestUri("/index.html")
        .requestMethod("GET");

    assertHeadersEqual(expectedResponse, response.getHeaderValue());
  }
}
