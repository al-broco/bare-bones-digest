package com.albroco.barebonesdigest.compatibility;

import com.albroco.barebonesdigest.ChallengeParseException;
import com.albroco.barebonesdigest.DigestChallenge;
import com.albroco.barebonesdigest.DigestChallengeResponse;

import org.junit.Test;

import static com.albroco.barebonesdigest.DigestTestUtils.assertHeadersEqual;

/**
 * Tests that the digest algorithm is compatible with the Passport version 0.3.2 and passport-http
 * version 0.3.0.
 * <p>
 * Server setup is something like this:
 * <pre>
 * var passport = require('passport');
 * var express = require('express');
 *
 * var app = express();
 * app.use(passport.initialize());
 * passport.serializeUser(function(user, done)   { done(null, user); });
 * passport.deserializeUser(function(user, done) { done(null, user); });
 *
 * var DigestStrategy = require('passport-http').DigestStrategy;
 *
 * passport.use(new DigestStrategy(digestConfig,
 *   function(username, done) {
 *     if (username === 'user') {
 *       return done(null, { }, "password");
 *     }
 *     return done(null, false);
 *   },
 *   function(params, done) {
 *     done(null, true)
 *   }
 * ));
 *
 * app.get('/index.html', passport.authenticate('digest'), function(req, res) {
 *   res.send('Hello World!');
 * });
 *
 * app.listen(8080);
 * </pre>
 *
 * @see <a href="http://passportjs.org/">Passport</a>
 * @see <a href="https://github.com/jaredhanson/passport-http">passport-http</a>
 */
public class NodeJsPassportCompatibilityTest {

  /**
   * Configuration: <code>{ realm: 'example.com' }</code>
   */
  @Test
  public void testQopNoneAlgorithmNoneAuthentication() throws Exception {
    // Tests an actual challenge and compares it to a correct response
    DigestChallenge challenge = DigestChallenge.parse("Digest realm=\"example.com\", " +
        "nonce=\"UbYel61i97BVTxJJvvR52Pf5RXZvFIvK\"");

    String expectedResponse = "Digest username=\"user\"," +
        "realm=\"example.com\"," +
        "nonce=\"UbYel61i97BVTxJJvvR52Pf5RXZvFIvK\"," +
        "uri=\"/index.html\"," +
        "response=\"619b5b4954460d7162d891ffd117ddf0\"";

    DigestChallengeResponse response = DigestChallengeResponse.responseTo(challenge)
        .username("user")
        .password("password")
        .digestUri("/index.html")
        .requestMethod("GET");

    assertHeadersEqual(expectedResponse, response.getHeaderValue());
  }

  /**
   * Configuration: <code>{ realm: 'example.com', algorithm: 'MD5' }</code>
   */
  @Test
  public void testQopNoneAlgorithmMd5Authentication() throws Exception {
    // Tests an actual challenge and compares it to a correct response
    DigestChallenge challenge = DigestChallenge.parse("Digest realm=\"example.com\", " +
        "nonce=\"4szhQuejBPq48n29PHDCpiEc7RhJBZB1\", algorithm=MD5");

    String expectedResponse = "Digest username=\"user\"," +
        "realm=\"example.com\"," +
        "nonce=\"4szhQuejBPq48n29PHDCpiEc7RhJBZB1\"," +
        "uri=\"/index.html\"," +
        "response=\"a94981ae7bffd3907f3523d7c82328b1\"," +
        "algorithm=MD5";

    DigestChallengeResponse response = DigestChallengeResponse.responseTo(challenge)
        .firstRequestClientNonce("6ee3363861c6c2d2")
        .clientNonce("6ee3363861c6c2d2")
        .username("user")
        .password("password")
        .digestUri("/index.html")
        .requestMethod("GET");

    assertHeadersEqual(expectedResponse, response.getHeaderValue());
  }

  /**
   * Configuration: <code>{ realm: 'example.com', algorithm: 'MD5-sess' }</code>
   * <p>
   * This configuration results in an illegal challenge.
   */
  @Test(expected = ChallengeParseException.class)
  public void testQopNoneAlgorithmMd5SessAuthentication() throws Exception {
    // Tests an actual challenge and compares it to a correct response
    DigestChallenge.parse("Digest realm=\"example.com\", " +
        "nonce=\"p9jAJJ3Xb1SeIqFcCyPxECjqR2wfa5Rn\", " +
        "algorithm=MD5-sess");
  }

  /**
   * Configuration: <code>{ realm: 'example.com', qop: 'auth' }</code>
   */
  @Test
  public void testQopAuthAlgorithmNoneAuthentication() throws Exception {
    // Tests an actual challenge and compares it to a correct response
    DigestChallenge challenge = DigestChallenge.parse("Digest realm=\"example.com\", " +
        "nonce=\"IMhIDDbBovLnM1ymXxMrJgplmbPkU83u\"," +
        " qop=\"auth\"");

    String expectedResponse = "Digest username=\"user\"," +
        "realm=\"example.com\"," +
        "nonce=\"IMhIDDbBovLnM1ymXxMrJgplmbPkU83u\"," +
        "uri=\"/index.html\"," +
        "response=\"41f9ec1de071d7e2b0e5ff412106ea60\"," +
        "cnonce=\"6ee3363861c6c2d2\"," +
        "qop=auth," +
        "nc=00000001";

    DigestChallengeResponse response = DigestChallengeResponse.responseTo(challenge)
        .firstRequestClientNonce("6ee3363861c6c2d2")
        .clientNonce("6ee3363861c6c2d2")
        .username("user")
        .password("password")
        .digestUri("/index.html")
        .requestMethod("GET");

    assertHeadersEqual(expectedResponse, response.getHeaderValue());
  }

  /**
   * Configuration: <code>{ realm: 'example.com', qop: 'auth', algorithm: 'MD5' }</code>
   */
  @Test
  public void testQopAuthAlgorithmMd5Authentication() throws Exception {
    // Tests an actual challenge and compares it to a correct response
    DigestChallenge challenge = DigestChallenge.parse("Digest realm=\"example.com\", " +
        "nonce=\"5EosphEnA8OadjK2ufuRxVLBx5a8s2uJ\", " +
        "algorithm=MD5, " +
        "qop=\"auth\"");

    String expectedResponse = "Digest username=\"user\"," +
        "realm=\"example.com\"," +
        "nonce=\"5EosphEnA8OadjK2ufuRxVLBx5a8s2uJ\"," +
        "uri=\"/index.html\"," +
        "response=\"f9a9457a70489a4fee49f2a3d89ce15f\"," +
        "cnonce=\"01c00dce79fc5018\"," +
        "algorithm=MD5," +
        "qop=auth," +
        "nc=00000001";

    DigestChallengeResponse response = DigestChallengeResponse.responseTo(challenge)
        .firstRequestClientNonce("01c00dce79fc5018")
        .clientNonce("01c00dce79fc5018")
        .username("user")
        .password("password")
        .digestUri("/index.html")
        .requestMethod("GET");

    assertHeadersEqual(expectedResponse, response.getHeaderValue());
  }


  /**
   * Configuration: <code>{ realm: 'example.com', qop: 'auth', algorithm: 'MD5-sess' }</code>
   */
  @Test
  public void testQopAuthAlgorithmMd5SessAuthentication() throws Exception {
    // Tests an actual challenge and compares it to a correct response
    DigestChallenge challenge = DigestChallenge.parse("Digest realm=\"example.com\", " +
        "nonce=\"wOAGvwo5ypydkeLZp7ESp3lXNuOHaB1y\", " +
        "algorithm=MD5-sess, qop=\"auth\"");

    String expectedResponse = "Digest username=\"user\"," +
        "realm=\"example.com\"," +
        "nonce=\"wOAGvwo5ypydkeLZp7ESp3lXNuOHaB1y\"," +
        "uri=\"/index.html\"," +
        "response=\"d847e469cafcdfa3ab866a2f75019fd0\"," +
        "cnonce=\"2959299f75296589\"," +
        "algorithm=MD5-sess," +
        "qop=auth,nc=00000001";

    DigestChallengeResponse response = DigestChallengeResponse.responseTo(challenge)
        .firstRequestClientNonce("2959299f75296589")
        .clientNonce("2959299f75296589")
        .username("user")
        .password("password")
        .digestUri("/index.html")
        .requestMethod("GET");

    assertHeadersEqual(expectedResponse, response.getHeaderValue());
  }
}
