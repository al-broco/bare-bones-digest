package com.albroco.barebonesdigest;

import org.junit.Ignore;
import org.junit.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;

/**
 * Tests the example from <a href="https://tools.ietf.org/html/rfc2617#section-3.5">Section 3.5 of
 * RFC 2069</a>.
 */
public class Rfc2617ExamplesTest {

  @Ignore("Implementation add algorithm=MD5 even if challenge does not specify algorithm")
  @Test
  public void testExampleFromRfc2069() throws Exception {
    DigestChallenge challenge = DigestChallenge.parse("Digest\n" +
        "                 realm=\"testrealm@host.com\",\n" +
        "                 qop=\"auth,auth-int\",\n" +
        "                 nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\n" +
        "                 opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"");

    String expectedResponse = "Digest username=\"Mufasa\",\n" +
        "                 realm=\"testrealm@host.com\",\n" +
        "                 nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\n" +
        "                 uri=\"/dir/index.html\",\n" +
        "                 qop=auth,\n" +
        "                 nc=00000001,\n" +
        "                 cnonce=\"0a4f113b\",\n" +
        "                 response=\"6629fae49393a05397450978507c4ef1\",\n" +
        "                 opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";

    DigestChallengeResponse response = DigestChallengeResponse.responseTo(challenge)
        .clientNonce("0a4f113b")
        .firstRequestClientNonce("0a4f113b")
        .username("Mufasa")
        .password("Circle Of Life")
        .digestUri("/dir/index.html")
        .requestMethod("GET");

    assertHeadersEqual(expectedResponse, response.getHeaderValue());
  }

  private void assertHeadersEqual(String expectedHeader, String generatedHeader) {
    assertTrue(generatedHeader.startsWith("Digest "));

    // Remove redundant newlines and spaces
    expectedHeader =
        Pattern.compile("\n *", Pattern.MULTILINE).matcher(expectedHeader).replaceAll("");

    Set<String> expectedSubstrings =
        new HashSet<>(Arrays.asList(expectedHeader.substring("Digest ".length()).split(",")));
    Set<String> actualSubstrings =
        new HashSet<>(Arrays.asList(generatedHeader.substring("Digest ".length()).split(",")));

    assertEquals(expectedSubstrings, actualSubstrings);
  }
}
