package org.barebonesdigest;

import org.junit.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;

public class DigestChallengeResponseTest {
  @Test
  public void testExampleFromRfc2617() throws Exception {
    // The example below is from Section 3.5 of RC 2617,
    // https://tools.ietf.org/html/rfc2617#section-3.5

    String EXAMPLE = "Digest username=\"Mufasa\"," +
        "realm=\"testrealm@host.com\"," +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"," +
        "uri=\"/dir/index.html\"," +
        "qop=auth," +
        "nc=00000001," +
        "cnonce=\"0a4f113b\"," +
        "response=\"6629fae49393a05397450978507c4ef1\"," +
        "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";

    DigestChallengeResponse response = new DigestChallengeResponse().username("Mufasa")
        .password("Circle Of Life")
        .quotedRealm("\"testrealm@host.com\"")
        .quotedNonce("\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"")
        .digestUri("/dir/index.html")
        .requestMethod("GET")
        .nonceCount(1)
        .clientNonce("0a4f113b")
        .quotedOpaque("\"5ccc069c403ebaf9f0171e9517f40e41\"");

    String generatedHeader = response.getHeaderValue();

    assertTrue(generatedHeader.startsWith("Digest "));

    Set<String> expectedSubstrings = new HashSet<>(Arrays.asList(EXAMPLE.substring("Digest ".length()).split(",")));
    Set<String> actualSubstrings =
        new HashSet<>(Arrays.asList(generatedHeader.substring("Digest ".length()).split(",")));

    assertEquals(expectedSubstrings, actualSubstrings);
  }
}
