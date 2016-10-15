// Copyright (c) 2016 Petter Wintzell

package com.albroco.barebonesdigest.examples;

import com.albroco.barebonesdigest.DigestChallenge;
import com.albroco.barebonesdigest.DigestChallengeResponse;

import org.junit.Test;

import static com.albroco.barebonesdigest.DigestTestUtils.assertHeadersEqual;

/**
 * Tests the example from <a href="https://tools.ietf.org/html/rfc2069#section-2.4">Section 2.4 of
 * RFC 2069</a>.
 * <p>
 * Note that the example is wrong, <a href="https://www.rfc-editor.org/errata_search.php?rfc=2069">
 * errata exists</a>.
 */
public class Rfc2069ExamplesTest {

  @Test
  public void testExampleFromRfc2069() throws Exception {
    DigestChallenge challenge = DigestChallenge.parse("Digest    realm=\"testrealm@host.com\",\n" +
        "                            nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\n" +
        "                            opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"");

    String expectedResponse = "Digest username=\"Mufasa\",\n" +
        "                            realm=\"testrealm@host.com\",\n" +
        "                            nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\n" +
        "                            uri=\"/dir/index.html\",\n" +
        //"                            response=\"e966c932a9242554e42c8ee200cec7f6\",\n" +
        "                            response=\"1949323746fe6a43ef61f9606e7febea\",\n" +
        "                            opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";

    DigestChallengeResponse response = DigestChallengeResponse.responseTo(challenge)
        .username("Mufasa")
        .password("CircleOfLife")
        .digestUri("/dir/index.html")
        .requestMethod("GET");

    assertHeadersEqual(expectedResponse, response.getHeaderValue());
  }
}
