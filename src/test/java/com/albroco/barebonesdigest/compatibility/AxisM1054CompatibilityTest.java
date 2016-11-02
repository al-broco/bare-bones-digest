// Copyright (c) 2016 Petter Wintzell

package com.albroco.barebonesdigest.compatibility;

import com.albroco.barebonesdigest.DigestAuthentication;

import org.junit.Test;

import static com.albroco.barebonesdigest.DigestTestUtils.assertHeadersEqual;

/**
 * Tests that the digest algorithm is compatible with an Axis M1054 camera.
 */
public class AxisM1054CompatibilityTest {

  @Test
  public void testQopAuthAuthenticationMd5Algorithm() throws Exception {
    // Tests an actual challenge and compares it to a correct response
    DigestAuthentication auth =
        DigestAuthentication.fromWwwAuthenticateHeader("Digest realm=\"AXIS_00408CE5B4AE\", " +
            "nonce=\"00000127Y5696118a2b01283063278e2d8c2c43eed9dc4\", " +
            "stale=FALSE, " +
            "qop=\"auth\", " +
            "Basic realm=\"AXIS_00408CE5B4AE\"");

    String expectedResponse = "Digest username=\"root\",realm=\"AXIS_00408CE5B4AE\"," +
        "nonce=\"00000127Y5696118a2b01283063278e2d8c2c43eed9dc4\",uri=\"/axis-cgi/jpg/image" +
        ".cgi\",response=\"d7d5c3a6c28614aa27d1c2a1231acb5f\",cnonce=\"fd7e8e85093d0ea9\"," +
        "qop=auth,nc=00000001";

    auth.username("root")
        .password("pass")
        .getChallengeResponse()
        .clientNonce("fd7e8e85093d0ea9")
        .firstRequestClientNonce("fd7e8e85093d0ea9");

    String actualResponse = auth.getAuthorizationForRequest("GET", "/axis-cgi/jpg/image.cgi");

    assertHeadersEqual(expectedResponse, actualResponse);
  }
}
