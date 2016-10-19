// Copyright (c) 2016 Petter Wintzell

package com.albroco.barebonesdigest.examples;

import com.albroco.barebonesdigest.DigestChallenge;
import com.albroco.barebonesdigest.DigestChallengeResponse;

import org.junit.Test;

import static com.albroco.barebonesdigest.DigestTestUtils.assertHeadersEqual;

/**
 * Tests the example from <a href="https://tools.ietf.org/html/rfc2617#section-3.5">Section 3.5 of
 * RFC 2069</a>.
 */
public class Rfc7617ExamplesTest {

  @Test
  public void testMd5ExampleFromRfc7617() throws Exception {
    DigestChallenge challenge = DigestChallenge.parse("Digest\n" +
        "       realm=\"http-auth@example.org\",\n" +
        "       qop=\"auth, auth-int\",\n" +
        "       algorithm=MD5,\n" +
        "       nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\",\n" +
        "       opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"");

    String expectedResponse = "Digest username=\"Mufasa\",\n" +
        "       realm=\"http-auth@example.org\",\n" +
        "       uri=\"/dir/index.html\",\n" +
        "       algorithm=MD5,\n" +
        "       nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\",\n" +
        "       nc=00000001,\n" +
        "       cnonce=\"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\",\n" +
        "       qop=auth,\n" +
        "       response=\"8ca523f5e9506fed4657c9700eebdbec\",\n" +
        "       opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"";

    DigestChallengeResponse response = DigestChallengeResponse.responseTo(challenge)
        .clientNonce("f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ")
        .firstRequestClientNonce("f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ")
        .username("Mufasa")
        .password("Circle of Life")
        .digestUri("/dir/index.html")
        .requestMethod("GET");

    assertHeadersEqual(expectedResponse, response.getHeaderValue());
  }

  @Test
  public void testExampleFromRfc7617() throws Exception {
    DigestChallenge challenge = DigestChallenge.parse("Digest\n" +
        "       realm=\"http-auth@example.org\",\n" +
        "       qop=\"auth, auth-int\",\n" +
        "       algorithm=SHA-256,\n" +
        "       nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\",\n" +
        "       opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"");

    String expectedResponse = "Digest username=\"Mufasa\",\n" +
        "       realm=\"http-auth@example.org\",\n" +
        "       uri=\"/dir/index.html\",\n" +
        "       algorithm=SHA-256,\n" +
        "       nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\",\n" +
        "       nc=00000001,\n" +
        "       cnonce=\"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\",\n" +
        "       qop=auth,\n" +
        "       response=\"753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1\",\n" +
        "       opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"";

    DigestChallengeResponse response = DigestChallengeResponse.responseTo(challenge)
        .clientNonce("f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ")
        .firstRequestClientNonce("f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ")
        .username("Mufasa")
        .password("Circle of Life")
        .digestUri("/dir/index.html")
        .requestMethod("GET");

    assertHeadersEqual(expectedResponse, response.getHeaderValue());
  }
}
