package com.albroco.barebonesdigest;

import org.junit.Test;

import static com.albroco.barebonesdigest.DigestTestUtils.assertHeadersEqual;

/**
 * Tests based on examples found in
 * <a href="http://www.cs.columbia.edu/sip/drafts/sip/draft-smith-sip-auth-examples-00.txt">
 * "Digest Authentication Examples for Session Initiation Protocol (SIP)"</a>,
 * draft-smith-sip-auth-examples-00.txt.
 */
public class SmithClarksonExamplesTest {

  @Test
  public void testExampleFromSection3_1AlgorithmAndQopNotSpecified() throws Exception {
    // Note: Response directive wrong in example, value copied from Section 3.1.3, digest generation
    // Note: cnonce and nc directives have been removed from the example since they must not be
    // included if the server did not include a qop in the challenge
    DigestChallenge challenge = DigestChallenge.parse("Digest\n" +
        "           realm=\"biloxi.com\",\n" +
        "           nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\n" +
        "           opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"");

    String expectedResponse = "Digest username=\"bob\",\n" +
        "           realm=\"biloxi.com\",\n" +
        "           nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\n" +
        "           uri=\"sip:bob@biloxi.com\",\n" +
        //"           nc=00000001,\n" +
        //"           cnonce=\"0a4f113b\",\n" +
        //"           response=\"89eb0059246c02b2f6ee02c7961d5ea3\",\n" +
        "           response=\"bf57e4e0d0bffc0fbaedce64d59add5e\",\n" +
        "           opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";

    DigestChallengeResponse response = DigestChallengeResponse.responseTo(challenge)
        .username("bob")
        .password("zanzibar")
        .digestUri("sip:bob@biloxi.com")
        .requestMethod("INVITE");

    assertHeadersEqual(expectedResponse, response.getHeaderValue());
  }

  @Test
  public void testExampleFromSection3_2AuthAndAlgorithmUnspecified() throws Exception {
    DigestChallenge challenge = DigestChallenge.parse("Digest\n" +
        "           realm=\"biloxi.com\",\n" +
        "           qop=\"auth,auth-int\",\n" +
        "           nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\n" +
        "           opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"");

    String expectedResponse = "Digest username=\"bob\",\n" +
        "           realm=\"biloxi.com\",\n" +
        "           nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\n" +
        "           uri=\"sip:bob@biloxi.com\",\n" +
        "           qop=auth,\n" +
        "           nc=00000001,\n" +
        "           cnonce=\"0a4f113b\",\n" +
        "           response=\"89eb0059246c02b2f6ee02c7961d5ea3\",\n" +
        "           opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";

    DigestChallengeResponse response = DigestChallengeResponse.responseTo(challenge)
        .clientNonce("0a4f113b")
        .firstRequestClientNonce("0a4f113b")
        .username("bob")
        .password("zanzibar")
        .digestUri("sip:bob@biloxi.com")
        .requestMethod("INVITE");

    assertHeadersEqual(expectedResponse, response.getHeaderValue());
  }

  @Test
  public void testExampleFromSection3_3AuthAndMd5() throws Exception {
    DigestChallenge challenge = DigestChallenge.parse("Digest\n" +
        "           realm=\"biloxi.com\",\n" +
        "           qop=\"auth,auth-int\",\n" +
        "           algorithm=MD5,\n" +
        "           nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\n" +
        "           opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"");

    String expectedResponse = "Digest username=\"bob\",\n" +
        "           realm=\"biloxi.com\",\n" +
        "           nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\n" +
        "           uri=\"sip:bob@biloxi.com\",\n" +
        "           qop=auth,\n" +
        "           algorithm=MD5,\n" +
        "           nc=00000001,\n" +
        "           cnonce=\"0a4f113b\",\n" +
        "           response=\"89eb0059246c02b2f6ee02c7961d5ea3\",\n" +
        "           opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";

    DigestChallengeResponse response = DigestChallengeResponse.responseTo(challenge)
        .clientNonce("0a4f113b")
        .firstRequestClientNonce("0a4f113b")
        .username("bob")
        .password("zanzibar")
        .digestUri("sip:bob@biloxi.com")
        .requestMethod("INVITE");

    assertHeadersEqual(expectedResponse, response.getHeaderValue());
  }

  @Test
  public void testExampleFromSection3_4AuthAndMd5Sess() throws Exception {
    // Note: Response directive wrong in example, value copied from Section 3.4.3, digest generation
    DigestChallenge challenge = DigestChallenge.parse("Digest\n" +
        "           realm=\"biloxi.com\",\n" +
        "           qop=\"auth,auth-int\",\n" +
        "           algorithm=MD5-sess,\n" +
        "           nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\n" +
        "           opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"");

    String expectedResponse = "Digest username=\"bob\",\n" +
        "           realm=\"biloxi.com\",\n" +
        "           nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\n" +
        "           uri=\"sip:bob@biloxi.com\",\n" +
        "           qop=auth,\n" +
        "           algorithm=MD5-sess,\n" +
        "           nc=00000001,\n" +
        "           cnonce=\"0a4f113b\",\n" +
        //"           response=\"89eb0059246c02b2f6ee02c7961d5ea3\",\n" +
        "           response=\"e4e4ea61d186d07a92c9e1f6919902e9\",\n" +
        "           opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";

    DigestChallengeResponse response = DigestChallengeResponse.responseTo(challenge)
        .clientNonce("0a4f113b")
        .firstRequestClientNonce("0a4f113b")
        .username("bob")
        .password("zanzibar")
        .digestUri("sip:bob@biloxi.com")
        .requestMethod("INVITE");

    assertHeadersEqual(expectedResponse, response.getHeaderValue());
  }

  @Test
  public void testExampleFromSection3_5AuthIntAndMd5() throws Exception {
    // Note: Response directive wrong in example, value copied from Section 3.5.3, digest generation
    DigestChallenge challenge = DigestChallenge.parse("Digest\n" +
        "           realm=\"biloxi.com\",\n" +
        "           qop=\"auth,auth-int\",\n" +
        "           algorithm=MD5,\n" +
        "           nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\n" +
        "           opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"");

    String expectedResponse = "Digest username=\"bob\",\n" +
        "           realm=\"biloxi.com\",\n" +
        "           nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\n" +
        "           uri=\"sip:bob@biloxi.com\",\n" +
        "           qop=auth-int,\n" +
        "           algorithm=MD5,\n" +
        "           nc=00000001,\n" +
        "           cnonce=\"0a4f113b\",\n" +
        //"           response=\"89eb0059246c02b2f6ee02c7961d5ea3\",\n" +
        "           response=\"41f1bde42dcddbee8ae7d65fd3474dc0\",\n" +
        "           opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";

    String entityBody = "v=0\r\n" +
        "o=bob 2890844526 2890844526 IN IP4 media.biloxi.com\r\n" +
        "s=\r\n" +
        "c=IN IP4 media.biloxi.com\r\n" +
        "t=0 0\r\n" +
        "m=audio 49170 RTP/AVP 0\r\n" +
        "a=rtpmap:0 PCMU/8000\r\n" +
        "m=video 51372 RTP/AVP 31\r\n" +
        "a=rtpmap:31 H261/90000\r\n" +
        "m=video 53000 RTP/AVP 32\r\n" +
        "a=rtpmap:32 MPV/90000\r\n";

    DigestChallengeResponse response = DigestChallengeResponse.responseTo(challenge)
        .clientNonce("0a4f113b")
        .firstRequestClientNonce("0a4f113b")
        .username("bob")
        .password("zanzibar")
        .digestUri("sip:bob@biloxi.com")
        .requestMethod("INVITE")
        .entityBody(entityBody.getBytes());

    assertHeadersEqual(expectedResponse, response.getHeaderValue());
  }

  @Test
  public void testExampleFromSection3_6AuthIntAndMd5Sess() throws Exception {
    // Note: Response directive wrong in example, value copied from Section 3.5.3, digest generation
    DigestChallenge challenge = DigestChallenge.parse("Digest\n" +
        "           realm=\"biloxi.com\",\n" +
        "           qop=\"auth,auth-int\",\n" +
        "           algorithm=MD5-sess,\n" +
        "           nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\n" +
        "           opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"");

    String expectedResponse = "Digest username=\"bob\",\n" +
        "           realm=\"biloxi.com\",\n" +
        "           nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\n" +
        "           uri=\"sip:bob@biloxi.com\",\n" +
        "           qop=auth-int,\n" +
        "           algorithm=MD5-sess,\n" +
        "           nc=00000001,\n" +
        "           cnonce=\"0a4f113b\",\n" +
        //"           response=\"89eb0059246c02b2f6ee02c7961d5ea3\",\n" +
        "           response=\"10e4c79b16d21d51995ab98083d134d8\",\n" +
        "           opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";

    String entityBody = "v=0\r\n" +
        "o=bob 2890844526 2890844526 IN IP4 media.biloxi.com\r\n" +
        "s=\r\n" +
        "c=IN IP4 media.biloxi.com\r\n" +
        "t=0 0\r\n" +
        "m=audio 49170 RTP/AVP 0\r\n" +
        "a=rtpmap:0 PCMU/8000\r\n" +
        "m=video 51372 RTP/AVP 31\r\n" +
        "a=rtpmap:31 H261/90000\r\n" +
        "m=video 53000 RTP/AVP 32\r\n" +
        "a=rtpmap:32 MPV/90000\r\n";

    DigestChallengeResponse response = DigestChallengeResponse.responseTo(challenge)
        .clientNonce("0a4f113b")
        .firstRequestClientNonce("0a4f113b")
        .username("bob")
        .password("zanzibar")
        .digestUri("sip:bob@biloxi.com")
        .requestMethod("INVITE")
        .entityBody(entityBody.getBytes());

    assertHeadersEqual(expectedResponse, response.getHeaderValue());
  }
}
