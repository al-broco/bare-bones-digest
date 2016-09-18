package com.albroco.barebonesdigest;

import org.junit.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertNull;
import static junit.framework.Assert.assertTrue;
import static org.junit.Assert.assertNotEquals;

public class DigestChallengeResponseTest {
  @Test(expected = UnsupportedAlgorithmHttpDigestException.class)
  public void testSetUnsupportedAlgorithm() throws Exception {
    new DigestChallengeResponse().algorithm("illegal");
  }

  @Test
  public void testGetAndSetMd5Algorithm() throws Exception {
    assertEquals("MD5", new DigestChallengeResponse().algorithm("MD5").getAlgorithm());
  }

  @Test
  public void testGetAndSetMd5SessAlgorithm() throws Exception {
    assertEquals("MD5-sess", new DigestChallengeResponse().algorithm("MD5-sess").getAlgorithm());
  }

  @Test
  public void testAlgorithmDefaultValue() {
    assertNull(new DigestChallengeResponse().getAlgorithm());
  }

  @Test
  public void testUnsetAlgorithm() throws Exception {
    assertNull(new DigestChallengeResponse().algorithm("MD5").algorithm(null).getAlgorithm());
  }

  @Test
  public void testGetAndSetUsername() {
    assertEquals("user", new DigestChallengeResponse().username("user").getUsername());
  }

  @Test
  public void testUsernameDefaultValue() {
    assertNull(new DigestChallengeResponse().getUsername());
  }

  @Test
  public void testUnsetUsername() {
    assertNull(new DigestChallengeResponse().username("username").username(null).getUsername());
  }

  @Test
  public void testGetAndSetPassword() {
    assertEquals("pwd", new DigestChallengeResponse().password("pwd").getPassword());
  }

  @Test
  public void testPasswordDefaultValue() {
    assertNull(new DigestChallengeResponse().getPassword());
  }

  @Test
  public void testUnsetPassword() {
    assertNull(new DigestChallengeResponse().password("pwd").password(null).getPassword());
  }

  @Test
  public void testGetAndSetClientNonce() {
    assertEquals("cnonce", new DigestChallengeResponse().clientNonce("cnonce").getClientNonce());
  }

  @Test
  public void testClientNonceDefaultValue() {
    String cnonce = new DigestChallengeResponse().getClientNonce();
    assertNotNull(cnonce);
    assertTrue("Client nonce too short", cnonce.length() > 0);
  }

  @Test
  public void testUnsetClientNonce() {
    assertNull(new DigestChallengeResponse().clientNonce("cnonce")
        .clientNonce(null)
        .getClientNonce());
  }

  @Test
  public void testClientNonceDoesNotChange() {
    DigestChallengeResponse response = new DigestChallengeResponse();
    assertEquals(response.getClientNonce(), response.getClientNonce());
  }

  @Test
  public void testGetAndSetFirstRequestClientNonce() {
    assertEquals("cnonce",
        new DigestChallengeResponse().firstRequestClientNonce("cnonce")
            .getFirstRequestClientNonce());
  }

  @Test
  public void testFirstRequestClientNonceDefaultValue() {
    DigestChallengeResponse response = new DigestChallengeResponse();
    assertEquals(response.getClientNonce(), response.getFirstRequestClientNonce());
  }

  @Test
  public void testFirstRequestClientNonceDoesNotChangeIfClientNonceChanges() {
    DigestChallengeResponse response = new DigestChallengeResponse();
    String firstRequestClientNonce = response.getFirstRequestClientNonce();
    response.clientNonce("overridden client nonce");
    assertEquals(firstRequestClientNonce, response.getFirstRequestClientNonce());
  }

  @Test
  public void testUnsetFirstRequestClientNonce() {
    assertNull(new DigestChallengeResponse().firstRequestClientNonce("cnonce")
        .firstRequestClientNonce(null)
        .getFirstRequestClientNonce());
  }

  @Test
  public void testGetAndSetQuotedNonce() {
    assertEquals("\"nonce\"",
        new DigestChallengeResponse().quotedNonce("\"nonce\"").getQuotedNonce());
  }

  @Test
  public void testGenerateClientNonce() {
    String cnonce =
        new DigestChallengeResponse().clientNonce(null).randomizeClientNonce().getClientNonce();
    assertNotNull(cnonce);
    assertTrue("Client nonce too short", cnonce.length() > 0);
  }

  @Test
  public void tesSetQuotedNonceResetsNonceCount() {
    assertEquals(1,
        new DigestChallengeResponse().nonceCount(10).quotedNonce("\"nonce\"").getNonceCount());
  }

  @Test
  public void testQuotedNonceDefaultValue() {
    assertNull(new DigestChallengeResponse().getQuotedNonce());
  }

  @Test
  public void testUnsetQuotedNonce() {
    assertNull(new DigestChallengeResponse().quotedNonce("\"nonce\"")
        .quotedNonce(null)
        .getQuotedNonce());
  }

  @Test
  public void testGetAndSetNonce() {
    assertEquals("nonce", new DigestChallengeResponse().nonce("nonce").getNonce());
  }

  @Test
  public void tesSetNonceResetsNonceCount() {
    assertEquals(1, new DigestChallengeResponse().nonceCount(10).nonce("nonce").getNonceCount());
  }

  @Test
  public void testNonceDefaultValue() {
    assertNull(new DigestChallengeResponse().getNonce());
  }

  @Test
  public void testUnsetNonce() {
    assertNull(new DigestChallengeResponse().nonce("nonce").nonce(null).getNonce());
  }

  @Test
  public void testSetNonceGetQuotedNonce() {
    assertEquals("\"nonce\"", new DigestChallengeResponse().nonce("nonce").getQuotedNonce());
  }

  @Test
  public void testSetQuotedNonceGetNonce() {
    assertEquals("nonce", new DigestChallengeResponse().quotedNonce("\"nonce\"").getNonce());
  }

  @Test
  public void testGetAndSetNonceCount() {
    assertEquals(5, new DigestChallengeResponse().nonceCount(5).getNonceCount());
  }

  @Test
  public void testNonceCountDefaultValue() {
    assertEquals(1, new DigestChallengeResponse().getNonceCount());
  }

  @Test
  public void testIncrementNonceCount() {
    assertEquals(2,
        new DigestChallengeResponse().nonceCount(1).incrementNonceCount().getNonceCount());
  }

  @Test
  public void testResetNonceCount() {
    assertEquals(1, new DigestChallengeResponse().nonceCount(10).resetNonceCount().getNonceCount());
  }

  @Test
  public void testGetAndSetQuotedOpaque() {
    assertEquals("\"opaque\"",
        new DigestChallengeResponse().quotedOpaque("\"opaque\"").getQuotedOpaque());
  }

  @Test
  public void testQuotedOpaqueDefaultValue() {
    assertNull(new DigestChallengeResponse().getQuotedOpaque());
  }

  @Test
  public void testUnsetQuotedOpaque() {
    assertNull(new DigestChallengeResponse().quotedOpaque("quotedOpaque")
        .quotedOpaque(null)
        .getQuotedOpaque());
  }

  @Test
  public void testGetAndSetOpaque() {
    assertEquals("opaque", new DigestChallengeResponse().opaque("opaque").getOpaque());
  }

  @Test
  public void testOpaqueDefaultValue() {
    assertNull(new DigestChallengeResponse().getOpaque());
  }

  @Test
  public void testUnsetOpaque() {
    assertNull(new DigestChallengeResponse().opaque("opaque").opaque(null).getOpaque());
  }

  @Test
  public void testSetOpaqueGetQuotedOpaque() {
    assertEquals("\"opaque\"", new DigestChallengeResponse().opaque("opaque").getQuotedOpaque());
  }

  @Test
  public void testSetQuotedOpaqueGetOpaque() {
    assertEquals("opaque", new DigestChallengeResponse().quotedOpaque("\"opaque\"").getOpaque());
  }

  @Test
  public void testGetAndSetDigestUri() {
    assertEquals("/uri", new DigestChallengeResponse().digestUri("/uri").getDigestUri());
  }

  @Test
  public void testDigestUriDefaultValue() {
    assertNull(new DigestChallengeResponse().getDigestUri());
  }

  @Test
  public void testUnsetDigestUri() {
    assertNull(new DigestChallengeResponse().digestUri("/uri").digestUri(null).getDigestUri());
  }

  @Test
  public void testGetAndSetQuotedRealm() {
    assertEquals("\"realm\"",
        new DigestChallengeResponse().quotedRealm("\"realm\"").getQuotedRealm());
  }

  @Test
  public void testQuotedRealmDefaultValue() {
    assertNull(new DigestChallengeResponse().getQuotedRealm());
  }

  @Test
  public void testUnsetQuotedRealm() {
    assertNull(new DigestChallengeResponse().quotedRealm("\"realm\"")
        .quotedRealm(null)
        .getQuotedRealm());
  }

  @Test
  public void testGetAndSetRealm() {
    assertEquals("realm", new DigestChallengeResponse().realm("realm").getRealm());
  }

  @Test
  public void testRealmDefaultValue() {
    assertNull(new DigestChallengeResponse().getRealm());
  }

  @Test
  public void testUnsetRealm() {
    assertNull(new DigestChallengeResponse().realm("realm").realm(null).getRealm());
  }

  @Test
  public void testSetRealmGetQuotedRealm() {
    assertEquals("\"realm\"", new DigestChallengeResponse().realm("realm").getQuotedRealm());
  }

  @Test
  public void testSetQuotedRealmGetRealm() {
    assertEquals("realm", new DigestChallengeResponse().quotedRealm("\"realm\"").getRealm());
  }

  @Test
  public void testGetAndSetRequestMethod() {
    assertEquals("GET", new DigestChallengeResponse().requestMethod("GET").getRequestMethod());
  }

  @Test
  public void testRequestMethodDefaultValue() {
    assertNull(new DigestChallengeResponse().getRequestMethod());
  }

  @Test
  public void testUnsetRequestMethod() {
    assertNull(new DigestChallengeResponse().requestMethod("GET")
        .requestMethod(null)
        .getRequestMethod());
  }

  @Test
  public void testSetChallenge() throws Exception {
    DigestChallenge challenge = DigestChallenge.parse("Digest " +
        "realm=\"testrealm@host.com\", " +
        "qop=\"auth,auth-int\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"");

    DigestChallengeResponse response = new DigestChallengeResponse().challenge(challenge);

    assertEquals("MD5", response.getAlgorithm());
    assertEquals("dcd98b7102dd2f0e8b11d0f600bfb0c093", response.getNonce());
    assertEquals("5ccc069c403ebaf9f0171e9517f40e41", response.getOpaque());
    assertEquals("testrealm@host.com", response.getRealm());
  }

  @Test
  public void testCreateFromChallenge() throws Exception {
    DigestChallenge challenge = DigestChallenge.parse("Digest " +
        "realm=\"testrealm@host.com\", " +
        "qop=\"auth,auth-int\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"");

    DigestChallengeResponse response = DigestChallengeResponse.responseTo(challenge);

    assertEquals("MD5", response.getAlgorithm());
    assertEquals("dcd98b7102dd2f0e8b11d0f600bfb0c093", response.getNonce());
    assertEquals("5ccc069c403ebaf9f0171e9517f40e41", response.getOpaque());
    assertEquals("testrealm@host.com", response.getRealm());
  }

  @Test(expected = IllegalStateException.class)
  public void testMissingUsername() {
    createChallengeFromRfc2617Example().username(null).getHeaderValue();
  }

  @Test(expected = IllegalStateException.class)
  public void testMissingPassword() {
    createChallengeFromRfc2617Example().password(null).getHeaderValue();
  }

  @Test(expected = IllegalStateException.class)
  public void testMissingRealm() {
    createChallengeFromRfc2617Example().realm(null).getHeaderValue();
  }

  @Test(expected = IllegalStateException.class)
  public void testMissingNonce() {
    createChallengeFromRfc2617Example().nonce(null).getHeaderValue();
  }

  @Test(expected = IllegalStateException.class)
  public void testMissingDigestUri() {
    createChallengeFromRfc2617Example().digestUri(null).getHeaderValue();
  }

  @Test(expected = IllegalStateException.class)
  public void testMissingRequestMethod() {
    createChallengeFromRfc2617Example().requestMethod(null).getHeaderValue();
  }

  @Test(expected = IllegalStateException.class)
  public void testMissingClientNonceWhenQopIsSet() {
    createChallengeFromRfc2617Example().clientNonce(null).getHeaderValue();
  }

  @Test(expected = IllegalStateException.class)
  public void testMissingFirstRequestClientNonceWithMd5SessAlgorithm() throws Exception {
    createChallengeFromRfc2617Example().firstRequestClientNonce(null)
        .algorithm("MD5-sess")
        .getHeaderValue();
  }

  @Test
  public void testMinimalQopAuthHeader() throws Exception {
    DigestChallengeResponse response = new DigestChallengeResponse().username("usr")
        .password("pwd")
        .realm("realm")
        .nonce("nonce")
        .digestUri("/uri")
        .requestMethod("GET")
        .clientNonce("cnonce")
        .firstRequestClientNonce("cnonce");

    String expectedHeader = "Digest username=\"usr\"," +
        "realm=\"realm\"," +
        "nonce=\"nonce\"," +
        "uri=\"/uri\"," +
        "qop=auth," +
        "response=\"ebffe33712374a9fde515485b70ee5a1\"," +
        "nc=00000001," +
        "cnonce=\"cnonce\"";

    assertHeadersEqual(expectedHeader, response.getHeaderValue());
  }

  @Test
  public void testQopAuthHeaderWithMd5Algorithm() throws Exception {
    DigestChallengeResponse response = new DigestChallengeResponse().username("usr")
        .password("pwd")
        .realm("realm")
        .nonce("nonce")
        .digestUri("/uri")
        .requestMethod("GET")
        .clientNonce("cnonce")
        .firstRequestClientNonce("cnonce")
        .algorithm("MD5");

    String expectedHeader = "Digest username=\"usr\"," +
        "realm=\"realm\"," +
        "nonce=\"nonce\"," +
        "uri=\"/uri\"," +
        "qop=auth," +
        "response=\"ebffe33712374a9fde515485b70ee5a1\"," +
        "nc=00000001," +
        "cnonce=\"cnonce\"," +
        "algorithm=MD5";

    assertHeadersEqual(expectedHeader, response.getHeaderValue());
  }

  @Test
  public void testQopAuthHeaderWithMd5SessAlgorithm() throws Exception {
    DigestChallengeResponse response = new DigestChallengeResponse().username("usr")
        .password("pwd")
        .realm("realm")
        .nonce("nonce")
        .digestUri("/uri")
        .requestMethod("GET")
        .clientNonce("cnonce")
        .firstRequestClientNonce("cnonce")
        .algorithm("MD5-sess");

    String expectedHeader = "Digest username=\"usr\"," +
        "realm=\"realm\"," +
        "nonce=\"nonce\"," +
        "uri=\"/uri\"," +
        "qop=auth," +
        "response=\"e9d2f4f7939312353ee18da867fb4ec2\"," +
        "nc=00000001," +
        "cnonce=\"cnonce\"," +
        "algorithm=MD5-sess";

    assertHeadersEqual(expectedHeader, response.getHeaderValue());
  }

  @Test
  public void testResponseChangesIfAlgorithmChanges() throws Exception {
    // This might seem redundant but tests that A1 (and other values) is not cached too aggressively
    DigestChallengeResponse response = new DigestChallengeResponse().username("usr")
        .password("pwd")
        .realm("realm")
        .nonce("nonce")
        .digestUri("/uri")
        .requestMethod("GET")
        .clientNonce("cnonce")
        .firstRequestClientNonce("cnonce")
        .algorithm("MD5");

    response.getHeaderValue();

    response.algorithm("MD5-sess");

    String expectedHeader = "Digest username=\"usr\"," +
        "realm=\"realm\"," +
        "nonce=\"nonce\"," +
        "uri=\"/uri\"," +
        "qop=auth," +
        "response=\"e9d2f4f7939312353ee18da867fb4ec2\"," +
        "nc=00000001," +
        "cnonce=\"cnonce\"," +
        "algorithm=MD5-sess";

    assertHeadersEqual(expectedHeader, response.getHeaderValue());
  }

  @Test
  public void testResponseChangesIfUsernameChanges() throws Exception {
    // This might seem redundant but tests that A1 (and other values) is not cached too aggressively
    DigestChallengeResponse response = new DigestChallengeResponse().username("usr")
        .password("pwd")
        .realm("realm")
        .nonce("nonce")
        .digestUri("/uri")
        .requestMethod("GET")
        .clientNonce("cnonce")
        .firstRequestClientNonce("cnonce")
        .algorithm("MD5");

    response.getHeaderValue();

    response.username("new user");

    String expectedHeader = "Digest username=\"new user\"," +
        "realm=\"realm\"," +
        "nonce=\"nonce\"," +
        "uri=\"/uri\"," +
        "qop=auth," +
        "response=\"82bc97801cb7ef79b8f5606fc1f62fc6\"," +
        "nc=00000001," +
        "cnonce=\"cnonce\"," +
        "algorithm=MD5";

    assertHeadersEqual(expectedHeader, response.getHeaderValue());
  }

  @Test
  public void testResponseChangesIfPasswordChanges() throws Exception {
    // This might seem redundant but tests that A1 (and other values) is not cached too aggressively
    DigestChallengeResponse response = new DigestChallengeResponse().username("usr")
        .password("pwd")
        .realm("realm")
        .nonce("nonce")
        .digestUri("/uri")
        .requestMethod("GET")
        .clientNonce("cnonce")
        .firstRequestClientNonce("cnonce")
        .algorithm("MD5");

    response.getHeaderValue();

    response.password("new password");

    String expectedHeader = "Digest username=\"usr\"," +
        "realm=\"realm\"," +
        "nonce=\"nonce\"," +
        "uri=\"/uri\"," +
        "qop=auth," +
        "response=\"f8227f462d3661a0c4f0c76c449ef453\"," +
        "nc=00000001," +
        "cnonce=\"cnonce\"," +
        "algorithm=MD5";

    assertHeadersEqual(expectedHeader, response.getHeaderValue());
  }

  @Test
  public void testMd5ResponseChangesIfClientNonceChanges() throws Exception {
    // This might seem redundant but tests that A1 (and other values) is not cached too aggressively
    DigestChallengeResponse response = new DigestChallengeResponse().username("usr")
        .password("pwd")
        .realm("realm")
        .nonce("nonce")
        .digestUri("/uri")
        .requestMethod("GET")
        .clientNonce("cnonce")
        .firstRequestClientNonce("cnonce")
        .algorithm("MD5");

    response.getHeaderValue();

    response.clientNonce("changed cnonce").firstRequestClientNonce("changed cnonce");

    String expectedHeader = "Digest username=\"usr\"," +
        "realm=\"realm\"," +
        "nonce=\"nonce\"," +
        "uri=\"/uri\"," +
        "qop=auth," +
        "response=\"60ac57635a413e9eee16345af309d76f\"," +
        "nc=00000001," +
        "cnonce=\"changed cnonce\"," +
        "algorithm=MD5";

    assertHeadersEqual(expectedHeader, response.getHeaderValue());
  }

  @Test
  public void testMd5SessResponseChangesIfClientNonceChanges() throws Exception {
    // This might seem redundant but tests that A1 (and other values) is not cached too aggressively
    DigestChallengeResponse response = new DigestChallengeResponse().username("usr")
        .password("pwd")
        .realm("realm")
        .nonce("nonce")
        .digestUri("/uri")
        .requestMethod("GET")
        .clientNonce("cnonce")
        .firstRequestClientNonce("cnonce")
        .algorithm("MD5-sess");

    response.getHeaderValue();

    response.clientNonce("changed cnonce").firstRequestClientNonce("changed cnonce");

    String expectedHeader = "Digest username=\"usr\"," +
        "realm=\"realm\"," +
        "nonce=\"nonce\"," +
        "uri=\"/uri\"," +
        "qop=auth," +
        "response=\"29ff1aeb8a555477e872cc6cfac3a187\"," +
        "nc=00000001," +
        "cnonce=\"changed cnonce\"," +
        "algorithm=MD5-sess";

    assertHeadersEqual(expectedHeader, response.getHeaderValue());
  }

  @Test
  public void testMd5ResponseDoesNotChangeIfFirstRequestClientNonceChanges() throws Exception {
    // This might seem redundant but tests that A1 (and other values) is not cached too aggressively
    DigestChallengeResponse response = new DigestChallengeResponse().username("usr")
        .password("pwd")
        .realm("realm")
        .nonce("nonce")
        .digestUri("/uri")
        .requestMethod("GET")
        .clientNonce("cnonce")
        .firstRequestClientNonce("cnonce")
        .algorithm("MD5");

    String headerValue = response.getHeaderValue();
    assertEquals(headerValue, response.firstRequestClientNonce("changed cnonce").getHeaderValue());
  }

  @Test
  public void testMd5SessResponseChangesIfFirstRequestClientNonceChanges() throws Exception {
    // This might seem redundant but tests that A1 (and other values) is not cached too aggressively
    DigestChallengeResponse response = new DigestChallengeResponse().username("usr")
        .password("pwd")
        .realm("realm")
        .nonce("nonce")
        .digestUri("/uri")
        .requestMethod("GET")
        .clientNonce("cnonce")
        .firstRequestClientNonce("cnonce")
        .algorithm("MD5-sess");

    String headerValue = response.getHeaderValue();
    assertNotEquals(headerValue,
        response.firstRequestClientNonce("changed cnonce").getHeaderValue());
  }

  @Test
  public void testExampleFromRfc2617() throws Exception {
    // The example below is from Section 3.5 of RC 2617,
    // https://tools.ietf.org/html/rfc2617#section-3.5

    DigestChallengeResponse response = createChallengeFromRfc2617Example();

    String expectedHeader = "Digest username=\"Mufasa\"," +
        "realm=\"testrealm@host.com\"," +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"," +
        "uri=\"/dir/index.html\"," +
        "qop=auth," +
        "nc=00000001," +
        "cnonce=\"0a4f113b\"," +
        "response=\"6629fae49393a05397450978507c4ef1\"," +
        "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";

    assertHeadersEqual(expectedHeader, response.getHeaderValue());
  }

  private void assertHeadersEqual(String expectedHeader, String generatedHeader) {
    assertTrue(generatedHeader.startsWith("Digest "));

    Set<String> expectedSubstrings =
        new HashSet<>(Arrays.asList(expectedHeader.substring("Digest ".length()).split(",")));
    Set<String> actualSubstrings =
        new HashSet<>(Arrays.asList(generatedHeader.substring("Digest ".length()).split(",")));

    assertEquals(expectedSubstrings, actualSubstrings);
  }

  private DigestChallengeResponse createChallengeFromRfc2617Example() {
    // The example below is from Section 3.5 of RC 2617,
    // https://tools.ietf.org/html/rfc2617#section-3.5
    return new DigestChallengeResponse().username("Mufasa")
        .password("Circle Of Life")
        .quotedRealm("\"testrealm@host.com\"")
        .quotedNonce("\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"")
        .digestUri("/dir/index.html")
        .requestMethod("GET")
        .nonceCount(1)
        .clientNonce("0a4f113b")
        .quotedOpaque("\"5ccc069c403ebaf9f0171e9517f40e41\"");
  }
}
