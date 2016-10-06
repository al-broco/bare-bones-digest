package com.albroco.barebonesdigest;

import org.junit.Test;

import java.util.Collections;
import java.util.EnumSet;

import static com.albroco.barebonesdigest.DigestChallenge.QualityOfProtection.AUTH;
import static com.albroco.barebonesdigest.DigestChallenge.QualityOfProtection.AUTH_INT;
import static com.albroco.barebonesdigest.DigestChallenge.QualityOfProtection
    .UNSPECIFIED_RFC2069_COMPATIBLE;
import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertNull;
import static junit.framework.Assert.assertTrue;

public class DigestChallengeTest {
  @Test
  public void testIsDigestChallengeEmptyString() {
    assertFalse(DigestChallenge.isDigestChallenge(""));
  }

  @Test
  public void testIsDigestChallengeCorrectPrefixNoSpace() {
    assertFalse(DigestChallenge.isDigestChallenge("Digest"));
  }

  @Test
  public void testIsDigestChallengeCorrectPrefix() {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"";
    assertTrue(DigestChallenge.isDigestChallenge(CHALLENGE));
  }

  @Test
  public void testIsDigestChallengeLowerCase() {
    String CHALLENGE = "digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"";
    assertTrue(DigestChallenge.isDigestChallenge(CHALLENGE));
  }

  @Test
  public void testIsDigestChallengeUpperCase() {
    String CHALLENGE = "DIGEST " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"";
    assertTrue(DigestChallenge.isDigestChallenge(CHALLENGE));
  }

  @Test
  public void testMinimalChallenge() throws Exception {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
  }

  @Test
  public void testRealm() throws Exception {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertEquals("\"testrealm@host.com\"", header.getQuotedRealm());
    assertEquals("testrealm@host.com", header.getRealm());
  }

  @Test
  public void testNonce() throws Exception {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertEquals("\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"", header.getQuotedNonce());
    assertEquals("dcd98b7102dd2f0e8b11d0f600bfb0c093", header.getNonce());
  }

  @Test
  public void testOpaque() throws Exception {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "qop=\"auth,auth-int\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertEquals("\"5ccc069c403ebaf9f0171e9517f40e41\"", header.getQuotedOpaque());
    assertEquals("5ccc069c403ebaf9f0171e9517f40e41", header.getOpaque());
  }

  @Test
  public void testMd5Algorithm() throws Exception {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "algorithm=MD5";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertEquals("MD5", header.getAlgorithm());
  }

  @Test
  public void testMd5SessAlgorithm() throws Exception {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "algorithm=MD5-sess";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertEquals("MD5-sess", header.getAlgorithm());
  }

  @Test
  public void testQuotedAlgorithm() throws Exception {
    // This is not a valid challenge but parsing is intentionally lenient
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "algorithm=\"MD5-sess\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertEquals("MD5-sess", header.getAlgorithm());
  }

  @Test
  public void testMissingAlgorithm() throws Exception {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertEquals(null, header.getAlgorithm());
  }

  @Test
  public void testUnknownAlgorithm() throws Exception {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "algorithm=XYZ";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertEquals("XYZ", header.getAlgorithm());
  }

  @Test
  public void testDomain() throws Exception {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "domain=\"http://domain.testrealm.com\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
  }

  @Test
  public void testStaleSetToTrue() throws Exception {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "stale=true";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertTrue(header.isStale());
  }

  @Test
  public void testStaleSetToFalse() throws Exception {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "stale=false";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertFalse(header.isStale());
  }

  @Test
  public void testStaleCaseInsensitive() throws Exception {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "stale=TRUE";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertTrue(header.isStale());
  }

  @Test
  public void testStaleDirectiveMissing() throws Exception {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertFalse(header.isStale());
  }

  @Test
  public void testQuotedStale() throws Exception {
    // This is not a valid challenge but parsing is intentionally lenient
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "stale=\"true\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertTrue(header.isStale());
  }

  @Test
  public void testStaleUnrecognizedValue() throws Exception {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "stale=no";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertFalse(header.isStale());
  }

  @Test
  public void testQopSetToAuth() throws Exception {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "qop=\"auth\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertEquals(EnumSet.of(AUTH), header.getSupportedQopTypes());
  }

  @Test
  public void testQopSetToAuthInt() throws Exception {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "qop=\"auth-int\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertEquals(EnumSet.of(AUTH_INT), header.getSupportedQopTypes());
  }

  @Test
  public void testQopSetToAuthAndAuthInt() throws Exception {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "qop=\"auth,auth-int\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertEquals(EnumSet.of(AUTH, AUTH_INT), header.getSupportedQopTypes());
  }

  @Test
  public void testQopMissing() throws Exception {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertEquals(EnumSet.of(UNSPECIFIED_RFC2069_COMPATIBLE), header.getSupportedQopTypes());
  }

  @Test
  public void testQopNotQuoted() throws Exception {
    // This is not a valid challenge, but some server implementations fail to quote the qop so
    // parsing is intentionally lenient
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "qop=auth";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertEquals(EnumSet.of(AUTH), header.getSupportedQopTypes());
  }

  @Test
  public void testQopUnknownQop() throws Exception {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "qop=\"future_extension\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertEquals(Collections.emptySet(), header.getSupportedQopTypes());
  }

  @Test
  public void testQopMalformedDirective() throws Exception {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "qop=\",, , auth\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertEquals(EnumSet.of(AUTH), header.getSupportedQopTypes());
  }

  @Test
  public void testUnrecognizedDirectiveWithTokenValue() throws Exception {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "unrecognized=token";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
  }

  @Test
  public void testUnrecognizedDirectiveWithQuotedValue() throws Exception {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "unrecognized=\"quoted\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
  }

  @Test(expected = HttpDigestChallengeParseException.class)
  public void testMalformedChallengeMissingRealm() throws Exception {
    // The example below is from Section 3.5 of RC 2617,
    // https://tools.ietf.org/html/rfc2617#section-3.5
    String CHALLENGE = "Digest " + "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"";

    assertNull(DigestChallenge.parse(CHALLENGE));
  }

  @Test(expected = HttpDigestChallengeParseException.class)
  public void testMalformedChallengeMissingNonce() throws Exception {
    // The example below is from Section 3.5 of RC 2617,
    // https://tools.ietf.org/html/rfc2617#section-3.5
    String CHALLENGE = "Digest " + "realm=\"testrealm@host.com\"";

    assertNull(DigestChallenge.parse(CHALLENGE));
  }

  @Test(expected = HttpDigestChallengeParseException.class)
  public void testMalformedChallengeWrongType() throws Exception {
    // The example below is from Section 3.5 of RC 2617,
    // https://tools.ietf.org/html/rfc2617#section-3.5
    String CHALLENGE = "Basic realm=\"WallyWorld\"";

    assertNull(DigestChallenge.parse(CHALLENGE));
  }

  @Test(expected = HttpDigestChallengeParseException.class)
  public void testMalformedChallengeWrongSyntax() throws Exception {
    // The example below is from Section 3.5 of RC 2617,
    // https://tools.ietf.org/html/rfc2617#section-3.5
    String CHALLENGE = "digest nonce,realm=\"WallyWorld\"";

    assertNull(DigestChallenge.parse(CHALLENGE));
  }

  @Test
  public void testThatDigestLiteralIsCaseInsensitive() throws Exception {
    String CHALLENGE = "DIGEST " +
        "realm=\"\", " +
        "qop=\"auth\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
  }
}