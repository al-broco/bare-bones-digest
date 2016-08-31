package org.barebonesdigest;

import org.junit.Ignore;
import org.junit.Test;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertNull;
import static junit.framework.Assert.assertTrue;

public class DigestChallengeTest {
  @Test
  public void testMinimalChallenge() throws Exception {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
  }

  @Test
  public void testRealm() {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertEquals("\"testrealm@host.com\"", header.getQuotedRealm());
    assertEquals("testrealm@host.com", header.getRealm());
  }

  @Test
  public void testNonce() {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertEquals("\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"", header.getQuotedNonce());
    assertEquals("dcd98b7102dd2f0e8b11d0f600bfb0c093", header.getNonce());
  }

  @Test
  public void testOpaque() {
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
  public void testMissingAlgorithm() throws Exception {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertEquals("MD5", header.getAlgorithm());
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
  public void testDomain() {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "domain=\"http://domain.testrealm.com\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
  }

  @Test
  public void testStaleSetToTrue() {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "stale=true";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertTrue(header.isStale());
  }

  @Test
  public void testStaleSetToFalse() {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "stale=false";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertFalse(header.isStale());
  }

  @Test
  public void testStaleCaseInsensitive() {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "stale=TRUE";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertTrue(header.isStale());
  }

  @Test
  public void testStaleDirectiveMissing() {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertFalse(header.isStale());
  }

  @Test
  public void testStaleUnrecognizedValue() {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "stale=no";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
    assertFalse(header.isStale());
  }

  @Test
  public void testQopSetToAuth() {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "qop=\"auth\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
  }

  @Test
  public void testQopSetToAuthInt() {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "qop=\"auth-int\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
  }

  @Test
  public void testQopSetToAuthAndAuthInt() {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "qop=\"auth,auth-int\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
  }

  @Test
  public void testQopMissing() {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
  }

  @Ignore
  @Test
  public void testUnrecognizedDirectiveWithTokenValue() {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "unrecognized=token";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
  }

  @Ignore
  @Test
  public void testUnrecognizedDirectiveWithQuotedValue() {
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "unrecognized=\"quoted\"";

    DigestChallenge header = DigestChallenge.parse(CHALLENGE);

    assertNotNull(header);
  }

  @Test
  public void testExampleFromRfc2617() throws Exception {
    // The example below is from Section 3.5 of RC 2617,
    // https://tools.ietf.org/html/rfc2617#section-3.5
    String EXAMPLE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "qop=\"auth,auth-int\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";

    DigestChallenge header = DigestChallenge.parse(EXAMPLE);

    assertNotNull(header);
    assertEquals("\"testrealm@host.com\"", header.getQuotedRealm());
    assertEquals("\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"", header.getQuotedNonce());
    assertEquals("\"5ccc069c403ebaf9f0171e9517f40e41\"", header.getQuotedOpaque());
    assertEquals("MD5", header.getAlgorithm());
  }

  @Test
  public void testMalformedChallengeMissingRealm() throws Exception {
    // The example below is from Section 3.5 of RC 2617,
    // https://tools.ietf.org/html/rfc2617#section-3.5
    String CHALLENGE = "Digest " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"";

    assertNull(DigestChallenge.parse(CHALLENGE));
  }

  @Test
  public void testMalformedChallengeMissingNonce() throws Exception {
    // The example below is from Section 3.5 of RC 2617,
    // https://tools.ietf.org/html/rfc2617#section-3.5
    String CHALLENGE = "Digest " +
        "realm=\"testrealm@host.com\"";

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