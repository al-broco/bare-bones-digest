// Copyright (c) 2016 Petter Wintzell

package com.albroco.barebonesdigest;

import org.junit.Test;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import static com.albroco.barebonesdigest.DigestChallenge.QualityOfProtection;
import static com.albroco.barebonesdigest.DigestChallenge.QualityOfProtection.AUTH;
import static com.albroco.barebonesdigest.DigestChallenge.QualityOfProtection.AUTH_INT;
import static com.albroco.barebonesdigest.DigestChallenge.QualityOfProtection
    .UNSPECIFIED_RFC2069_COMPATIBLE;
import static com.albroco.barebonesdigest.DigestTestUtils.assertHeadersEqual;
import static com.albroco.barebonesdigest.DigestTestUtils.directiveFromHeader;
import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertNull;
import static junit.framework.Assert.assertTrue;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotEquals;

public class DigestChallengeResponseTest {
  @Test
  public void testIsAlgorithmSupportedMd5() {
    assertTrue(DigestChallengeResponse.isAlgorithmSupported("MD5"));
  }

  @Test
  public void testIsAlgorithmSupportedMd5Sess() {
    assertTrue(DigestChallengeResponse.isAlgorithmSupported("MD5-sess"));
  }

  @Test
  public void testIsAlgorithmSupportedSha256() {
    assertTrue(DigestChallengeResponse.isAlgorithmSupported("SHA-256"));
  }

  @Test
  public void testIsAlgorithmSupportedSha256Sess() {
    assertTrue(DigestChallengeResponse.isAlgorithmSupported("SHA-256-sess"));
  }

  @Test
  public void testIsAlgorithmSupportedNoAlgorithm() {
    assertTrue(DigestChallengeResponse.isAlgorithmSupported(null));
  }

  @Test
  public void testIsAlgorithmSupportedUnsupportedAlgorithm() {
    assertFalse(DigestChallengeResponse.isAlgorithmSupported("unsupported"));
  }

  @Test(expected = IllegalArgumentException.class)
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
  public void testGetAndSetSha256Algorithm() throws Exception {
    assertEquals("MD5", new DigestChallengeResponse().algorithm("MD5").getAlgorithm());
  }

  @Test
  public void testGetAndSetSha256SessAlgorithm() throws Exception {
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
  public void testSetAlgorithmToMd5ResetsEntityBodyDigest() {
    byte[] digest = {-44, 29, -116, -39, -113, 0, -78, 4, -23, -128, 9, -104, -20, -8, 66, 126};
    DigestChallengeResponse response = new DigestChallengeResponse();
    response.entityBody(new byte[] { 1, 2, 3}).algorithm("MD5");
    assertArrayEquals(digest, response.getEntityBodyDigest());
  }

  @Test
  public void testSetAlgorithmToSha256ResetsEntityBodyDigest() {
    byte[] digest =
        {-29, -80, -60, 66, -104, -4, 28, 20, -102, -5, -12, -56, -103, 111, -71, 36, 39, -82, 65,
            -28, 100, -101, -109, 76, -92, -107, -103, 27, 120, 82, -72, 85};
    DigestChallengeResponse response = new DigestChallengeResponse();
    response.entityBody(new byte[] { 1, 2, 3}).algorithm("SHA-256");
    assertArrayEquals(digest, response.getEntityBodyDigest());
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
  public void testGetAndSetSupportedQopTypes() {
    assertEquals(EnumSet.of(AUTH),
        new DigestChallengeResponse().supportedQopTypes(EnumSet.of(AUTH)).getSupportedQopTypes());
    assertEquals(EnumSet.of(AUTH_INT),
        new DigestChallengeResponse().supportedQopTypes(EnumSet.of(AUTH))
            .supportedQopTypes(EnumSet.of(AUTH_INT))
            .getSupportedQopTypes());
  }

  @Test(expected = IllegalArgumentException.class)
  public void testSetSupportedQopTypesEmptySet() {
    new DigestChallengeResponse().supportedQopTypes(EnumSet.noneOf(DigestChallenge
        .QualityOfProtection.class));
  }

  @Test
  public void testGetAndSetSupportedQopTypesAuth() {
    assertEquals(EnumSet.of(AUTH),
        new DigestChallengeResponse().supportedQopTypes(EnumSet.of(AUTH)).getSupportedQopTypes());
  }

  @Test
  public void testGetAndSetSupportedQopTypesAuthInt() {
    assertEquals(EnumSet.of(AUTH_INT),
        new DigestChallengeResponse().supportedQopTypes(EnumSet.of(AUTH_INT))
            .getSupportedQopTypes());
  }

  @Test
  public void testGetAndSetSupportedQopTypesRfc2069() {
    assertEquals(EnumSet.of(UNSPECIFIED_RFC2069_COMPATIBLE),
        new DigestChallengeResponse().supportedQopTypes(EnumSet.of(UNSPECIFIED_RFC2069_COMPATIBLE))
            .getSupportedQopTypes());
  }

  @Test
  public void testSupportedQopTypesReturnedCannotModifyInternalRepresentation() {
    DigestChallengeResponse response = new DigestChallengeResponse();
    Set<DigestChallenge.QualityOfProtection> qops =
        response.supportedQopTypes(EnumSet.of(AUTH)).getSupportedQopTypes();
    try {
      qops.add(AUTH_INT);
      assertEquals(EnumSet.of(AUTH), response.getSupportedQopTypes());
    } catch (UnsupportedOperationException e) {
      // Can't add to returned set, this is OK
    }
  }

  @Test
  public void testSupportedQopTypesSetMakesACopy() {
    Set<DigestChallenge.QualityOfProtection> qops = EnumSet.of(AUTH);
    DigestChallengeResponse response = new DigestChallengeResponse().supportedQopTypes(qops);
    qops.add(AUTH_INT);
    assertEquals(EnumSet.of(AUTH), response.getSupportedQopTypes());
  }

  @Test
  public void testSupportedQopTypesDefaultValue() {
    assertEquals(Collections.emptySet(), new DigestChallengeResponse().getSupportedQopTypes());
  }

  @Test
  public void testGetQopAllQopTypesSupportedEntityBodySet() {
    assertEquals(AUTH,
        new DigestChallengeResponse().supportedQopTypes(EnumSet.allOf(QualityOfProtection.class))
            .entityBody(new byte[0])
            .getQop());
  }

  @Test
  public void testGetQopAllQopTypesSupportedEntityBodyNotSet() {
    assertEquals(AUTH,
        new DigestChallengeResponse().supportedQopTypes(EnumSet.allOf(QualityOfProtection.class))
            .getQop());
  }

  @Test
  public void testGetQopAuthSupportedEntityBodySet() {
    assertEquals(AUTH,
        new DigestChallengeResponse().supportedQopTypes(EnumSet.complementOf(EnumSet.of(AUTH_INT)))
            .entityBody(new byte[0])
            .getQop());
  }

  @Test
  public void testGetQopOnlyRfc2069Supported() {
    assertEquals(UNSPECIFIED_RFC2069_COMPATIBLE,
        new DigestChallengeResponse().supportedQopTypes(EnumSet.of(UNSPECIFIED_RFC2069_COMPATIBLE))
            .getQop());
  }

  @Test
  public void testGetQopDefaultValue() {
    assertNull(new DigestChallengeResponse().getQop());
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
  public void testGetAndSetEntityBodyDigest() {
    assertArrayEquals(new byte[]{1, 2, 3},
        new DigestChallengeResponse().entityBodyDigest(new byte[]{1, 2, 3}).getEntityBodyDigest());
  }

  @Test
  public void testEntityBodyDigestDefaultValue() {
    byte[] digest = {-44, 29, -116, -39, -113, 0, -78, 4, -23, -128, 9, -104, -20, -8, 66, 126};
    assertArrayEquals(digest, new DigestChallengeResponse().getEntityBodyDigest());
  }

  @Test
  public void testEntityBodyDigestMd5DefaultValue() {
    byte[] digest = {-44, 29, -116, -39, -113, 0, -78, 4, -23, -128, 9, -104, -20, -8, 66, 126};
    assertArrayEquals(digest, new DigestChallengeResponse().algorithm("MD5").getEntityBodyDigest());
  }

  @Test
  public void testEntityBodyDigestMd5SessDefaultValue() {
    byte[] digest = {-44, 29, -116, -39, -113, 0, -78, 4, -23, -128, 9, -104, -20, -8, 66, 126};
    assertArrayEquals(digest,
        new DigestChallengeResponse().algorithm("MD5-sess").getEntityBodyDigest());
  }

  @Test
  public void testEntityBodyDigestSha256DefaultValue() {
    byte[] digest =
        {-29, -80, -60, 66, -104, -4, 28, 20, -102, -5, -12, -56, -103, 111, -71, 36, 39, -82, 65,
            -28, 100, -101, -109, 76, -92, -107, -103, 27, 120, 82, -72, 85};
    assertArrayEquals(digest,
        new DigestChallengeResponse().algorithm("SHA-256").getEntityBodyDigest());
  }

  @Test
  public void testEntityBodyDigestSha256SessDefaultValue() {
    byte[] digest =
        {-29, -80, -60, 66, -104, -4, 28, 20, -102, -5, -12, -56, -103, 111, -71, 36, 39, -82, 65,
            -28, 100, -101, -109, 76, -92, -107, -103, 27, 120, 82, -72, 85};
    assertArrayEquals(digest,
        new DigestChallengeResponse().algorithm("SHA-256-sess").getEntityBodyDigest());
  }

  @Test
  public void testEntityBodyDigestReturnedIsNotInternalRepresentation() {
    DigestChallengeResponse response = new DigestChallengeResponse();
    byte[] bytes = response.entityBodyDigest(new byte[]{1, 2, 3}).getEntityBodyDigest();
    bytes[0]++;
    assertArrayEquals(new byte[]{1, 2, 3}, response.getEntityBodyDigest());
  }

  @Test
  public void testEntityBodyDigestSetMakesACopy() {
    byte[] bytes = new byte[]{1, 2, 3};
    DigestChallengeResponse response = new DigestChallengeResponse();
    response.entityBodyDigest(bytes);
    bytes[0]++;
    assertArrayEquals(new byte[]{1, 2, 3}, response.getEntityBodyDigest());
  }

  @Test
  public void testSetEntityBodyGetEntityBodyDigest() {
    assertArrayEquals(new byte[]{82, -119, -33, 115, 125, -11, 115, 38, -4, -35, 34, 89, 122, -5,
            31, -84},
        new DigestChallengeResponse().entityBody(new byte[]{1, 2, 3}).getEntityBodyDigest());
  }

  @Test
  public void testIsEntityBodyDigestRequiredOnlyAuthIntSupported() {
    assertTrue(new DigestChallengeResponse().supportedQopTypes(EnumSet.of(AUTH_INT))
        .isEntityBodyDigestRequired());
  }

  @Test
  public void testIsEntityBodyDigestRequiredAuthIntNotSupported() {
    assertFalse(new DigestChallengeResponse().supportedQopTypes(EnumSet.complementOf(EnumSet.of(
        AUTH_INT))).isEntityBodyDigestRequired());
  }

  @Test
  public void testIsEntityBodyDigestRequiredAuthIntAndAuthSupported() {
    assertFalse(new DigestChallengeResponse().supportedQopTypes(EnumSet.of(AUTH, AUTH_INT))
        .isEntityBodyDigestRequired());
  }

  @Test
  public void testIsEntityBodyDigestRequiredAuthIntAndRfc2069Supported() {
    assertTrue(new DigestChallengeResponse().supportedQopTypes(EnumSet.of(AUTH_INT,
        UNSPECIFIED_RFC2069_COMPATIBLE)).isEntityBodyDigestRequired());
  }

  @Test
  public void testIsEntityBodyDigestRequiredDefaultValue() {
    assertFalse(new DigestChallengeResponse().isEntityBodyDigestRequired());
  }

  @Test
  public void testSetChallenge() throws Exception {
    DigestChallenge challenge = DigestChallenge.parse("Digest " +
        "realm=\"testrealm@host.com\", " +
        "qop=\"auth,auth-int\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"");

    DigestChallengeResponse response = new DigestChallengeResponse().challenge(challenge);

    assertEquals(null, response.getAlgorithm());
    assertEquals("dcd98b7102dd2f0e8b11d0f600bfb0c093", response.getNonce());
    assertEquals("5ccc069c403ebaf9f0171e9517f40e41", response.getOpaque());
    assertEquals("testrealm@host.com", response.getRealm());
  }

  @Test
  public void testIsChallengeSupportedSupportedChallengeNoAlgorithm() throws Exception {
    DigestChallenge challenge = DigestChallenge.parse("Digest " +
        "realm=\"testrealm@host.com\", " +
        "qop=\"auth,auth-int\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"");

    assertTrue(DigestChallengeResponse.isChallengeSupported(challenge));
  }

  @Test
  public void testIsChallengeSupportedSupportedChallengeSupportedAlgorithm() throws Exception {
    DigestChallenge challenge = DigestChallenge.parse("Digest " +
        "realm=\"testrealm@host.com\", " +
        "qop=\"auth,auth-int\", " +
        "algorithm=MD5, " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"");

    assertTrue(DigestChallengeResponse.isChallengeSupported(challenge));
  }

  @Test
  public void testIsChallengeSupportedUnsupportedAlgorithm() throws Exception {
    DigestChallenge challenge = DigestChallenge.parse("Digest " +
        "realm=\"testrealm@host.com\", " +
        "qop=\"auth,auth-int\", " +
        "algorithm=XYZ, " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"");

    assertFalse(DigestChallengeResponse.isChallengeSupported(challenge));
  }

  @Test
  public void testIsChallengeNoSupportedQopTypes() throws Exception {
    DigestChallenge challenge = DigestChallenge.parse("Digest " +
        "realm=\"testrealm@host.com\", " +
        "qop=\"custom\", " +
        "algorithm=MD5, " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"");

    assertFalse(DigestChallengeResponse.isChallengeSupported(challenge));
  }

  @Test
  public void testCreateFromChallenge() throws Exception {
    DigestChallenge challenge = DigestChallenge.parse("Digest " +
        "realm=\"testrealm@host.com\", " +
        "qop=\"auth,auth-int\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"");

    DigestChallengeResponse response = DigestChallengeResponse.responseTo(challenge);

    assertEquals(null, response.getAlgorithm());
    assertEquals("dcd98b7102dd2f0e8b11d0f600bfb0c093", response.getNonce());
    assertEquals("5ccc069c403ebaf9f0171e9517f40e41", response.getOpaque());
    assertEquals("testrealm@host.com", response.getRealm());
  }

  @Test(expected = InsufficientInformationException.class)
  public void testMissingUsername() {
    createChallengeFromRfc2617Example().username(null).getHeaderValue();
  }

  @Test(expected = InsufficientInformationException.class)
  public void testMissingPassword() {
    createChallengeFromRfc2617Example().password(null).getHeaderValue();
  }

  @Test(expected = InsufficientInformationException.class)
  public void testMissingRealm() {
    createChallengeFromRfc2617Example().realm(null).getHeaderValue();
  }

  @Test(expected = InsufficientInformationException.class)
  public void testMissingNonce() {
    createChallengeFromRfc2617Example().nonce(null).getHeaderValue();
  }

  @Test(expected = InsufficientInformationException.class)
  public void testMissingDigestUri() {
    createChallengeFromRfc2617Example().digestUri(null).getHeaderValue();
  }

  @Test(expected = InsufficientInformationException.class)
  public void testMissingRequestMethod() {
    createChallengeFromRfc2617Example().requestMethod(null).getHeaderValue();
  }

  @Test(expected = InsufficientInformationException.class)
  public void testMissingClientNonceWhenQopIsAuth() {
    createChallengeFromRfc2617Example().supportedQopTypes(EnumSet.of(AUTH))
        .clientNonce(null)
        .getHeaderValue();
  }

  @Test(expected = InsufficientInformationException.class)
  public void testMissingClientNonceWhenQopIsAuthInt() {
    createChallengeFromRfc2617Example().supportedQopTypes(EnumSet.of(AUTH_INT))
        .entityBody(new byte[0])
        .clientNonce(null)
        .getHeaderValue();
  }

  @Test(expected = InsufficientInformationException.class)
  public void testSupportedQopTypesNotSet() {
    // The example below is from Section 3.5 of RC 2617,
    // https://tools.ietf.org/html/rfc2617#section-3.5
    DigestChallengeResponse response = new DigestChallengeResponse().username("Mufasa")
        .password("Circle Of Life")
        .quotedRealm("\"testrealm@host.com\"")
        .quotedNonce("\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"")
        .digestUri("/dir/index.html")
        .requestMethod("GET")
        .nonceCount(1)
        .clientNonce("0a4f113b")
        .quotedOpaque("\"5ccc069c403ebaf9f0171e9517f40e41\"");

    response.getHeaderValue();
  }

  @Test
  public void testMissingClientNonceWhenQopIsDefault() {
    // CLient nonce need not be specified if qop is not specified
    createChallengeFromRfc2069Example().clientNonce(null).getHeaderValue();
  }

  @Test(expected = InsufficientInformationException.class)
  public void testMissingFirstRequestClientNonceWithMd5SessAlgorithm() throws Exception {
    createChallengeFromRfc2617Example().firstRequestClientNonce(null)
        .algorithm("MD5-sess")
        .getHeaderValue();
  }

  @Test
  public void testMinimalMissingQopHeader() throws Exception {
    DigestChallengeResponse response = new DigestChallengeResponse().username("usr")
        .password("pwd")
        .realm("realm")
        .nonce("nonce")
        .digestUri("/uri")
        .requestMethod("GET")
        .clientNonce("cnonce")
        .supportedQopTypes(EnumSet.of(UNSPECIFIED_RFC2069_COMPATIBLE))
        .firstRequestClientNonce("cnonce");

    String expectedHeader = "Digest username=\"usr\"," +
        "realm=\"realm\"," +
        "nonce=\"nonce\"," +
        "uri=\"/uri\"," +
        "response=\"adba5ae6d43ec9d90bae975312318549\"";

    assertHeadersEqual(expectedHeader, response.getHeaderValue());
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
        .supportedQopTypes(EnumSet.of(AUTH))
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
  public void testMinimalQopAuthIntHeader() throws Exception {
    DigestChallengeResponse response = new DigestChallengeResponse().username("usr")
        .password("pwd")
        .realm("realm")
        .nonce("nonce")
        .digestUri("/uri")
        .requestMethod("POST")
        .entityBody(new byte[0])
        .clientNonce("cnonce")
        .supportedQopTypes(EnumSet.of(AUTH_INT))
        .firstRequestClientNonce("cnonce");

    String expectedHeader = "Digest username=\"usr\"," +
        "realm=\"realm\"," +
        "nonce=\"nonce\"," +
        "uri=\"/uri\"," +
        "qop=auth-int," +
        "response=\"47679b2a05a94bdd675fb8503dab1910\"," +
        "nc=00000001," +
        "cnonce=\"cnonce\"";

    assertHeadersEqual(expectedHeader, response.getHeaderValue());
  }

  @Test
  public void testPreferAuthOverAuthIntIfEntityBodyIsSpecified() throws Exception {
    DigestChallengeResponse response = new DigestChallengeResponse().username("usr")
        .password("pwd")
        .realm("realm")
        .nonce("nonce")
        .digestUri("/uri")
        .requestMethod("POST")
        .entityBody(new byte[0])
        .clientNonce("cnonce")
        .supportedQopTypes(EnumSet.of(AUTH, AUTH_INT))
        .firstRequestClientNonce("cnonce");

    assertEquals("auth", directiveFromHeader(response.getHeaderValue(), "qop"));
  }

  @Test
  public void testPreferAuthOverAuthIntIfEntityBodyIsNotSpecified() throws Exception {
    DigestChallengeResponse response = new DigestChallengeResponse().username("usr")
        .password("pwd")
        .realm("realm")
        .nonce("nonce")
        .digestUri("/uri")
        .requestMethod("POST")
        .clientNonce("cnonce")
        .supportedQopTypes(EnumSet.of(AUTH, AUTH_INT))
        .firstRequestClientNonce("cnonce");

    assertEquals("auth", directiveFromHeader(response.getHeaderValue(), "qop"));
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
        .supportedQopTypes(EnumSet.of(AUTH))
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
        .supportedQopTypes(EnumSet.of(AUTH))
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
        .supportedQopTypes(EnumSet.of(AUTH))
        .firstRequestClientNonce("cnonce")
        .algorithm("MD5");

    String responseBeforeChange = directiveFromHeader(response.getHeaderValue(), "response");

    response.algorithm("MD5-sess");

    assertNotEquals(responseBeforeChange,
        directiveFromHeader(response.getHeaderValue(), "response"));
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
        .supportedQopTypes(EnumSet.of(AUTH))
        .firstRequestClientNonce("cnonce")
        .algorithm("MD5");

    String responseBeforeChange = directiveFromHeader(response.getHeaderValue(), "response");

    response.username("new user");

    assertNotEquals(responseBeforeChange,
        directiveFromHeader(response.getHeaderValue(), "response"));
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
        .supportedQopTypes(EnumSet.of(AUTH))
        .firstRequestClientNonce("cnonce")
        .algorithm("MD5");

    String responseBeforeChange = directiveFromHeader(response.getHeaderValue(), "response");

    response.password("new password");

    assertNotEquals(responseBeforeChange,
        directiveFromHeader(response.getHeaderValue(), "response"));
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
        .supportedQopTypes(EnumSet.of(AUTH))
        .firstRequestClientNonce("cnonce")
        .algorithm("MD5");

    String responseBeforeChange = directiveFromHeader(response.getHeaderValue(), "response");

    response.clientNonce("changed cnonce").firstRequestClientNonce("changed cnonce");

    assertNotEquals(responseBeforeChange,
        directiveFromHeader(response.getHeaderValue(), "response"));
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
        .supportedQopTypes(EnumSet.of(AUTH))
        .firstRequestClientNonce("cnonce")
        .algorithm("MD5-sess");

    String responseBeforeChange = directiveFromHeader(response.getHeaderValue(), "response");

    response.clientNonce("changed cnonce").firstRequestClientNonce("changed cnonce");

    assertNotEquals(responseBeforeChange,
        directiveFromHeader(response.getHeaderValue(), "response"));
  }

  @Test
  public void testMd5SessResponseChangesIfNonceChanges() throws Exception {
    // This might seem redundant but tests that A1 (and other values) is not cached too aggressively
    DigestChallengeResponse response = new DigestChallengeResponse().username("usr")
        .password("pwd")
        .realm("realm")
        .nonce("nonce")
        .digestUri("/uri")
        .requestMethod("GET")
        .clientNonce("cnonce")
        .supportedQopTypes(EnumSet.of(AUTH))
        .firstRequestClientNonce("cnonce")
        .algorithm("MD5-sess");

    response.nonce("changed cnonce");
    // Note: Check the actual value to make sure A1 has not been cached and it is computed in thw
    // wrong way
    assertEquals("\"9a5f5b2b54591dec14ef57762dfa1131\"",
        directiveFromHeader(response.getHeaderValue(), "response"));
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
        .supportedQopTypes(EnumSet.of(AUTH))
        .firstRequestClientNonce("cnonce")
        .algorithm("MD5");

    String responseBeforeChange = directiveFromHeader(response.getHeaderValue(), "response");

    response.firstRequestClientNonce("changed cnonce");

    assertEquals(responseBeforeChange, directiveFromHeader(response.getHeaderValue(), "response"));
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
        .supportedQopTypes(EnumSet.of(AUTH))
        .firstRequestClientNonce("cnonce")
        .algorithm("MD5-sess");

    String responseBeforeChange = directiveFromHeader(response.getHeaderValue(), "response");

    response.firstRequestClientNonce("changed cnonce");

    assertNotEquals(responseBeforeChange,
        directiveFromHeader(response.getHeaderValue(), "response"));
  }

  private DigestChallengeResponse createChallengeFromRfc2617Example() {
    // The example below is from Section 3.5 of RC 2617,
    // https://tools.ietf.org/html/rfc2617#section-3.5
    DigestChallengeResponse response = new DigestChallengeResponse().username("Mufasa")
        .password("Circle Of Life")
        .quotedRealm("\"testrealm@host.com\"")
        .quotedNonce("\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"")
        .digestUri("/dir/index.html")
        .requestMethod("GET")
        .nonceCount(1)
        .clientNonce("0a4f113b")
        .supportedQopTypes(EnumSet.of(AUTH, AUTH_INT))
        .quotedOpaque("\"5ccc069c403ebaf9f0171e9517f40e41\"");

    return response;
  }

  private DigestChallengeResponse createChallengeFromRfc2069Example() {
    // The example below is from Section 2.4 of RC 2069,
    // https://tools.ietf.org/html/rfc2069#section-2.4
    DigestChallengeResponse response = new DigestChallengeResponse().username("Mufasa")
        .password("CircleOfLife")
        .realm("testrealm@host.com")
        .nonce("dcd98b7102dd2f0e8b11d0f600bfb0c093")
        .digestUri("/dir/index.html")
        .requestMethod("GET")
        .supportedQopTypes(EnumSet.of(UNSPECIFIED_RFC2069_COMPATIBLE))
        .opaque("5ccc069c403ebaf9f0171e9517f40e41");

    return response;
  }
}
