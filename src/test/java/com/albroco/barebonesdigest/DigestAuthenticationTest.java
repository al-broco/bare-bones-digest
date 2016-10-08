package com.albroco.barebonesdigest;

import com.android.internal.util.Predicate;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.albroco.barebonesdigest.DigestChallenge.QualityOfProtection.AUTH;
import static com.albroco.barebonesdigest.DigestChallenge.QualityOfProtection.AUTH_INT;
import static com.albroco.barebonesdigest.DigestChallenge.QualityOfProtection
    .UNSPECIFIED_RFC2069_COMPATIBLE;
import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertNull;
import static junit.framework.Assert.assertTrue;

public class DigestAuthenticationTest {
  private static final String AUTH_CHALLENGE =
      "Digest realm=\"\",algorithm=MD5,nonce=\"whatever\",qop=\"auth\"";
  private static final String AUTH_INT_CHALLENGE =
      "Digest realm=\"\",algorithm=MD5,nonce=\"whatever\",qop=\"auth-int\"";
  private static final String AUTH_AUTH_INT_CHALLENGE =
      "Digest realm=\"\",algorithm=MD5,nonce=\"whatever\",qop=\"auth,auth-int\"";
  private static final String LEGACY_CHALLENGE =
      "Digest realm=\"\",algorithm=MD5,nonce=\"whatever\"";
  private static final String UNSUPPORTED_QOP_CHALLENGE =
      "Digest realm=\"\",algorithm=MD5,nonce=\"whatever\",qop=\"custom\"";
  private static final String UNSUPPORTED_ALGORITHM_CHALLENGE =
      "Digest realm=\"\",algorithm=UNSUPPORTED,nonce=\"whatever\",qop=\"auth,auth-int\"";
  private static final String UNSUPPORTED_SCHEME_CHALLENGE = "Basic realm=\"\"";

  @Test
  public void testCreateFromHeadersOneHeader() throws Exception {
    Map<String, List<String>> headers = new HashMap<>();
    headers.put("WWW-Authenticate", Collections.singletonList(AUTH_CHALLENGE));

    DigestAuthentication auth = DigestAuthentication.fromResponseHeaders(headers);
    assertTrue(auth.canRespond());
  }

  @Test
  public void testCreateFromHeadersOneHeaderMultipleChallenges() throws Exception {
    Map<String, List<String>> headers = new HashMap<>();
    headers.put("WWW-Authenticate",
        Collections.singletonList(AUTH_CHALLENGE + "," + AUTH_AUTH_INT_CHALLENGE));

    DigestAuthentication auth = DigestAuthentication.fromResponseHeaders(headers);
    assertTrue(auth.canRespond());
  }

  @Test
  public void testCreateFromHeadersTwoHeaders() throws Exception {
    Map<String, List<String>> headers = new HashMap<>();
    headers.put("WWW-Authenticate", Arrays.asList(AUTH_CHALLENGE, AUTH_AUTH_INT_CHALLENGE));

    DigestAuthentication auth = DigestAuthentication.fromResponseHeaders(headers);
    assertTrue(auth.canRespond());
  }

  @Test
  public void testCreateFromHeadersMissingHeader() throws Exception {
    DigestAuthentication auth =
        DigestAuthentication.fromResponseHeaders(Collections.<String, List<String>>emptyMap());
    assertFalse(auth.canRespond());
  }

  @Test
  public void testCreateFromHeadersPickBestChallenge() throws Exception {
    Map<String, List<String>> headers = new HashMap<>();
    headers.put("WWW-Authenticate",
        Arrays.asList(AUTH_CHALLENGE, AUTH_INT_CHALLENGE, AUTH_AUTH_INT_CHALLENGE));

    DigestAuthentication auth = DigestAuthentication.fromResponseHeaders(headers);
    assertTrue(auth.canRespond());
    assertEquals(EnumSet.of(AUTH, AUTH_INT), auth.getChallengeResponse().getSupportedQopTypes());
  }

  @Test
  public void testCreateFromHeadersFilterIncompatibleChallenges() throws Exception {
    Map<String, List<String>> headers = new HashMap<>();
    headers.put("WWW-Authenticate",
        Arrays.asList(UNSUPPORTED_ALGORITHM_CHALLENGE,
            UNSUPPORTED_QOP_CHALLENGE,
            UNSUPPORTED_SCHEME_CHALLENGE));

    DigestAuthentication auth = DigestAuthentication.fromResponseHeaders(headers);
    assertFalse(auth.canRespond());
  }

  @Test(expected = HttpDigestChallengeParseException.class)
  public void testCreateFromHeadersMalformedHeader() throws Exception {
    Map<String, List<String>> headers = new HashMap<>();
    headers.put("WWW-Authenticate", Collections.singletonList("x x x"));
    DigestAuthentication.fromResponseHeaders(headers);
  }

  @Test
  public void testCreateFromWwwAuthHeadersOneHeader() throws Exception {
    DigestAuthentication auth =
        DigestAuthentication.fromWwwAuthenticateHeaders(Collections.singleton(AUTH_CHALLENGE));
    assertTrue(auth.canRespond());
  }

  @Test
  public void testCreateFromWwwAuthHeadersOneHeaderMultipleChallenges() throws Exception {
    DigestAuthentication auth =
        DigestAuthentication.fromWwwAuthenticateHeaders(Collections.singleton(
            AUTH_CHALLENGE + "," + AUTH_INT_CHALLENGE));
    assertTrue(auth.canRespond());
  }

  @Test
  public void testCreateFromWwwAuthHeadersTwoHeaders() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeaders(Arrays.asList(
        AUTH_CHALLENGE,
        AUTH_AUTH_INT_CHALLENGE));
    assertTrue(auth.canRespond());
  }

  @Test
  public void testCreateFromWwwAuthHeadersMissingHeader() throws Exception {
    DigestAuthentication auth =
        DigestAuthentication.fromWwwAuthenticateHeaders(Collections.<String>emptyList());
    assertFalse(auth.canRespond());
  }

  @Test
  public void testCreateFromWwwAuthHeadersPickBestChallenge() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeaders(Arrays.asList(
        AUTH_CHALLENGE,
        AUTH_INT_CHALLENGE,
        AUTH_AUTH_INT_CHALLENGE));

    assertTrue(auth.canRespond());
    assertEquals(EnumSet.of(AUTH, AUTH_INT), auth.getChallengeResponse().getSupportedQopTypes());
  }

  @Test
  public void testCreateFromWwwAuthHeadersFilterIncompatibleChallenges() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeaders(Arrays.asList(
        UNSUPPORTED_ALGORITHM_CHALLENGE,
        UNSUPPORTED_QOP_CHALLENGE,
        UNSUPPORTED_SCHEME_CHALLENGE));
    assertFalse(auth.canRespond());
  }

  @Test(expected = HttpDigestChallengeParseException.class)
  public void testCreateFromWwwAuthHeadersMalformedHeader() throws Exception {
    DigestAuthentication.fromWwwAuthenticateHeaders(Collections.singletonList("x x x"));
  }

  @Test
  public void testCreateFromWwwAuthHeader() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_CHALLENGE);
    assertTrue(auth.canRespond());
  }

  @Test
  public void testCreateFromWwwAuthHeaderTwoChallenges() throws Exception {
    DigestAuthentication auth =
        DigestAuthentication.fromWwwAuthenticateHeader(AUTH_CHALLENGE + "," + AUTH_INT_CHALLENGE);
    assertTrue(auth.canRespond());
  }

  @Test
  public void testCreateFromWwwAuthHeaderMissingChallenge() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader("");
    assertFalse(auth.canRespond());
  }

  @Test
  public void testCreateFromWwwAuthHeaderPickBestChallenge() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(
        AUTH_CHALLENGE + "," + AUTH_INT_CHALLENGE + "," + AUTH_AUTH_INT_CHALLENGE);
    assertTrue(auth.canRespond());
    assertEquals(EnumSet.of(AUTH, AUTH_INT), auth.getChallengeResponse().getSupportedQopTypes());
  }

  @Test
  public void testCreateFromAuthHeaderFilterIncompatibleChallenges() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(
        UNSUPPORTED_ALGORITHM_CHALLENGE + "," + UNSUPPORTED_QOP_CHALLENGE + "," +
            UNSUPPORTED_SCHEME_CHALLENGE);
    assertFalse(auth.canRespond());
  }

  @Test(expected = HttpDigestChallengeParseException.class)
  public void testCreateFromWwwAuthHeaderMalformedHeader() throws Exception {
    DigestAuthentication.fromWwwAuthenticateHeader("x x x");
  }

  @Test
  public void testCreateFromChallengesOneChallenge() throws Exception {
    DigestAuthentication auth =
        DigestAuthentication.fromChallenges(Collections.singleton(AUTH_CHALLENGE));
    assertTrue(auth.canRespond());
  }

  @Test
  public void testCreateFromChallengesTwoChallenges() throws Exception {
    DigestAuthentication auth =
        DigestAuthentication.fromChallenges(Arrays.asList(AUTH_CHALLENGE, AUTH_AUTH_INT_CHALLENGE));
    assertTrue(auth.canRespond());
  }

  @Test
  public void testCreateFromChallengesMissingChallenge() throws Exception {
    DigestAuthentication auth =
        DigestAuthentication.fromChallenges(Collections.<String>emptyList());
    assertFalse(auth.canRespond());
  }

  @Test
  public void testCreateFromChallengesPickBestChallenge() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromChallenges(Arrays.asList(AUTH_CHALLENGE,
        AUTH_AUTH_INT_CHALLENGE,
        AUTH_AUTH_INT_CHALLENGE));

    assertTrue(auth.canRespond());
    assertEquals(EnumSet.of(AUTH, AUTH_INT), auth.getChallengeResponse().getSupportedQopTypes());
  }

  @Test
  public void testCreateFromChallengesFilterIncompatibleChallenges() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromChallenges(Arrays.asList(
        UNSUPPORTED_ALGORITHM_CHALLENGE,
        UNSUPPORTED_QOP_CHALLENGE,
        UNSUPPORTED_SCHEME_CHALLENGE));
    assertFalse(auth.canRespond());
  }

  @Test(expected = HttpDigestChallengeParseException.class)
  public void testCreateFromChallengesMalformedChallenge() throws Exception {
    DigestAuthentication.fromChallenges(Collections.singleton("Digest x x x"));
  }

  @Test
  public void testCreateFromDigestChallengesOneChallenge() throws Exception {
    DigestAuthentication auth =
        DigestAuthentication.fromDigestChallenges(Collections.singleton(DigestChallenge.parse(
            AUTH_CHALLENGE)));
    assertTrue(auth.canRespond());
  }

  @Test
  public void testCreateFromDigestChallengesTwoChallenges() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromDigestChallenges(Arrays.asList(
        DigestChallenge.parse(AUTH_CHALLENGE),
        DigestChallenge.parse(AUTH_AUTH_INT_CHALLENGE)));
    assertTrue(auth.canRespond());
  }

  @Test
  public void testCreateFromDigestChallengesMissingChallenge() throws Exception {
    DigestAuthentication auth =
        DigestAuthentication.fromDigestChallenges(Collections.<DigestChallenge>emptyList());
    assertFalse(auth.canRespond());
  }

  @Test
  public void testCreateFromDigestChallengesPickBestChallenge() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromDigestChallenges(Arrays.asList(
        DigestChallenge.parse(AUTH_CHALLENGE),
        DigestChallenge.parse(AUTH_INT_CHALLENGE),
        DigestChallenge.parse(AUTH_AUTH_INT_CHALLENGE)));
    assertTrue(auth.canRespond());
    assertEquals(EnumSet.of(AUTH, AUTH_INT), auth.getChallengeResponse().getSupportedQopTypes());
  }

  @Test
  public void testCreateDigestChallengesFilterIncompatibleChallenges() throws Exception {
    DigestAuthentication auth =
        DigestAuthentication.fromDigestChallenges(Arrays.asList(DigestChallenge.parse(
            UNSUPPORTED_ALGORITHM_CHALLENGE), DigestChallenge.parse(UNSUPPORTED_QOP_CHALLENGE)));
    assertFalse(auth.canRespond());
  }

  @Test
  public void testCreateFromDigestChallenge() throws Exception {
    DigestAuthentication auth =

        DigestAuthentication.fromDigestChallenge(DigestChallenge.parse(AUTH_CHALLENGE));
    assertTrue(auth.canRespond());
  }

  @Test
  public void testCreateDigestChallengeFilterIncompatibleChallenges() throws Exception {
    DigestAuthentication auth =
        DigestAuthentication.fromDigestChallenge(DigestChallenge.parse(UNSUPPORTED_QOP_CHALLENGE));
    assertFalse(auth.canRespond());
  }

  @Test
  public void testCanRespondToValidChallenge() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_CHALLENGE);
    assertTrue(auth.canRespond());
  }

  @Test
  public void testCannotRespondToUnsupportedChallenge() throws Exception {
    DigestAuthentication auth =
        DigestAuthentication.fromWwwAuthenticateHeader(UNSUPPORTED_QOP_CHALLENGE);
    assertFalse(auth.canRespond());
  }

  @Test
  public void testCanRespondOneValidOneUnsupportedChallenge() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(
        AUTH_CHALLENGE + "," + UNSUPPORTED_QOP_CHALLENGE);
    assertTrue(auth.canRespond());
  }

  @Test
  public void testCannotRespondToMissingChallenges() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader("");
    assertFalse(auth.canRespond());
  }

  @Test
  public void testFilterChallengesNoChange() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_CHALLENGE);
    auth.filterChallenges(new Predicate<Object>() {
      @Override
      public boolean apply(Object o) {
        return true;
      }
    });

    assertEquals(EnumSet.of(AUTH), auth.getChallengeResponse().getSupportedQopTypes());
  }

  @Test
  public void testFilterChallengesRemoveAllChallenges() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_CHALLENGE);
    auth.filterChallenges(new Predicate<Object>() {
      @Override
      public boolean apply(Object o) {
        return false;
      }
    });

    assertFalse(auth.canRespond());
  }

  @Test
  public void testFilterChallengesRemoveOneChallenge() throws Exception {
    DigestAuthentication auth =
        DigestAuthentication.fromWwwAuthenticateHeader(AUTH_CHALLENGE + "," + LEGACY_CHALLENGE);
    // Filter to remove the auth qop challenge
    auth.filterChallenges(new Predicate<DigestChallenge>() {
      @Override
      public boolean apply(DigestChallenge challenge) {
        return !challenge.getSupportedQopTypes().contains(AUTH);
      }
    });
    assertEquals(EnumSet.of(UNSPECIFIED_RFC2069_COMPATIBLE),
        auth.getChallengeResponse().getSupportedQopTypes());
  }

  @Test
  public void testFilterChallengesExcludeAuthIntFilterRemovesChallengeThatSupportsOnlyAuthInt()
      throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_INT_CHALLENGE)
        .filterChallenges(DigestAuthentication.EXCLUDE_AUTH_INT_FILTER);
    assertFalse(auth.canRespond());
  }

  @Test
  public void
  testFilterChallengesExcludeAuthIntFilterDoesNotRemoveChallengeThatSupportAuthAndAuthInt()
      throws Exception {
    DigestAuthentication auth =
        DigestAuthentication.fromWwwAuthenticateHeader(AUTH_AUTH_INT_CHALLENGE)
            .filterChallenges(DigestAuthentication.EXCLUDE_AUTH_INT_FILTER);
    assertTrue(auth.canRespond());
  }

  @Test
  public void testFilterChallengesExcludeLegacyQopFilterRemovesChallengeThatSupportsOnlyLegacy()
      throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(LEGACY_CHALLENGE)
        .filterChallenges(DigestAuthentication.EXCLUDE_LEGACY_QOP_FILTER);
    assertFalse(auth.canRespond());
  }

  @Test
  public void
  testFilterChallengesExcludeLegacyQopFilterDoesNotRemoveChallengeThatSupportAuthAndLegacy()
      throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_CHALLENGE)
        .filterChallenges(DigestAuthentication.EXCLUDE_LEGACY_QOP_FILTER);
    assertTrue(auth.canRespond());
  }

  @Test(expected = IllegalStateException.class)
  public void testFilterChallengesAfterChellengeHasBeenChosen() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_CHALLENGE);
    auth.getChallengeResponse();
    auth.filterChallenges(DigestAuthentication.EXCLUDE_LEGACY_QOP_FILTER);
  }

  @Test
  public void testReorderChallenges() throws Exception {
    DigestAuthentication auth =
        DigestAuthentication.fromWwwAuthenticateHeader(AUTH_CHALLENGE + "," + LEGACY_CHALLENGE);
    auth.challengeOrdering(Collections.reverseOrder(DigestAuthentication
        .DEFAULT_CHALLENGE_COMPARATOR));
    assertEquals(EnumSet.of(UNSPECIFIED_RFC2069_COMPATIBLE),
        auth.getChallengeResponse().getSupportedQopTypes());
  }

  @Test(expected = IllegalStateException.class)
  public void testReorderChallengesAfterChellengeHasBeenChosen() throws Exception {
    DigestAuthentication auth =
        DigestAuthentication.fromWwwAuthenticateHeader(AUTH_CHALLENGE + "," + LEGACY_CHALLENGE);
    auth.getChallengeResponse();
    auth.challengeOrdering(DigestAuthentication.DEFAULT_CHALLENGE_COMPARATOR);
  }


  @Test
  public void testIsEntityBodyDigestRequiredAuthQop() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_CHALLENGE);
    assertFalse(auth.isEntityBodyDigestRequired());
  }

  @Test
  public void testIsEntityBodyDigestRequiredAuthIntQop() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_INT_CHALLENGE);
    assertTrue(auth.isEntityBodyDigestRequired());
  }

  @Test
  public void testGetAndSetUsernameBeforeChallengeChosen() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_INT_CHALLENGE);
    assertEquals("user", auth.username("user").getUsername());
  }

  @Test
  public void testUsernameDefaultValueBeforeChallengeChosen() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_INT_CHALLENGE);
    assertNull(auth.getUsername());
  }

  @Test
  public void testUnsetUsernameBeforeChallengeChosen() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_INT_CHALLENGE);
    assertNull(auth.username("username").username(null).getUsername());
  }

  @Test
  public void testGetAndSetUsernameAfterChallengeChosen() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_INT_CHALLENGE);
    auth.getChallengeResponse();
    assertEquals("user", auth.username("user").getUsername());
  }

  @Test
  public void testUsernameDefaultValueAfterChallengeChosen() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_INT_CHALLENGE);
    auth.getChallengeResponse();
    assertNull(auth.getUsername());
  }

  @Test
  public void testUnsetUsernameAfterChallengeChosen() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_INT_CHALLENGE);
    auth.getChallengeResponse();
    assertNull(auth.username("username").username(null).getUsername());
  }

  @Test
  public void testSetUsernameBeforeChallengeChosenChangesChallenge() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_INT_CHALLENGE);
    auth.username("user");
    assertEquals("user", auth.getChallengeResponse().getUsername());
  }

  @Test
  public void testSetUsernameAfterChallengeChosenChangesChallenge() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_INT_CHALLENGE);
    auth.getChallengeResponse();
    auth.username("user");
    assertEquals("user", auth.getChallengeResponse().getUsername());
  }

  @Test
  public void testSetUsernameOnChallengeChangesAuth() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_INT_CHALLENGE);
    auth.getChallengeResponse().username("user");
    assertEquals("user", auth.getUsername());
  }

  @Test
  public void testGetAndSetPasswordBeforeChallengeChosen() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_INT_CHALLENGE);
    assertEquals("pwd", auth.password("pwd").getPassword());
  }

  @Test
  public void testPasswordDefaultValueBeforeChallengeChosen() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_INT_CHALLENGE);
    assertNull(auth.getPassword());
  }

  @Test
  public void testUnsetPasswordBeforeChallengeChosen() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_INT_CHALLENGE);
    assertNull(auth.password("pwd").password(null).getPassword());
  }

  @Test
  public void testGetAndSetPasswordAfterChallengeChosen() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_INT_CHALLENGE);
    auth.getChallengeResponse();
    assertEquals("pwd", auth.password("pwd").getPassword());
  }

  @Test
  public void testPasswordDefaultValueAfterChallengeChosen() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_INT_CHALLENGE);
    auth.getChallengeResponse();
    assertNull(auth.getPassword());
  }

  @Test
  public void testUnsetPasswordAfterChallengeChosen() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_INT_CHALLENGE);
    auth.getChallengeResponse();
    assertNull(auth.password("pwd").password(null).getPassword());
  }

  @Test
  public void testSetPasswordBeforeChallengeChosenChangesChallenge() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_INT_CHALLENGE);
    auth.password("pwd");
    assertEquals("pwd", auth.getChallengeResponse().getPassword());
  }

  @Test
  public void testSetPasswordAfterChallengeChosenChangesChallenge() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_INT_CHALLENGE);
    auth.getChallengeResponse();
    auth.password("pwd");
    assertEquals("pwd", auth.getChallengeResponse().getPassword());
  }

  @Test
  public void testSetPasswordOnChallengeChangesAuth() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_INT_CHALLENGE);
    auth.getChallengeResponse().password("pwd");
    assertEquals("pwd", auth.getPassword());
  }

  @Test
  public void testGetChallengeResponse() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_CHALLENGE);
    assertNotNull(auth.getChallengeResponse());
  }

  @Test(expected = IllegalStateException.class)
  public void testGetChallengeResponseNoSupportedChallenge() throws Exception {
    DigestAuthentication auth =
        DigestAuthentication.fromWwwAuthenticateHeader(UNSUPPORTED_QOP_CHALLENGE);
    auth.getChallengeResponse();
  }

  @Test
  public void testGetAuthorizationForRequest() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_CHALLENGE);
    String authorization =
        auth.username("user").password("passwd").getAuthorizationForRequest("GET", "/index.html");
    assertNotNull(authorization);
    assertTrue("Header doesn't start with 'Digest ': " + authorization,
        authorization.startsWith("Digest "));
  }

  @Test
  public void testGetAuthorizationForRequestStartsAtNonceCount1() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_CHALLENGE);
    String authorization =
        auth.username("user").password("passwd").getAuthorizationForRequest("GET", "/index.html");
    assertNotNull(authorization);
    Set<String> assignments = DigestTestUtils.directiveAssignmentsFromHeader(authorization);
    String expectedAssignment = "nc=00000001";
    assertTrue("Missing assignment " + expectedAssignment + ", hdr: " + authorization,
        assignments.contains(expectedAssignment));
  }

  @Test
  public void testGetAuthorizationForRequestNonceCountIncreasesForEachInvocation() throws
      Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_CHALLENGE);
    auth.username("user").password("passwd").getAuthorizationForRequest("GET", "/index.html");
    String authorization = auth.getAuthorizationForRequest("GET", "/index.html");
    assertNotNull(authorization);
    Set<String> assignments = DigestTestUtils.directiveAssignmentsFromHeader(authorization);
    String expectedAssignment = "nc=00000002";
    assertTrue("Missing assignment " + expectedAssignment + ", hdr: " + authorization,
        assignments.contains(expectedAssignment));
  }

  @Test(expected = InsufficientInformationException.class)
  public void testGetAuthorizationForRequestMissingEnitityBodyDigest() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_INT_CHALLENGE);
    auth.username("user").password("passwd").getAuthorizationForRequest("GET", "/index.html");
  }

  @Test
  public void testGetAuthorizationForRequestEnitityBodySetOnChallengeResponse() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_INT_CHALLENGE);
    auth.username("user").password("passwd").getChallengeResponse().entityBody(new byte[0]);
    String authorization = auth.getAuthorizationForRequest("POST", "/index.html", new byte[0]);
    assertNotNull(authorization);
  }

  @Test(expected = IllegalStateException.class)
  public void testGetAuthorizationForRequestNoValidChallenges() throws Exception {
    DigestAuthentication auth =
        DigestAuthentication.fromWwwAuthenticateHeader(UNSUPPORTED_QOP_CHALLENGE);
    auth.username("user").password("passwd").getAuthorizationForRequest("GET", "/index.html");
  }

  @Test
  public void testGetAuthorizationForRequestWithEntityBody() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_INT_CHALLENGE);
    String authorization = auth.username("user")
        .password("passwd")
        .getAuthorizationForRequest("POST", "/index.html", new byte[0]);
    assertNotNull(authorization);
    assertTrue("Header doesn't start with 'Digest ': " + authorization,
        authorization.startsWith("Digest "));
  }

  @Test
  public void testGetAuthorizationForRequestWithEntityBodyStartsAtNonceCount1() throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_INT_CHALLENGE);
    String authorization = auth.username("user")
        .password("passwd")
        .getAuthorizationForRequest("POST", "/index.html", new byte[0]);
    assertNotNull(authorization);
    Set<String> assignments = DigestTestUtils.directiveAssignmentsFromHeader(authorization);
    String expectedAssignment = "nc=00000001";
    assertTrue("Missing assignment " + expectedAssignment + ", hdr: " + authorization,
        assignments.contains(expectedAssignment));
  }

  @Test
  public void testGetAuthorizationForRequestWithEntityBodyNonceCountIncreasesForEachInvocation()
      throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_INT_CHALLENGE);
    auth.username("user")
        .password("passwd")
        .getAuthorizationForRequest("POST", "/index.html", new byte[0]);
    String authorization = auth.getAuthorizationForRequest("POST", "/index.html", new byte[0]);
    assertNotNull(authorization);
    Set<String> assignments = DigestTestUtils.directiveAssignmentsFromHeader(authorization);
    String expectedAssignment = "nc=00000002";
    assertTrue("Missing assignment " + expectedAssignment + ", hdr: " + authorization,
        assignments.contains(expectedAssignment));
  }

  @Test(expected = IllegalStateException.class)
  public void testGetAuthorizationForRequestWithEntityBodyNoValidChallenges() throws Exception {
    DigestAuthentication auth =
        DigestAuthentication.fromWwwAuthenticateHeader(UNSUPPORTED_QOP_CHALLENGE);
    auth.username("user")
        .password("passwd")
        .getAuthorizationForRequest("POST", "/index.html", new byte[0]);
  }

  @Test(expected = InsufficientInformationException.class)
  public void testGetAuthorizationForRequestWithEntityEntityBodyNotReusedInSubsequentRequests()
      throws Exception {
    DigestAuthentication auth = DigestAuthentication.fromWwwAuthenticateHeader(AUTH_INT_CHALLENGE);
    // This should work:
    auth.username("user")
        .password("passwd")
        .getAuthorizationForRequest("POST", "/index.html", new byte[0]);
    // THis should fail:
    auth.username("user").password("passwd").getAuthorizationForRequest("POST", "/index.html");
  }
}
