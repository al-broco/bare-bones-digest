package com.albroco.barebonesdigest;

import org.junit.Test;

import static com.albroco.barebonesdigest.DigestAuthentication.QopFilter;
import static com.albroco.barebonesdigest.DigestChallenge.QualityOfProtection.AUTH;
import static com.albroco.barebonesdigest.DigestChallenge.QualityOfProtection
    .UNSPECIFIED_RFC2069_COMPATIBLE;
import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertTrue;

public class DigestAuthenticationQopFilterTest {
  private static final DigestChallenge AUTH_CHALLENGE;
  private static final DigestChallenge AUTH_AUTH_INT_CHALLENGE;
  private static final DigestChallenge LEGACY_CHALLENGE;

  static {
    try {
      AUTH_CHALLENGE =
          DigestChallenge.parse("Digest realm=\"\",algorithm=MD5,nonce=\"whatever\",qop=\"auth\"");
      AUTH_AUTH_INT_CHALLENGE = DigestChallenge.parse(
          "Digest realm=\"\",algorithm=MD5,nonce=\"whatever\",qop=\"auth,auth-int\"");
      LEGACY_CHALLENGE =
          DigestChallenge.parse("Digest realm=\"\",algorithm=MD5,nonce=\"whatever\"");
    } catch (HttpDigestChallengeParseException e) {
      e.printStackTrace();
      throw new RuntimeException(e);
    }
  }

  @Test
  public void testQopFilterAllowingQopsSupportedQop() {
    assertTrue(QopFilter.allowingQops(AUTH).apply(AUTH_CHALLENGE));
    assertTrue(QopFilter.allowingQops(AUTH).apply(AUTH_AUTH_INT_CHALLENGE));
  }

  @Test
  public void testQopFilterAllowingQopsUnsupportedQop() {
    assertFalse(QopFilter.allowingQops(AUTH).apply(LEGACY_CHALLENGE));
  }

  @Test
  public void testQopFilterDisallowingQopsSupportsOtherQops() {
    assertTrue(QopFilter.disallowingQops(AUTH).apply(AUTH_AUTH_INT_CHALLENGE));
  }

  @Test
  public void testQopFilterDisallowingQopsSupportingOnlyThatQop() {
    assertFalse(QopFilter.disallowingQops(UNSPECIFIED_RFC2069_COMPATIBLE).apply(LEGACY_CHALLENGE));
  }
}
