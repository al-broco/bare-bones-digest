package com.albroco.barebonesdigest;

import org.junit.Test;

import static junit.framework.Assert.assertEquals;

public class QualityOfProtectionTest {
  @Test
  public void testAuthQopValue() {
    assertEquals("auth", DigestChallenge.QualityOfProtection.AUTH.getQopValue());
  }

  @Test
  public void testAuthIntQopValue() {
    assertEquals("auth-int", DigestChallenge.QualityOfProtection.AUTH_INT.getQopValue());
  }
}
