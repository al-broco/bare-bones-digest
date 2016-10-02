package com.albroco.barebonesdigest;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static junit.framework.Assert.assertEquals;

public class WwwAuthenticateHeaderTest {

  @Test
  public void testParseSingleBasicAuthChallenge() throws Exception {
    String challenge = "Basic realm=\"simple\"";
    assertEquals(Arrays.asList(challenge), WwwAuthenticateHeader.extractChallenges(challenge));
  }

  @Test
  public void testParseSingleDigestAuthChallenge() throws Exception {
    String challenge = "Digest\n" +
        "                 realm=\"testrealm@host.com\",\n" +
        "                 qop=\"auth,auth-int\",\n" +
        "                 nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\n" +
        "                 opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";
    assertEquals(Arrays.asList(challenge), WwwAuthenticateHeader.extractChallenges(challenge));
  }

  @Test
  public void testParseSingleCustomAuthChallengeSchemeOnly() throws Exception {
    String challenge = "Newauth";
    assertEquals(Arrays.asList(challenge), WwwAuthenticateHeader.extractChallenges(challenge));
  }

  @Test
  public void testParseSingleCustomAuthChallengeAuthParamBased() throws Exception {
    String challenge = "Newauth realm=\"apps\", type=1, title=\"Login to \\\"apps\\\"\"";
    ;
    assertEquals(Arrays.asList(challenge), WwwAuthenticateHeader.extractChallenges(challenge));
  }

  @Test
  public void testParseSingleCustomAuthChallengeToken68Based() throws Exception {
    String challenge = "Newauth token68";
    assertEquals(Arrays.asList(challenge), WwwAuthenticateHeader.extractChallenges(challenge));
  }

  @Test
  public void testParseSingleCustomAuthChallengeToken68EndingInEqualsSignBased() throws Exception {
    String challenge = "Newauth token68==";
    assertEquals(Arrays.asList(challenge), WwwAuthenticateHeader.extractChallenges(challenge));
  }

  @Test
  public void testMultipleAuthParamBasedChallenges() throws Exception {
    testMultipleChallenges("Basic realm=\"realm1\"", "Basic realm=\"realm2\"");
  }

  @Test
  public void testMultipleSchemeOnlyChallenges() throws Exception {
    testMultipleChallenges("Custom1", "Custom2");
  }

  @Test
  public void testMultipleToken68BasedChallenges() throws Exception {
    testMultipleChallenges("Custom1 token68", "Custom2 token68");
  }

  @Test
  public void testMultipleToken68BasedChallengesEndingInEuqlaitySigns() throws Exception {
    testMultipleChallenges("Custom1 token68==", "Custom2 token68==");
  }

  @Test
  public void test7235ExampleChallenge() throws Exception {
    String challenges = "Newauth realm=\"apps\", type=1,\n" +
        "                       title=\"Login to \\\"apps\\\"\", Basic realm=\"simple\"";

    List<String> expectedResult = new ArrayList<>(2);
    expectedResult.add("Newauth realm=\"apps\", type=1,\n" +
        "                       title=\"Login to \\\"apps\\\"\"");
    expectedResult.add("Basic realm=\"simple\"");

    assertEquals(expectedResult, WwwAuthenticateHeader.extractChallenges(challenges));
  }

  private void testMultipleChallenges(String... challenges) throws
      HttpDigestChallengeParseException {
    // Test parsing the challenges joined by a comma
    assertEquals(Arrays.asList(challenges),
        WwwAuthenticateHeader.extractChallenges(joinStrings(",", challenges)));
    // Also test parsing the challenges joined by some excessive whitespace
    assertEquals(Arrays.asList(challenges),
        WwwAuthenticateHeader.extractChallenges(joinStrings(" , ", challenges)));
  }

  private String joinStrings(String delimiter, String... strings) {
    StringBuilder result = new StringBuilder();
    for (String string : strings) {
      if (result.length() > 0) {
        result.append(delimiter);
      }
      result.append(string);
    }
    return result.toString();
  }
}
