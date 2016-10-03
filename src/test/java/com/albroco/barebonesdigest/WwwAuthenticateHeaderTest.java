package com.albroco.barebonesdigest;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static junit.framework.Assert.assertEquals;

public class WwwAuthenticateHeaderTest {

  @Test
  public void testParseAuthParamBasedChallenge() throws Exception {
    String challenge = "Newauth realm=\"apps\", type=1, title=\"Login to \\\"apps\\\"\"";
    assertEquals(Arrays.asList(challenge), WwwAuthenticateHeader.extractChallenges(challenge));
  }

  @Test
  public void testParseAuthParamBasedChallengeOptionalWhitespace() throws Exception {
    String challenge = "Basic realm = \"simple\"  ,  key=\"value\"";
    assertEquals(Arrays.asList(challenge), WwwAuthenticateHeader.extractChallenges(challenge));
  }

  @Test
  public void testParseAuthParamBasedChallengeUnquotedValues() throws Exception {
    String challenge = "Basic realm=simple,key=value";
    assertEquals(Arrays.asList(challenge), WwwAuthenticateHeader.extractChallenges(challenge));
  }

  @Test
  public void testParseAuthParamBasedChallengeUnquotedValuesOptionalWhitespace() throws Exception {
    String challenge = "Basic realm = simple , key = value";
    assertEquals(Arrays.asList(challenge), WwwAuthenticateHeader.extractChallenges(challenge));
  }

  @Test
  public void testParseAuthParamBasedChallengeTrailingWhitespace() throws Exception {
    String challenge = "Basic realm = \"simple\"  ";
    assertEquals(Arrays.asList("Basic realm = \"simple\""),
        WwwAuthenticateHeader.extractChallenges(challenge));
  }

  @Test
  public void testParseSchemeOnlyChallenge() throws Exception {
    String challenge = "Newauth";
    assertEquals(Arrays.asList(challenge), WwwAuthenticateHeader.extractChallenges(challenge));
  }

  @Test
  public void testParseSchemeOnlyChallengeTrailingWhitespace() throws Exception {
    String challenge = "Newauth   ";
    assertEquals(Arrays.asList("Newauth"), WwwAuthenticateHeader.extractChallenges(challenge));
  }

  @Test
  public void testParseToken68BasedChallenge() throws Exception {
    String challenge = "Newauth token68";
    assertEquals(Arrays.asList(challenge), WwwAuthenticateHeader.extractChallenges(challenge));
  }

  @Test
  public void testParseToken68BasedChallengeTrailingWhitespace() throws Exception {
    String challenge = "Newauth token68  ";
    assertEquals(Arrays.asList("Newauth token68"),
        WwwAuthenticateHeader.extractChallenges(challenge));
  }

  @Test
  public void testParseToken68BasedChallengeEndingInEqualsSign() throws Exception {
    String challenge = "Newauth token68==";
    assertEquals(Arrays.asList(challenge), WwwAuthenticateHeader.extractChallenges(challenge));
  }

  @Test
  public void testParseToken68BasedChallengeEndingInEqualsSignTrailingWhitespace() throws
      Exception {
    String challenge = "Newauth token68==  ";
    assertEquals(Arrays.asList("Newauth token68=="),
        WwwAuthenticateHeader.extractChallenges(challenge));
  }

  @Test
  public void testParseEmptyHeader() throws Exception {
    assertEquals(Collections.emptyList(),
        WwwAuthenticateHeader.extractChallenges(""));
  }

  @Test
  public void testExtractFromHeadersNoChallenges() throws Exception {
    assertEquals(Collections.emptyList(),
        WwwAuthenticateHeader.extractChallenges(Collections.<String, List<String>>emptyMap()));
  }

  @Test
  public void testExtractFromHeadersSingleHeader() throws Exception {
    assertEquals(Collections.singletonList("Custom"),
        WwwAuthenticateHeader.extractChallenges(Collections.singletonMap("WWW-Authenticate",
            Arrays.asList("Custom"))));
  }

  @Test
  public void testExtractFromHeadersSingleHeaderCaseInsensitiveHeaderNames() throws Exception {
    assertEquals(Collections.singletonList("Custom"),
        WwwAuthenticateHeader.extractChallenges(Collections.singletonMap("www-AUTHENTICATE",
            Arrays.asList("Custom"))));
  }

  @Test
  public void testExtractFromHeadersMultipleHeaders() throws Exception {
    assertEquals(Arrays.asList("Custom1", "Custom2"),
        WwwAuthenticateHeader.extractChallenges(Collections.singletonMap("WWW-Authenticate",
            Arrays.asList("Custom1", "Custom2"))));
  }

  @Test
  public void testExtractFromWwwAuthenticateHeadersNoChallenges() throws Exception {
    assertEquals(Collections.emptyList(),
        WwwAuthenticateHeader.extractChallenges(Collections.<String>emptyList()));
  }

  @Test
  public void testExtractFromWwwAuthenticateHeadersSingleHeader() throws Exception {
    assertEquals(Collections.singletonList("Custom"),
        WwwAuthenticateHeader.extractChallenges(Arrays.asList("Custom")));
  }

  @Test
  public void testExtractFromWwwAuthenticateHeadersMultipleHeaders() throws Exception {
    assertEquals(Arrays.asList("Custom1", "Custom2"),
        WwwAuthenticateHeader.extractChallenges(Arrays.asList("Custom1", "Custom2")));
  }

  @Test
  public void testExtractFromWwwAuthenticateHeaderSingleHeader() throws Exception {
    assertEquals(Collections.singletonList("Custom"),
        WwwAuthenticateHeader.extractChallenges("Custom"));
  }

  @Test(expected = HttpDigestChallengeParseException.class)
  public void testMalformedChallengeMixToken68AndAuthParam1() throws Exception {
    WwwAuthenticateHeader.extractChallenges("Basic realm=\"simple\", token68=");
  }

  @Test(expected = HttpDigestChallengeParseException.class)
  public void testMalformedChallengeMixToken68AndAuthParam2() throws Exception {
    WwwAuthenticateHeader.extractChallenges("Custom token68==, realm=\"simple\"");
  }

  @Test(expected = HttpDigestChallengeParseException.class)
  public void testMalformedChallengeMissingScheme() throws Exception {
    WwwAuthenticateHeader.extractChallenges("realm=\"simple\"");
  }

  @Test(expected = HttpDigestChallengeParseException.class)
  public void testMalformedChallengeMissingCommas() throws Exception {
    WwwAuthenticateHeader.extractChallenges("Custom1 custom2 custom3");
  }

  @Test(expected = HttpDigestChallengeParseException.class)
  public void testMalformedChallengeEmptyChallenge() throws Exception {
    WwwAuthenticateHeader.extractChallenges("Custom1,,custom2");
  }

  @Test(expected = HttpDigestChallengeParseException.class)
  public void testMalformedChallengeWhitespaceOnlyChallenge() throws Exception {
    WwwAuthenticateHeader.extractChallenges("Custom1, ,custom2");
  }

  @Test(expected = HttpDigestChallengeParseException.class)
  public void testMalformedChallengeWhitespaceOnly() throws Exception {
    assertEquals(Collections.emptyList(),
        WwwAuthenticateHeader.extractChallenges("  "));
  }

  @Test
  public void testParseBasicChallenge() throws Exception {
    String challenge = "Basic realm=\"simple\"";
    assertEquals(Arrays.asList(challenge), WwwAuthenticateHeader.extractChallenges(challenge));
  }

  @Test
  public void testParseDigestAuthChallenge() throws Exception {
    String challenge = "Digest\n" +
        "                 realm=\"testrealm@host.com\",\n" +
        "                 qop=\"auth,auth-int\",\n" +
        "                 nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\n" +
        "                 opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";
    assertEquals(Arrays.asList(challenge), WwwAuthenticateHeader.extractChallenges(challenge));
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
}
