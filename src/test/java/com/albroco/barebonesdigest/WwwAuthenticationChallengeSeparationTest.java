// Copyright (c) 2016 Petter Wintzell

package com.albroco.barebonesdigest;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static junit.framework.Assert.assertEquals;
import static org.junit.runners.Parameterized.Parameters;

/**
 * Brute force test that checks that the parser correctly identifies where one challenge ends and
 * the next starts.
 */
@RunWith(Parameterized.class)
public class WwwAuthenticationChallengeSeparationTest {
  private static final String[] CHALLENGES =
      {"CustomOneWord", "CustomToken68 token68", "CustomToken68 token68=",
          "Newauth realm=\"apps\", type=1, title=\"Login to \\\"apps\\\"\"", "Digest\n" +
          "                 realm=\"testrealm@host.com\",\n" +
          "                 qop=\"auth,auth-int\",\n" +
          "                 nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\n" +
          "                 opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"",
          "CustomVariedSpacing  realm = \"realm\" , quote=\"\\\"\",key=value"};

  private static final String[] DELIMITERS = {",", " , "};

  @Parameters(name = "Parse header {0}")
  public static Iterable<Object[]> data() {
    List<Object[]> data = new ArrayList<>();

    for (String challenge1 : CHALLENGES) {
      for (String challenge2 : CHALLENGES) {
        for (String challenge3 : CHALLENGES) {
          for (String delimiter : DELIMITERS) {
            String header = joinStrings(delimiter, challenge1, challenge2, challenge3);
            data.add(new Object[]{header, new String[]{challenge1, challenge2, challenge3}});
          }
        }
      }
    }

    return data;
  }

  private final String header;
  private final String[] challenges;

  public WwwAuthenticationChallengeSeparationTest(String header, String[] challenges) {
    this.header = header;
    this.challenges = challenges;
  }

  @Test
  public void test() throws Exception {
    List<String> expectedResult = Arrays.asList(challenges);
    assertEquals(expectedResult, WwwAuthenticateHeader.extractChallenges(header));
  }

  private static String joinStrings(String delimiter, String... strings) {
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
