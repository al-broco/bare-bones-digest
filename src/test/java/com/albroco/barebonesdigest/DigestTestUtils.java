// Copyright (c) 2016 Petter Wintzell

package com.albroco.barebonesdigest;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;

public class DigestTestUtils {
  public static void assertHeadersEqual(String expectedHeader, String generatedHeader) {
    // Remove redundant newlines and spaces
    expectedHeader =
        Pattern.compile("\n *", Pattern.MULTILINE).matcher(expectedHeader).replaceAll("");

    assertEquals(directiveAssignmentsFromHeader(expectedHeader),
        directiveAssignmentsFromHeader(generatedHeader));
  }

  public static String directiveFromHeader(String header, String directive) {
    String prefix = directive + "=";
    for (String assignment : directiveAssignmentsFromHeader(header)) {
      if (assignment.startsWith(prefix)) {
        return assignment.substring(prefix.length());
      }
    }
    return null;
  }

  public static Set<String> directiveAssignmentsFromHeader(String header) {
    assertTrue("Header doesn't start with 'Digest '", header.startsWith("Digest "));
    return new HashSet<>(Arrays.asList(header.substring("Digest ".length()).split(",", -1)));
  }
}
