// Copyright (c) 2016 Petter Wintzell

package com.albroco.barebonesdigest;

import org.junit.Test;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertNotNull;

public class Rfc2116AbnfParserTest {
  @Test
  public void testConsumeMatchingLiteral() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("literal");
    parser.consumeLiteral("literal");
    assertEquals("literal", parser.get());
  }

  @Test
  public void testConsumeMatchingLiteralCaseInsensitive() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("Literal");
    parser.consumeLiteral("literal");
    assertEquals("Literal", parser.get());
  }

  @Test(expected = Rfc2616AbnfParser.ParseException.class)
  public void testConsumeLiteralNoMatchLookingForShorterString() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("mismatch");
    parser.consumeLiteral("literal");
  }

  @Test(expected = Rfc2616AbnfParser.ParseException.class)
  public void testConsumeLiteralNoMatchLookingForLongerString() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("mismatch");
    parser.consumeLiteral("long literal text");
  }

  @Test(expected = Rfc2616AbnfParser.ParseException.class)
  public void testConsumeLiteralEmptySourceString() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("");
    parser.consumeLiteral("mismatch");
  }

  @Test
  public void testConsumeLiteralEmptyLiteral() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("");
    parser.consumeLiteral("");
    assertEquals("", parser.get());
  }

  @Test
  public void testConsumeOwsNoWhitespace() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("string");
    parser.consumeOws();
    assertEquals("", parser.get());
  }

  @Test
  public void testConsumeOwsMatchesSpace() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser(" string");
    parser.consumeOws();
    assertEquals(" ", parser.get());
  }

  @Test
  public void testConsumeOwsMatchesHorizontalTab() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("\tstring");
    parser.consumeOws();
    assertEquals("\t", parser.get());
  }

  @Test
  public void testConsumeOwsMatchesNewline() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("\nstring");
    parser.consumeOws();
    assertEquals("\n", parser.get());
  }

  @Test
  public void testConsumeOwsMatchesCarriageReturn() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("\rstring");
    parser.consumeOws();
    assertEquals("\r", parser.get());
  }

  @Test
  public void testConsumeOwsConsumesMultipleWhitespaceCharacters() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser(" \t\r\nstring");
    parser.consumeOws();
    assertEquals(" \t\r\n", parser.get());
  }

  @Test(expected = Rfc2616AbnfParser.ParseException.class)
  public void testConsumeRwsNoWhitespace() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("string");
    parser.consumeRws();
  }

  @Test
  public void testConsumeRwsMatchesSpace() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser(" string");
    parser.consumeRws();
    assertEquals(" ", parser.get());
  }

  @Test
  public void testConsumeRwsMatchesHorizontalTab() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("\tstring");
    parser.consumeRws();
    assertEquals("\t", parser.get());
  }

  @Test
  public void testConsumeRwsMatchesNewline() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("\nstring");
    parser.consumeRws();
    assertEquals("\n", parser.get());
  }

  @Test
  public void testConsumeRwsMatchesCarriageReturn() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("\rstring");
    parser.consumeRws();
    assertEquals("\r", parser.get());
  }

  @Test
  public void testConsumeRwsConsumesMultipleWhitespaceCharacters() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser(" \t\r\nstring");
    parser.consumeRws();
    assertEquals(" \t\r\n", parser.get());
  }

  @Test
  public void testConsumeTokenValidToken() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("token");
    parser.consumeToken();
    assertEquals("token", parser.get());
  }

  @Test(expected = Rfc2616AbnfParser.ParseException.class)
  public void testConsumeTokenNoToken() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("");
    parser.consumeToken();
  }

  @Test
  public void testConsumeTokenTokenFollowedBySeparator() throws Exception {
    String separators = "()<>@,;:\\\"/[]?={} \t";

    for (char c : separators.toCharArray()) {
      Rfc2616AbnfParser parser = new Rfc2616AbnfParser("token" + c);
      parser.consumeToken();
      assertEquals("token", parser.get());
    }
  }

  @Test
  public void testConsumeTokenTokenFollowedByControlCharacter0To31() throws Exception {
    for (int charCode = 0; charCode <= 31; ++charCode) {
      Rfc2616AbnfParser parser = new Rfc2616AbnfParser("token" + (char) charCode);
      parser.consumeToken();
      assertEquals("token", parser.get());
    }
  }

  @Test
  public void testConsumeTokenTokenFollowedByControlCharacterDEL() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("token" + (char) 127);
    parser.consumeToken();
    assertEquals("token", parser.get());
  }

  @Test
  public void testConsumeTokenAllValidTokenCharacters() throws Exception {
    String validTokenChars =
        "!#$%&'*+-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ^_`abcdefghijklmnopqrstuvwxyz|~";

    for (char c : validTokenChars.toCharArray()) {
      String token = Character.toString(c);
      Rfc2616AbnfParser parser = new Rfc2616AbnfParser(token);
      parser.consumeToken();
      assertEquals(token, parser.get());
    }
  }

  @Test
  public void testConsumeValidToken68() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("token68");
    parser.consumeToken68();
    assertEquals("token68", parser.get());
  }

  @Test
  public void testConsumeValidToken68EndingInEquals() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("token68=");
    parser.consumeToken68();
    assertEquals("token68=", parser.get());
  }

  @Test
  public void testConsumeValidToken68EndingInMultipleEquals() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("token68======");
    parser.consumeToken68();
    assertEquals("token68======", parser.get());
  }

  @Test
  public void testConsumeValidToken68EqualsEndsToken() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("token68=not_part_of_the_token");
    parser.consumeToken68();
    assertEquals("token68=", parser.get());
  }

  @Test(expected = Rfc2616AbnfParser.ParseException.class)
  public void testConsumeToken68NoToken() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("");
    parser.consumeToken68();
  }

  @Test
  public void testConsumeToken68FollowedByNonToken68Character() throws Exception {
    String validToken68Chars =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~+/";

    String invalidToken68Chars = "";
    for (char c = 0; c <= 128; ++c) {
      if (c == '=') {
        continue;
      }
      if (validToken68Chars.indexOf(c) != -1) {
        continue;
      }
      invalidToken68Chars += c;
    }

    for (char c : invalidToken68Chars.toCharArray()) {
      Rfc2616AbnfParser parser = new Rfc2616AbnfParser("token68" + c);
      parser.consumeToken68();
      assertEquals("token68", parser.get());
    }
  }

  @Test
  public void testConsumeToken68AllValidToken68CharactersExceptEquals() throws Exception {
    String validToken68Chars =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~+/";

    for (char c : validToken68Chars.toCharArray()) {
      String token68 = Character.toString(c);
      Rfc2616AbnfParser parser = new Rfc2616AbnfParser(token68);
      parser.consumeToken68();
      assertEquals(token68, parser.get());
    }
  }

  @Test
  public void testConsumeQuotedString() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("\"string\"");
    parser.consumeQuotedString();
    assertEquals("\"string\"", parser.get());
  }

  @Test(expected = Rfc2616AbnfParser.ParseException.class)
  public void testConsumeQuotedStringNoEndQuote() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("\"string");
    parser.consumeQuotedString();
  }

  @Test(expected = Rfc2616AbnfParser.ParseException.class)
  public void testConsumeQuotedStringNoLeadingQuote() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("string");
    parser.consumeQuotedString();
  }

  @Test(expected = Rfc2616AbnfParser.ParseException.class)
  public void testConsumeQuotedStringEmptyString() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("");
    parser.consumeQuotedString();
  }

  @Test(expected = Rfc2616AbnfParser.ParseException.class)
  public void testConsumeQuotedStringNoEndQuoteEndsInQuotedQuoteCharacter() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("\"string\\\"");
    parser.consumeQuotedString();
  }

  @Test(expected = Rfc2616AbnfParser.ParseException.class)
  public void testConsumeQuotedStringNoEndQuoteEndsInBackslash() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("\"string\\");
    parser.consumeQuotedString();
  }

  @Test
  public void testConsumeQuotedStringWithQuotedCharacters() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("\"\\s\\t\\r\\i\\n\\g\"");
    parser.consumeQuotedString();
    assertEquals("\"\\s\\t\\r\\i\\n\\g\"", parser.get());
  }

  @Test
  public void testConsumeQuotedStringWithQuotedQuoteCharacters() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("\"\\\"\"");
    parser.consumeQuotedString();
    assertEquals("\"\\\"\"", parser.get());
  }

  @Test
  public void testConsumeQuotedStringWithQuotedBackslashCharacters() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("\"\\\\\"");
    parser.consumeQuotedString();
    assertEquals("\"\\\\\"", parser.get());
  }

  @Test
  public void testConsumeQuotedStringOrTokenStringIsToken() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("token");
    parser.consumeQuotedStringOrToken();
    assertEquals("token", parser.get());
  }

  @Test
  public void testConsumeQuotedStringOrTokenStringIsQuotedString() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("\"quoted\"");
    parser.consumeQuotedStringOrToken();
    assertEquals("\"quoted\"", parser.get());
  }

  @Test(expected = Rfc2616AbnfParser.ParseException.class)
  public void testConsumeQuotedStringOrTokenStringIsMalformed() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser(" ");
    parser.consumeQuotedStringOrToken();
  }

  @Test(expected = Rfc2616AbnfParser.ParseException.class)
  public void testConsumeQuotedStringOrTokenStringIsEmpty() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("");
    parser.consumeQuotedStringOrToken();
  }

  @Test
  public void testQuote() throws Exception {
    assertEquals("\"string\"", Rfc2616AbnfParser.quote("string"));
  }

  @Test
  public void testQuoteStringWithQuote() throws Exception {
    assertEquals("\"\\\"\"", Rfc2616AbnfParser.quote("\""));
  }

  @Test
  public void testQuoteStringWithBackslash() throws Exception {
    assertEquals("\"\\\\\"", Rfc2616AbnfParser.quote("\\"));
  }

  @Test
  public void testUnquote() throws Exception {
    assertEquals("string", Rfc2616AbnfParser.unquote("\"string\""));
  }

  @Test
  public void testUnquoteWithQuotedCharacters() throws Exception {
    assertEquals("string", Rfc2616AbnfParser.unquote("\"\\s\\t\\r\\i\\n\\g\""));
  }

  @Test
  public void testUnquoteWithQuotedQuoteCharacters() throws Exception {
    assertEquals("\\", Rfc2616AbnfParser.unquote("\"\\\\\""));
  }

  @Test
  public void testUnquoteInvalidStringNoQuotes() throws Exception {
    assertNotNull(Rfc2616AbnfParser.unquote("string"));
  }

  @Test
  public void testUnquoteInvalidStringEmptyString() throws Exception {
    assertNotNull(Rfc2616AbnfParser.unquote(""));
  }

  @Test
  public void testUnquoteInvalidStringNoEndQuote() throws Exception {
    assertNotNull(Rfc2616AbnfParser.unquote("\"string"));
  }

  @Test
  public void testUnquoteInvalidStringEndsInQuotedQuoteCharacter() throws Exception {
    assertNotNull(Rfc2616AbnfParser.unquote("\"string\\\""));
  }

  @Test
  public void testUnquoteInvalidStringEndsInBackslash() throws Exception {
    assertNotNull(Rfc2616AbnfParser.unquote("\"string\\"));
  }

  @Test
  public void testUnquoteIfQuotedInputIsQuoted() throws Exception {
    assertEquals("string", Rfc2616AbnfParser.unquoteIfQuoted("\"string\""));
  }

  @Test
  public void testUnquoteIfQuotedInputIsAToken() throws Exception {
    assertEquals("string", Rfc2616AbnfParser.unquoteIfQuoted("string"));
  }

  @Test
  public void testUnquoteIfQuotedInputIsEmpty() throws Exception {
    assertEquals("", Rfc2616AbnfParser.unquoteIfQuoted(""));
  }

  @Test
  public void testParseRfc2617Example() throws Exception {
    String example = "Digest\n" +
        "                 realm=\"testrealm@host.com\",\n" +
        "                 qop=\"auth,auth-int\",\n" +
        "                 nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\n" +
        "                 opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";

    Rfc2616AbnfParser parser = new Rfc2616AbnfParser(example);

    assertEquals("Digest", parser.consumeLiteral("digest").get());

    assertEquals("realm", parser.consumeOws().consumeToken().get());
    assertEquals("=", parser.consumeOws().consumeLiteral("=").get());
    assertEquals("\"testrealm@host.com\"", parser.consumeOws().consumeQuotedString().get());
    assertEquals(",", parser.consumeOws().consumeLiteral(",").get());

    assertEquals("qop", parser.consumeOws().consumeToken().get());
    assertEquals("=", parser.consumeOws().consumeLiteral("=").get());
    assertEquals("\"auth,auth-int\"", parser.consumeOws().consumeQuotedString().get());
    assertEquals(",", parser.consumeOws().consumeLiteral(",").get());

    assertEquals("nonce", parser.consumeOws().consumeToken().get());
    assertEquals("=", parser.consumeOws().consumeLiteral("=").get());
    assertEquals("\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"",
        parser.consumeOws().consumeQuotedString().get());
    assertEquals(",", parser.consumeOws().consumeLiteral(",").get());

    assertEquals("opaque", parser.consumeOws().consumeToken().get());
    assertEquals("=", parser.consumeOws().consumeLiteral("=").get());
    assertEquals("\"5ccc069c403ebaf9f0171e9517f40e41\"",
        parser.consumeOws().consumeQuotedString().get());

    assertFalse(parser.consumeOws().hasMoreData());
  }
}
