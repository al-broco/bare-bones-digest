package org.barebonesdigest;

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
  public void testConsumeLiteralNoMatch() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("literal");
    parser.consumeLiteral("misatch");
  }

  @Test
  public void testConsumeWhitespaceNoWhitespace() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("string");
    parser.consumeWhitespace();
    assertEquals("", parser.get());
  }

  @Test
  public void testConsumeWhitespaceMatchesSpace() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser(" string");
    parser.consumeWhitespace();
    assertEquals(" ", parser.get());
  }

  @Test
  public void testConsumeWhitespaceMatchesHorizontalTab() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("\tstring");
    parser.consumeWhitespace();
    assertEquals("\t", parser.get());
  }

  @Test
  public void testConsumeWhitespaceMatchesNewline() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("\nstring");
    parser.consumeWhitespace();
    assertEquals("\n", parser.get());
  }

  @Test
  public void testConsumeWhitespaceMatchesCarriageReturn() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("\rstring");
    parser.consumeWhitespace();
    assertEquals("\r", parser.get());
  }

  @Test
  public void testConsumeWhitespaceConsumesMultipleWhitespaceCharacters() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser(" \t\r\nstring");
    parser.consumeWhitespace();
    assertEquals(" \t\r\n", parser.get());
  }

  @Test
  public void testConsumeTokenValidToken() throws Exception {
    Rfc2616AbnfParser parser = new Rfc2616AbnfParser("token");
    parser.consumeToken();
    assertEquals("token", parser.get());
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
  public void testConsumeTokenTokenAllValidTokenCharacters() throws Exception {
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
  public void testParseRfc2617Example() throws Exception {
    String example = "Digest\n" +
        "                 realm=\"testrealm@host.com\",\n" +
        "                 qop=\"auth,auth-int\",\n" +
        "                 nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\n" +
        "                 opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";

    Rfc2616AbnfParser parser = new Rfc2616AbnfParser(example);

    assertEquals("Digest", parser.consumeLiteral("digest").get());

    assertEquals("realm", parser.consumeWhitespace().consumeToken().get());
    assertEquals("=", parser.consumeWhitespace().consumeLiteral("=").get());
    assertEquals("\"testrealm@host.com\"", parser.consumeWhitespace().consumeQuotedString().get());
    assertEquals(",", parser.consumeWhitespace().consumeLiteral(",").get());

    assertEquals("qop", parser.consumeWhitespace().consumeToken().get());
    assertEquals("=", parser.consumeWhitespace().consumeLiteral("=").get());
    assertEquals("\"auth,auth-int\"", parser.consumeWhitespace().consumeQuotedString().get());
    assertEquals(",", parser.consumeWhitespace().consumeLiteral(",").get());

    assertEquals("nonce", parser.consumeWhitespace().consumeToken().get());
    assertEquals("=", parser.consumeWhitespace().consumeLiteral("=").get());
    assertEquals("\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"",
        parser.consumeWhitespace().consumeQuotedString().get());
    assertEquals(",", parser.consumeWhitespace().consumeLiteral(",").get());

    assertEquals("opaque", parser.consumeWhitespace().consumeToken().get());
    assertEquals("=", parser.consumeWhitespace().consumeLiteral("=").get());
    assertEquals("\"5ccc069c403ebaf9f0171e9517f40e41\"",
        parser.consumeWhitespace().consumeQuotedString().get());

    assertFalse(parser.consumeWhitespace().containsMoreData());
  }
}
