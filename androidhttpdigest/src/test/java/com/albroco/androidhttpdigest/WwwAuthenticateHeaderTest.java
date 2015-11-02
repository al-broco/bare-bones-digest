package com.albroco.androidhttpdigest;

import org.junit.Test;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertNull;

public class WwwAuthenticateHeaderTest {
  @Test
  public void testExampleFromRfc2617() throws Exception {
    String EXAMPLE = "Digest " +
        "realm=\"testrealm@host.com\", " +
        "qop=\"auth,auth-int\", " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
        "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";

    WwwAuthenticateHeader header = WwwAuthenticateHeader.parse(EXAMPLE);

    assertNotNull(header);
    assertEquals("testrealm@host.com", header.getRealm());
    assertEquals("dcd98b7102dd2f0e8b11d0f600bfb0c093", header.getNonce());
    assertEquals("\"5ccc069c403ebaf9f0171e9517f40e41\"", header.getOpaqueQuoted());
    assertNull(header.getAlgorithm());
  }
}