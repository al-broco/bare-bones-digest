package com.albroco.androidhttpdigest;

import java.net.HttpURLConnection;

public class WwwAuthenticateHeader {
  public static final String HTTP_DIGEST_CHALLENGE_PREFIX = "Digest ";
  private final String realm;
  private final String nonce;
  private final String opaqueQuoted;
  private final String algorithm;

  private WwwAuthenticateHeader(String realm, String nonce, String opaqueQuoted, String algorithm) {
    this.realm = realm;
    this.nonce = nonce;
    this.opaqueQuoted = opaqueQuoted;
    this.algorithm = algorithm;
  }

  public static WwwAuthenticateHeader parse(String authenticateHeader) {
    // TODO: Current parsing is broken and only works for simple cases

    if (!authenticateHeader.startsWith(HTTP_DIGEST_CHALLENGE_PREFIX)) {
      return null;
    }

    String realm = null;
    String nonce = null;
    String opaqueQuoted = null;
    String algorithm = null;

    String digestChallenge = authenticateHeader.substring(HTTP_DIGEST_CHALLENGE_PREFIX.length());
    String challengeParts[] = digestChallenge.split(",");
    for (String challengePart : challengeParts) {
      int equalsIndex = challengePart.indexOf('=');
      if (equalsIndex != -1) {
        String key = challengePart.substring(0, equalsIndex).trim();
        String value = challengePart.substring(equalsIndex + 1).trim();

        if (key.equals("realm")) {
          realm = unquoteString(value);
        } else if (key.equals("nonce")) {
          nonce = unquoteString(value);
        } else if (key.equals("opaque")) {
          opaqueQuoted = value;
        } else if (key.equals("algorithm")) {
          algorithm = value;
        }
      }
    }

    return new WwwAuthenticateHeader(realm, nonce, opaqueQuoted, algorithm);
  }

  public String getRealm() {
    return realm;
  }

  public String getAlgorithm() {
    return algorithm;
  }

  public String getNonce() {
    return nonce;
  }

  public String getOpaqueQuoted() {
    return opaqueQuoted;
  }

  private static String unquoteString(String str) {
    // TODO: implement properly
    if (str.startsWith("\"") && str.endsWith("\"")) {
      return str.substring(1, str.length() - 1);
    }
    return str;
  }
}
