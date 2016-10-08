package com.albroco.barebonesdigest;

import java.io.IOException;

/**
 * Indicates that a <code>WWW-Authenticate</code> header or challenge could not be parsed because it
 * is malformed.
 */
public class HttpDigestChallengeParseException extends IOException {
  /**
   * Constructs a new {@code HttpDigestChallengeParseException} with its stack trace and detail
   * message filled in.
   *
   * @param detailMessage the detail message for this exception.
   */
  public HttpDigestChallengeParseException(String detailMessage) {
    super(detailMessage);
  }

  /**
   * Constructs a new instance of this class with detail message and cause filled in.
   *
   * @param message The detail message for the exception.
   * @param cause   The detail cause for the exception.
   */
  public HttpDigestChallengeParseException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Constructs a new instance of this class with its detail cause filled in.
   *
   * @param cause The detail cause for the exception.
   */
  public HttpDigestChallengeParseException(Throwable cause) {
    super(cause);
  }
}
